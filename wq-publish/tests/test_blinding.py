"""盲化供数关键流程自测（python -I tests/test_blinding.py）。

覆盖需求：
1. 盲码：同合作方跨版本稳定、跨合作方不同、不随样本号/连续编号可推算、重启保持
2. 导出 CSV 仅含 盲码/检测项目/浓度 三列，不含样本号；导出只含一个完整已发布版本
3. 撤销合作方：旧地址 410 不再取数；已开始（已受理）的下载可完整结束
4. 撤销/新下载与原批次发布交错：撤销后拒绝新导出；并发下导出始终绑定完整版本
5. 生成失败不留可用部分导出（failed + 无文件），原始供数 published.csv 不受影响
6. 崩溃恢复：building 残留 → failed；ready 文件缺失/损坏 → 按登记重建；游离文件隔离
"""
import csv
import hashlib
import io
import os
import shutil
import sys
import tempfile
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from wq_publish.app import create_app
from wq_publish.blinding import blind_code
from wq_publish.storage import (
    BLIND_KEY_FILENAME,
    LIVE_FILENAME,
    ExportError,
    PartnerError,
)

PASS, FAIL = 0, 0
EXAMPLE_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "examples"
)


def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ✓ {name}")
    else:
        FAIL += 1
        print(f"  ✗ {name} {detail}")


def read_example(fname):
    with open(os.path.join(EXAMPLE_DIR, fname), "rb") as fh:
        return fh.read()


def upload_and_publish(client, storage, fname, batch):
    resp = client.post(
        "/preview",
        data={"batch_no": batch,
              "csv_file": (io.BytesIO(read_example(fname)), fname)},
        content_type="multipart/form-data",
    )
    import re
    token = re.search(rb"/publish/([0-9a-f]+)", resp.data).group(1).decode()
    client.post(f"/publish/{token}")
    return storage.current_registry()["current_version"]


def parse_csv(data: bytes):
    text = data.decode("utf-8-sig")
    reader = csv.reader(io.StringIO(text))
    table = list(reader)
    return table[0], table[1:]


tmp = tempfile.mkdtemp(prefix="wq-blind-test-")
data_dir = os.path.join(tmp, "data")
down_dir = os.path.join(tmp, "downstream")
app = create_app(data_dir=data_dir, downstream_dir=down_dir)
client = app.test_client()
st = app.storage

print("== 1. 前置：发布 v1 / v2 ==")
v1 = upload_and_publish(client, st, "batch_v1.csv", "B1")
v2 = upload_and_publish(client, st, "batch_v2_revision.csv", "B2")
check("发布到 v2", v1 == 1 and v2 == 2)

print("== 2. 盲码性质 ==")
key = st.blind_master_key
check("主密钥为 32 字节且已持久化", len(key) == 32
      and os.path.exists(os.path.join(data_dir, BLIND_KEY_FILENAME))
      and oct(os.stat(os.path.join(data_dir, BLIND_KEY_FILENAME)).st_mode & 0o777) == "0o600")

_B32HEX = set("0123456789ABCDEFGHIJKLMNOPQRSTUV")  # RFC 4648 base32hex 字母表（无填充）
c1_s001 = blind_code(key, 1, "S001")
check("盲码定长 16 且为 base32hex 字符集",
      len(c1_s001) == 16 and all(ch in _B32HEX for ch in c1_s001),
      c1_s001)
check("盲码不含样本号原文", "S001" not in c1_s001)
codes_seq = [blind_code(key, 1, f"S{n:03d}") for n in range(1, 6)]
check("连续样本号的盲码互不相同（无连续编号可枚举性）",
      len(set(codes_seq)) == 5, str(codes_seq))
check("同合作方同样本盲码确定性（重复计算一致）",
      blind_code(key, 1, "S001") == c1_s001)
check("跨合作方盲码不同（域分隔）",
      blind_code(key, 1, "S001") != blind_code(key, 2, "S001"))

print("== 3. 建立合作方与重名防护 ==")
pa = st.create_partner("甲方水务")
pb = st.create_partner("乙方环监")
check("合作方 id 不同", pa["id"] != pb["id"])
try:
    st.create_partner("甲方水务")
    check("重名合作方被拒", False)
except PartnerError:
    check("重名合作方被拒", True)
try:
    st.create_partner("   ")
    check("空名称被拒", False)
except PartnerError:
    check("空名称被拒", True)
page = client.get("/partners")
check("合作方列表页 200 且含两个合作方",
      page.status_code == 200 and "甲方水务".encode() in page.data
      and "乙方环监".encode() in page.data)

print("== 4. 盲化导出：仅三列、完整版本、跨版本稳定 ==")
ea = st.create_blind_export(pa["id"], v1)
header, rows = parse_csv(open(st.export_path(ea["file_name"]), "rb").read())
check("导出表头仅 盲码/检测项目/浓度 三列",
      header == ["盲码", "检测项目", "浓度(mg/L)"], str(header))
check("v1 导出 5 行（完整版本，无部分导出）", len(rows) == 5)
flat = "\n".join(",".join(r) for r in rows)
check("导出中不含任何原始样本号",
      all(s not in flat for s in ("S001", "S002", "S003", "S004")))
check("导出中不含盲码以外的可关联标识", "样本" not in flat)

ea2 = st.create_blind_export(pa["id"], v2)
_, rows2 = parse_csv(open(st.export_path(ea2["file_name"]), "rb").read())
check("v2 导出也是完整 5 行", len(rows2) == 5)
# v1 与 v2 共同样本 S001/S003：同一合作方盲码必须一致（可追踪修订）
codes_v1 = {r[0] for r in rows}
codes_v2 = {r[0] for r in rows2}
common = codes_v1 & codes_v2
check("同合作方跨版本盲码稳定（共同样本盲码集合相交）", len(common) >= 3,
      f"{codes_v1} vs {codes_v2}")
check("盲码与直接派生结果一致",
      st.blind_code_for(pa["id"], "S001") in codes_v1)

# 不同合作方对同版本的盲码集合不相交
eb = st.create_blind_export(pb["id"], v1)
_, rows_b = parse_csv(open(st.export_path(eb["file_name"]), "rb").read())
check("不同合作方盲码完全不同，无法互串",
      codes_v1.isdisjoint({r[0] for r in rows_b}))
# 浓度保持一致（业务数据未被盲化改动）
conc_a = sorted(r[2] for r in rows)
conc_b = sorted(r[2] for r in rows_b)
check("两合作方导出的浓度数据一致", conc_a == conc_b)

print("== 5. 下载地址与 HTTP 语义 ==")
resp = client.get(f"/blind/{ea['token']}")
check("有效地址可下载（200、附件、内容哈希正确）",
      resp.status_code == 200
      and resp.headers["Content-Disposition"].startswith("attachment")
      and hashlib.sha256(resp.data).hexdigest() == ea["content_hash"])
check("未知地址 410", client.get("/blind/" + "f" * 32).status_code == 410)
detail = client.get(f"/partners/{pa['id']}")
check("合作方详情页含下载链接和版本选择",
      f"/blind/{ea['token']}".encode() in detail.data
      and b"v2" in detail.data)

print("== 6. 撤销：旧地址失效、进行中下载完整、拒绝新导出 ==")
# 模拟已受理的下载：先打开文件句柄，再撤销
fh = open(st.export_path(ea["file_name"]), "rb")
before = fh.read()
ok = st.revoke_partner(pa["id"])
check("撤销成功", ok)
check("重复撤销返回 False", st.revoke_partner(pa["id"]) is False)
after = fh.read()
fh.seek(0)
check("已开始的下载在撤销后仍可读完且字节完整", fh.read() == before)
fh.close()
resp = client.get(f"/blind/{ea['token']}")
check("撤销后旧地址不再取数（410）", resp.status_code == 410)
resp = client.get(f"/blind/{ea2['token']}")
check("撤销后该合作方所有地址均 410", resp.status_code == 410)
try:
    st.create_blind_export(pa["id"], v1)
    check("撤销后不再受理新导出", False)
except PartnerError:
    check("撤销后不再受理新导出", True)
# 撤销不影响其他合作方
check("撤销甲方不影响乙方下载",
      client.get(f"/blind/{eb['token']}").status_code == 200)
# 撤销不影响原始供数
check("原始供数文件仍可下载且内容不变",
      client.get("/published.csv").status_code == 200
      and b"S001" in client.get("/published.csv").data)

print("== 7. 失败原子性：不留可用部分导出，原始供数不受影响 ==")
live_before = open(os.path.join(down_dir, LIVE_FILENAME), "rb").read()
try:
    st.create_blind_export(pb["id"], 999)
    check("基于不存在的版本导出被拒", False)
except ExportError:
    check("基于不存在的版本导出被拒", True)
check("失败后无 building 记录、无 failed 之外的残留文件",
      all(e["status"] != "building" for e in st.list_exports(pb["id"])))
on_disk = set(os.listdir(st.blind_export_dir))
# 全部合作方的 ready 文件（含已撤销方——其文件保留供进行中的下载读完）
ready_files = {
    e["file_name"]
    for p in st.list_partners()
    for e in st.list_exports(p["id"])
    if e["status"] == "ready"
}
check("磁盘文件全部对应 ready 导出（无半成品/游离文件，撤销方文件保留）",
      all(not n.startswith(".tmp") for n in on_disk)
      and on_disk == ready_files,
      f"disk={on_disk} ready={ready_files}")
live_after = open(os.path.join(down_dir, LIVE_FILENAME), "rb").read()
check("盲化操作全程不改变原始供数文件", live_before == live_after)

# 模拟写盘失败：把导出目录临时换成文件，触发 IO 错误后应登记 failed
stash = st.blind_export_dir
shutil.move(stash, stash + ".bak")
open(stash, "w").write("x")  # 同名文件占位，makedirs/写文件必然失败
try:
    st.create_blind_export(pb["id"], v1)
    check("写盘失败时抛错", False)
except OSError:
    check("写盘失败时抛错", True)
os.unlink(stash)
shutil.move(stash + ".bak", stash)
failed = [e for e in st.list_exports(pb["id"]) if e["status"] == "failed"]
check("写盘失败的导出登记为 failed", len(failed) >= 1)
check("failed 导出地址不可下载",
      all(client.get(f"/blind/{e['token']}").status_code == 410 for e in failed))
check("失败后无临时文件残留",
      not [n for n in os.listdir(st.blind_export_dir) if n.startswith(".tmp")])

print("== 8. 交错并发：发布 / 撤销 / 新导出同时进行 ==")
errors = []


def worker_publish():
    try:
        for i in range(4):
            upload_and_publish(client, st, "batch_v1.csv", f"RACE-P-{i}")
    except BaseException as exc:  # 409 冲突属于预期，重新预览即可
        errors.append(("publish", repr(exc)))


def worker_export():
    try:
        for i in range(4):
            rec = st.create_blind_export(pb["id"], v1)  # 始终绑定已发布的 v1
            _, r = parse_csv(open(st.export_path(rec["file_name"]), "rb").read())
            if len(r) != 5:
                errors.append(("export-rowcount", len(r)))
    except BaseException as exc:
        errors.append(("export", repr(exc)))


t1 = threading.Thread(target=worker_publish)
t2 = threading.Thread(target=worker_export)
t1.start(); t2.start(); t1.join(); t2.join()
check("并发交错下无异常（发布冲突由会话机制吸收）", errors == [], str(errors))
for e in st.list_exports(pb["id"]):
    if e["status"] == "ready":
        _, r = parse_csv(open(st.export_path(e["file_name"]), "rb").read())
        if len(r) != e["row_count"] or e["row_count"] == 0:
            check("每个就绪导出都对应一个完整版本的全量数据", False,
                  f"{e['token']} {len(r)} rows")
            break
else:
    check("每个就绪导出都对应一个完整版本的全量数据", True)

print("== 9. 重启保持：密钥/盲码稳定 + 崩溃恢复 ==")
# 9a 重启后盲码不变（密钥持久化）
app2 = create_app(data_dir=data_dir, downstream_dir=down_dir)
check("重启后同合作方盲码保持不变",
      app2.storage.blind_code_for(pb["id"], "S001") == blind_code(key, pb["id"], "S001"))
ready_b = [e for e in app2.storage.list_exports(pb["id"]) if e["status"] == "ready"]
check("重启后既有导出仍可下载",
      all(client.get(f"/blind/{e['token']}").status_code == 200 for e in ready_b))

# 9b 模拟 building 崩溃：手工插入 building 记录并放半成品文件
with app2.storage._connect() as conn:
    conn.execute("BEGIN IMMEDIATE")
    conn.execute(
        "INSERT INTO blind_exports(token, partner_id, version, row_count,"
        " file_name, content_hash, created_at, status)"
        " VALUES (?,?,?,0,?, '', ?, 'building')",
        ("deadbeef" * 4, pb["id"], v1, "blind_crash.csv", "2026-01-01T00:00:00+00:00"),
    )
    conn.commit()
open(os.path.join(st.blind_export_dir, "blind_crash.csv"), "w").write("半份数据")
open(os.path.join(st.blind_export_dir, ".tmp-publish-orphan.csv"), "w").write("x")
app3 = create_app(data_dir=data_dir, downstream_dir=down_dir)
row = next(e for e in app3.storage.list_exports(pb["id"]) if e["token"] == "deadbeef" * 4)
check("9b building 残留重启后标记 failed", row["status"] == "failed")
check("9b 半成品文件被删除",
      not os.path.exists(os.path.join(st.blind_export_dir, "blind_crash.csv")))
check("9b 遗留临时文件被清理",
      not os.path.exists(os.path.join(st.blind_export_dir, ".tmp-publish-orphan.csv")))
check("9b failed 地址不可下载",
      client.get(f"/blind/{'deadbeef' * 4}").status_code == 410)

# 9c ready 文件被删/被改坏 → 按登记确定性重建且哈希一致
target = ready_b[0]
path = app3.storage.export_path(target["file_name"])
os.unlink(path)
app4 = create_app(data_dir=data_dir, downstream_dir=down_dir)
check("9c 缺失的就绪导出被重建",
      os.path.exists(path)
      and hashlib.sha256(open(path, "rb").read()).hexdigest() == target["content_hash"])
with open(path, "ab") as fh:
    fh.write(b"CORRUPT\n")
app5 = create_app(data_dir=data_dir, downstream_dir=down_dir)
check("9c 损坏的就绪导出按登记重建",
      hashlib.sha256(open(path, "rb").read()).hexdigest() == target["content_hash"])

# 9d 游离文件隔离
stranger = os.path.join(st.blind_export_dir, "stranger.csv")
open(stranger, "w").write("x")
create_app(data_dir=data_dir, downstream_dir=down_dir)
check("9d 盲化目录游离文件被隔离",
      not os.path.exists(stranger)
      and any(f.endswith("stranger.csv")
              for f in os.listdir(os.path.join(data_dir, "quarantine"))))

# 9e 恢复动作与合作方操作均写入事件日志
events = app5.storage.recent_events(200)
kinds = {e["kind"] for e in events}
check("事件日志记录 partner/blind/recover 类事件",
      {"partner", "blind", "recover"}.issubset(kinds), str(kinds))

print("== 10. 原始供数全流程不受盲化功能影响 ==")
reg = app5.storage.current_registry()
live_hash = hashlib.sha256(
    open(os.path.join(down_dir, LIVE_FILENAME), "rb").read()
).hexdigest()
check("最终原始供数与登记哈希一致", live_hash == reg["content_hash"])
check("下游目录仍只有正式文件（盲化文件在 data 目录）",
      sorted(os.listdir(down_dir)) == [LIVE_FILENAME])

shutil.rmtree(tmp, ignore_errors=True)
print(f"\n结果：{PASS} 通过，{FAIL} 失败")
sys.exit(1 if FAIL else 0)
