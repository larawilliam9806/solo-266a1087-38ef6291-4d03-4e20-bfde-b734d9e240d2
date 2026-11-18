"""SQLite 登记 + 下游目录原子发布 + 盲化供数 + 启动一致性恢复。

设计要点
--------
* SQLite 是版本/行数/合作方/导出登记的唯一真相源；下游目录中的 CSV 只是它的镜像。
* 发布在单个 ``BEGIN IMMEDIATE`` 事务内完成：先写同目录临时文件并 fsync，
  再 ``os.replace`` 原子改名（下游只会看到完整的旧文件或新文件），
  最后提交事务登记新版本。
* 提交后进程若在改名完成前崩溃：重启时按数据库登记重新生成 CSV，
  并清理遗留临时文件；登记里不存在的游离文件会被移入 quarantine 隔离。
* 盲化主密钥持久化在数据目录（0600），盲码为 HMAC 确定性派生，
  同合作方跨版本稳定、跨合作方域隔离；盲化导出文件放在数据目录的
  ``blind_exports/`` 下，与下游正式供数物理隔离，任何盲化失败都不影响原始供数。
* 盲化导出登记经历 building → ready/failed：崩溃遗留的 building 一律置 failed
  并清除半成品；ready 文件缺失/损坏可按登记确定性重建。
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone

from .blinding import (
    BlindCodeCollision,
    assert_unique_within_partner,
    blind_code,
)
from .validation import format_concentration, render_blind_csv, render_csv

LIVE_FILENAME = "published_results.csv"
BLIND_EXPORT_DIRNAME = "blind_exports"
BLIND_KEY_FILENAME = "blind_master_key"


class PublishConflictError(Exception):
    """确认发布时基线版本已过期，需要重新预览。"""


class PartnerError(Exception):
    """合作方操作不合法（重名、撤销后再操作等）。"""


class ExportError(Exception):
    """盲化导出生成失败（版本不存在、合作方已撤销、盲码碰撞等）。"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Storage:
    def __init__(self, data_dir: str, downstream_dir: str):
        self.data_dir = os.path.abspath(data_dir)
        self.downstream_dir = os.path.abspath(downstream_dir)
        os.makedirs(self.data_dir, exist_ok=True)
        os.makedirs(self.downstream_dir, exist_ok=True)
        self.db_path = os.path.join(self.data_dir, "wq_publish.db")
        self.live_path = os.path.join(self.downstream_dir, LIVE_FILENAME)
        self.quarantine_dir = os.path.join(self.data_dir, "quarantine")
        os.makedirs(self.quarantine_dir, exist_ok=True)
        # 盲化导出文件全部放在数据目录（与下游正式供数完全隔离，
        # 原始 published_results.csv 不受任何盲化操作影响）
        self.blind_export_dir = os.path.join(self.data_dir, BLIND_EXPORT_DIRNAME)
        os.makedirs(self.blind_export_dir, exist_ok=True)
        self.blind_key_path = os.path.join(self.data_dir, BLIND_KEY_FILENAME)
        self.blind_master_key = self._load_or_create_blind_key()
        self._init_db()
        self.recover()

    def _load_or_create_blind_key(self) -> bytes:
        """加载持久化的盲化主密钥；不存在则生成 32 字节随机密钥并落盘。

        密钥在重启后保持不变 → 同一合作方的样本盲码跨版本/跨进程稳定。
        """
        if os.path.exists(self.blind_key_path):
            with open(self.blind_key_path, "rb") as fh:
                key = fh.read()
            if len(key) >= 32:
                return key
        key = secrets.token_bytes(32)
        # 先写临时文件再原子改名，避免半写密钥被后续进程读取
        tmp = self.blind_key_path + ".tmp"
        with open(tmp, "wb") as fh:
            fh.write(key)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, self.blind_key_path)
        os.chmod(self.blind_key_path, 0o600)
        self._fsync_dir(self.data_dir)
        return key

    # ---------- 基础 ----------
    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=15)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=15000")
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS registry (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    current_version INTEGER NOT NULL,
                    batch_no TEXT NOT NULL,
                    row_count INTEGER NOT NULL,
                    published_at TEXT NOT NULL,
                    content_hash TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    version INTEGER NOT NULL,
                    batch_no TEXT NOT NULL,
                    sample_no TEXT NOT NULL,
                    analyte TEXT NOT NULL,
                    concentration REAL NOT NULL CHECK (concentration >= 0),
                    UNIQUE (version, sample_no, analyte)
                );
                CREATE INDEX IF NOT EXISTS idx_results_version
                    ON results(version);
                CREATE TABLE IF NOT EXISTS revision_sessions (
                    token TEXT PRIMARY KEY,
                    batch_no TEXT NOT NULL,
                    base_version INTEGER NOT NULL,
                    payload TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    status TEXT NOT NULL CHECK (status IN ('pending','published','obsolete','cancelled'))
                );
                CREATE TABLE IF NOT EXISTS event_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    detail TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS partners (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE,
                    token TEXT NOT NULL UNIQUE,
                    created_at TEXT NOT NULL,
                    revoked_at TEXT
                );
                CREATE TABLE IF NOT EXISTS blind_exports (
                    token TEXT PRIMARY KEY,
                    partner_id INTEGER NOT NULL REFERENCES partners(id),
                    version INTEGER NOT NULL,
                    row_count INTEGER NOT NULL,
                    file_name TEXT NOT NULL,
                    content_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    status TEXT NOT NULL CHECK (status IN ('building','ready','failed'))
                );
                CREATE INDEX IF NOT EXISTS idx_blind_exports_partner
                    ON blind_exports(partner_id);
                """
            )

    def _log(self, conn: sqlite3.Connection, kind: str, detail: str) -> None:
        conn.execute(
            "INSERT INTO event_log(ts, kind, detail) VALUES (?,?,?)",
            (_now(), kind, detail),
        )

    def log(self, kind: str, detail: str) -> None:
        with self._connect() as conn:
            self._log(conn, kind, detail)

    # ---------- 启动恢复 ----------
    def recover(self) -> list[str]:
        """重启后核对下游文件与登记的一致性，返回本次恢复动作说明。"""
        actions: list[str] = []
        with self._connect() as conn:
            reg = conn.execute("SELECT * FROM registry WHERE id = 1").fetchone()

            # 1) 清理崩溃遗留的临时文件（可能只写了一半，绝不能被下游读到）
            for name in os.listdir(self.downstream_dir):
                if name.startswith(".tmp-publish-"):
                    path = os.path.join(self.downstream_dir, name)
                    try:
                        os.unlink(path)
                    except OSError:
                        pass
                    msg = f"清理遗留临时文件 downstream/{name}"
                    actions.append(msg)
                    self._log(conn, "recover", msg)

            # 2) 登记为空：正式文件（若存在）属于无登记游离文件，隔离并保留
            if reg is None:
                if os.path.exists(self.live_path):
                    dest = self._quarantine(LIVE_FILENAME)
                    msg = f"数据库无任何发布登记，将下游游离文件移入 {os.path.basename(dest)}"
                    actions.append(msg)
                    self._log(conn, "recover", msg)
            else:
                expected_csv = self._render_version(conn, reg["current_version"])
                expected_hash = hashlib.sha256(expected_csv.encode("utf-8")).hexdigest()

                # 3) 文件缺失/哈希不符：以登记为准原子重建
                need_rewrite = True
                if os.path.exists(self.live_path):
                    with open(self.live_path, "rb") as fh:
                        actual_hash = hashlib.sha256(fh.read()).hexdigest()
                    need_rewrite = actual_hash != expected_hash

                if need_rewrite:
                    self._atomic_write(expected_csv)
                    msg = (
                        f"下游 CSV 与登记 v{reg['current_version']} 不一致，"
                        "已按数据库登记重建（恢复为完整新版本）"
                    )
                    actions.append(msg)
                    self._log(conn, "recover", msg)
                else:
                    self._log(
                        conn,
                        "recover",
                        f"启动核对通过：下游 CSV 与登记 v{reg['current_version']} 一致",
                    )

                # 4) 同目录下游文件白名单：非登记文件一律隔离
                for name in os.listdir(self.downstream_dir):
                    full = os.path.join(self.downstream_dir, name)
                    if os.path.isfile(full) and name != LIVE_FILENAME:
                        dest = self._quarantine(name)
                        msg = f"下游目录存在未登记文件 {name}，已移入 {os.path.basename(dest)}"
                        actions.append(msg)
                        self._log(conn, "recover", msg)

            # 5) 超过 24 小时仍未确认的预览会话作废，避免无限期堆积
            cutoff = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat(
                timespec="seconds"
            )
            stale = conn.execute(
                "SELECT token FROM revision_sessions "
                "WHERE status='pending' AND created_at < ?",
                (cutoff,),
            ).fetchall()
            for s in stale:
                conn.execute(
                    "UPDATE revision_sessions SET status='obsolete' WHERE token=?",
                    (s["token"],),
                )
                self._log(
                    conn, "recover",
                    f"预览会话 {s['token'][:8]} 超过 24 小时未确认，已作废",
                )

            # 6) 盲化导出一致性恢复（与正式供数相互独立，失败不影响原始供数）
            self._recover_blind_exports(conn)
        return actions

    def _recover_blind_exports(self, conn: sqlite3.Connection) -> None:
        # 6.1 清理盲化导出目录中的半写临时文件
        for name in os.listdir(self.blind_export_dir):
            if name.startswith(".tmp-publish-"):
                self._safe_unlink(os.path.join(self.blind_export_dir, name))
                self._log(conn, "recover", f"清理盲化导出遗留临时文件 {name}")

        # 6.2 上次崩溃时未完成的导出：一律置为 failed 并删除可能的半成品，
        #     绝不留下可被下载的部分导出
        building = conn.execute(
            "SELECT token, file_name FROM blind_exports WHERE status='building'"
        ).fetchall()
        for item in building:
            conn.execute(
                "UPDATE blind_exports SET status='failed' WHERE token=?",
                (item["token"],),
            )
            self._safe_unlink(
                os.path.join(self.blind_export_dir, item["file_name"])
            )
            self._log(
                conn, "recover",
                f"盲化导出 {item['token'][:8]} 上次未生成完成，已标记 failed",
            )

        # 6.3 就绪导出的文件缺失/哈希不符：按数据库登记确定性重建（盲码可复现）
        ready = conn.execute(
            "SELECT * FROM blind_exports WHERE status='ready'"
        ).fetchall()
        registered_files = set()
        for item in ready:
            registered_files.add(item["file_name"])
            path = os.path.join(self.blind_export_dir, item["file_name"])
            need_rewrite = True
            if os.path.exists(path):
                with open(path, "rb") as fh:
                    actual_hash = hashlib.sha256(fh.read()).hexdigest()
                need_rewrite = actual_hash != item["content_hash"]
            if need_rewrite:
                csv_text, _ = self._build_blind_csv(conn, item["partner_id"],
                                                    item["version"])
                self._atomic_write(
                    csv_text, self.blind_export_dir, item["file_name"]
                )
                self._log(
                    conn, "recover",
                    f"盲化导出 {item['token'][:8]} 文件缺失/损坏，"
                    f"已按登记 v{item['version']} 重建",
                )

        # 6.4 盲化目录中的游离文件隔离（不直接删除）
        for name in os.listdir(self.blind_export_dir):
            full = os.path.join(self.blind_export_dir, name)
            if os.path.isfile(full) and name not in registered_files:
                self._quarantine(name, source_dir=self.blind_export_dir)
                self._log(
                    conn, "recover",
                    f"盲化导出目录存在未登记文件 {name}，已移入 quarantine",
                )

    def _build_blind_csv(
        self, conn: sqlite3.Connection, partner_id: int, version: int
    ) -> tuple[str, int]:
        """从数据库的版本结果确定性渲染某合作方的盲化 CSV。

        返回 (CSV 文本, 数据行数)。
        """
        rows = self._version_rows(conn, version)
        sample_nos = sorted({r["sample_no"] for r in rows})
        mapping = assert_unique_within_partner(
            self.blind_master_key, partner_id, sample_nos
        )
        blind_rows = [
            {
                "blind_code": mapping[r["sample_no"]],
                "analyte": r["analyte"],
                "concentration": r["concentration"],
            }
            for r in rows
        ]
        return render_blind_csv(blind_rows), len(blind_rows)

    def _quarantine(self, name: str, source_dir: str | None = None) -> str:
        source_dir = source_dir or self.downstream_dir
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
        dest = os.path.join(self.quarantine_dir, f"{stamp}-{name}")
        os.replace(os.path.join(source_dir, name), dest)
        return dest

    def _atomic_write(
        self,
        csv_text: str,
        target_dir: str | None = None,
        final_name: str | None = None,
    ) -> None:
        """同目录临时文件 + fsync + 原子改名，保证读者只看到完整文件。"""
        target_dir = target_dir or self.downstream_dir
        final_path = (
            os.path.join(target_dir, final_name)
            if final_name is not None
            else self.live_path
        )
        tmp_path = os.path.join(
            target_dir, f".tmp-publish-{uuid.uuid4().hex}.csv"
        )
        fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o640)
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="") as fh:
                fh.write(csv_text)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp_path, final_path)
            self._fsync_dir(target_dir)
        except BaseException:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise

    @staticmethod
    def _safe_unlink(path: str) -> None:
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
        except OSError:
            pass

    @staticmethod
    def _fsync_dir(path: str) -> None:
        try:
            fd = os.open(path, os.O_RDONLY)
        except OSError:
            return
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    # ---------- 读 ----------
    def current_registry(self):
        with self._connect() as conn:
            return conn.execute("SELECT * FROM registry WHERE id = 1").fetchone()

    def current_rows(self) -> list[dict]:
        with self._connect() as conn:
            reg = conn.execute("SELECT * FROM registry WHERE id = 1").fetchone()
            if reg is None:
                return []
            return self._version_rows(conn, reg["current_version"])

    def _version_rows(self, conn: sqlite3.Connection, version: int) -> list[dict]:
        cur = conn.execute(
            "SELECT sample_no, analyte, concentration FROM results "
            "WHERE version = ? ORDER BY sample_no, analyte",
            (version,),
        )
        return [dict(r) for r in cur.fetchall()]

    def _render_version(self, conn: sqlite3.Connection, version: int) -> str:
        return render_csv(self._version_rows(conn, version))

    def recent_events(self, limit: int = 20):
        with self._connect() as conn:
            return conn.execute(
                "SELECT * FROM event_log ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()

    def get_session(self, token: str):
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM revision_sessions WHERE token = ?", (token,)
            ).fetchone()
            if row is None:
                return None
            data = dict(row)
            data["rows"] = json.loads(data["payload"])
            return data

    def create_session(self, batch_no: str, base_version: int, rows: list[dict]) -> str:
        token = uuid.uuid4().hex
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO revision_sessions(token, batch_no, base_version, payload,"
                " created_at, status) VALUES (?,?,?,?,?,?)",
                (
                    token,
                    batch_no,
                    base_version,
                    json.dumps(rows, ensure_ascii=False),
                    _now(),
                    "pending",
                ),
            )
        return token

    def mark_obsolete(self, token: str, current_version: int) -> None:
        """预览在确认前已被其他发布超越：作废该会话，强制重新预览。"""
        with self._connect() as conn:
            cur = conn.execute(
                "UPDATE revision_sessions SET status='obsolete' "
                "WHERE token=? AND status='pending'",
                (token,),
            )
            if cur.rowcount:
                self._log(
                    conn, "conflict",
                    f"会话 {token[:8]} 已过期（当前 v{current_version}），"
                    "拒绝覆盖，需重新预览",
                )

    def cancel_session(self, token: str) -> bool:
        with self._connect() as conn:
            cur = conn.execute(
                "UPDATE revision_sessions SET status='cancelled' "
                "WHERE token=? AND status='pending'",
                (token,),
            )
            if cur.rowcount:
                self._log(conn, "cancel", f"放弃修订会话 {token[:8]}")
                return cur.rowcount > 0
        return False

    # ---------- 预览差异 ----------
    def preview_diff(self, new_rows: list[dict]) -> dict:
        """与当前已发布版本比对，返回 增/改/删/不变 四类差异。"""
        old = {(r["sample_no"], r["analyte"]): r["concentration"]
               for r in self.current_rows()}
        new = {(r["sample_no"], r["analyte"]): r["concentration"] for r in new_rows}
        inserts, updates, deletes, unchanged = [], [], [], []
        for key, val in new.items():
            if key not in old:
                inserts.append({"sample_no": key[0], "analyte": key[1], "new": val})
            elif old[key] != val:
                updates.append(
                    {"sample_no": key[0], "analyte": key[1],
                     "old": old[key], "new": val}
                )
            else:
                unchanged.append({"sample_no": key[0], "analyte": key[1], "value": val})
        for key, val in old.items():
            if key not in new:
                deletes.append({"sample_no": key[0], "analyte": key[1], "old": val})
        inserts.sort(key=lambda d: (d["sample_no"], d["analyte"]))
        updates.sort(key=lambda d: (d["sample_no"], d["analyte"]))
        deletes.sort(key=lambda d: (d["sample_no"], d["analyte"]))
        unchanged.sort(key=lambda d: (d["sample_no"], d["analyte"]))
        return {
            "inserts": inserts, "updates": updates,
            "deletes": deletes, "unchanged": unchanged,
        }

    # ---------- 确认发布（核心事务） ----------
    def publish(self, token: str) -> tuple[int, int]:
        """确认整批替换。返回 (新版本号, 行数)。

        并发控制：BEGIN IMMEDIATE 立即拿写锁，事务内再次核对会话基线版本，
        若期间已有别人发布（current_version > base_version），本会话作废，
        抛出 PublishConflictError，调用方须重新预览。
        """
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            session = conn.execute(
                "SELECT * FROM revision_sessions WHERE token=?", (token,)
            ).fetchone()
            if session is None:
                raise PublishConflictError("修订会话不存在或已失效，请重新上传预览")
            if session["status"] != "pending":
                label = {"published": "已发布", "obsolete": "已过期",
                         "cancelled": "已取消"}.get(session["status"], session["status"])
                raise PublishConflictError(f"该修订会话{label}，请重新上传预览")

            reg = conn.execute("SELECT * FROM registry WHERE id=1").fetchone()
            current_version = reg["current_version"] if reg else 0
            if session["base_version"] != current_version:
                conn.execute(
                    "UPDATE revision_sessions SET status='obsolete' WHERE token=?",
                    (token,),
                )
                self._log(
                    conn, "conflict",
                    f"会话 {token[:8]} 基于 v{session['base_version']} 发起，"
                    f"当前已为 v{current_version}，拒绝覆盖，需重新预览",
                )
                raise PublishConflictError(
                    f"版本已变化：您基于 v{session['base_version']} 预览，"
                    f"当前已是 v{current_version}，请重新预览后再发布"
                )

            rows = json.loads(session["payload"])
            new_version = current_version + 1
            csv_text = render_csv(rows)
            content_hash = hashlib.sha256(csv_text.encode("utf-8")).hexdigest()

            # 先原子替换文件（旧文件在 replace 前始终完整可用）
            self._atomic_write(csv_text)

            # 再落库登记；若此后进程崩溃，重启 recover() 以登记为准重建/核对
            conn.executemany(
                "INSERT INTO results(version, batch_no, sample_no, analyte, concentration)"
                " VALUES (?,?,?,?,?)",
                [
                    (new_version, session["batch_no"], r["sample_no"],
                     r["analyte"], r["concentration"])
                    for r in rows
                ],
            )
            conn.execute(
                "INSERT INTO registry(id, current_version, batch_no, row_count,"
                " published_at, content_hash) VALUES (1,?,?,?,?,?) "
                "ON CONFLICT(id) DO UPDATE SET current_version=excluded.current_version,"
                " batch_no=excluded.batch_no, row_count=excluded.row_count,"
                " published_at=excluded.published_at, content_hash=excluded.content_hash",
                (new_version, session["batch_no"], len(rows), _now(), content_hash),
            )
            conn.execute(
                "UPDATE revision_sessions SET status='published' WHERE token=?",
                (token,),
            )
            self._log(
                conn, "publish",
                f"发布 v{new_version}：批次 {session['batch_no']}，{len(rows)} 行，"
                f"sha256={content_hash[:12]}…",
            )
            return new_version, len(rows)

    # ---------- 页面辅助 ----------
    @staticmethod
    def display_concentration(value: float) -> str:
        return format_concentration(value)

    # ---------- 合作方管理 ----------
    def list_partners(self) -> list[sqlite3.Row]:
        """合作方列表（含就绪导出数），撤销的排在后面。"""
        with self._connect() as conn:
            return conn.execute(
                "SELECT p.*, ("
                "  SELECT COUNT(*) FROM blind_exports b"
                "  WHERE b.partner_id = p.id AND b.status='ready'"
                ") AS ready_count FROM partners p"
                " ORDER BY (p.revoked_at IS NOT NULL), p.id"
            ).fetchall()

    def get_partner(self, partner_id: int):
        with self._connect() as conn:
            return conn.execute(
                "SELECT * FROM partners WHERE id = ?", (partner_id,)
            ).fetchone()

    def create_partner(self, name: str) -> dict:
        name = (name or "").strip()
        if not name:
            raise PartnerError("合作方名称不能为空")
        if len(name) > 100:
            raise PartnerError("合作方名称长度不能超过 100 个字符")
        token = uuid.uuid4().hex
        with self._connect() as conn:
            try:
                cur = conn.execute(
                    "INSERT INTO partners(name, token, created_at, revoked_at)"
                    " VALUES (?,?,?,NULL)",
                    (name, token, _now()),
                )
            except sqlite3.IntegrityError as exc:
                raise PartnerError(f"合作方“{name}”已存在，名称不可重复") from exc
            partner_id = cur.lastrowid
            self._log(
                conn, "partner",
                f"建立合作方 {name}（id={partner_id}），盲化域已初始化",
            )
        return {"id": partner_id, "name": name, "token": token}

    def revoke_partner(self, partner_id: int) -> bool:
        """撤销合作方。

        只翻转数据库状态：已就绪的导出文件保留，使已经开始的下载可以完整
        结束；撤销后所有旧下载地址一律拒绝受理新请求。
        """
        with self._connect() as conn:
            partner = conn.execute(
                "SELECT * FROM partners WHERE id = ?", (partner_id,)
            ).fetchone()
            if partner is None:
                raise PartnerError("合作方不存在")
            if partner["revoked_at"] is not None:
                return False
            conn.execute(
                "UPDATE partners SET revoked_at = ? WHERE id = ?",
                (_now(), partner_id),
            )
            ready = conn.execute(
                "SELECT COUNT(*) AS n FROM blind_exports"
                " WHERE partner_id = ? AND status='ready'",
                (partner_id,),
            ).fetchone()["n"]
            self._log(
                conn, "partner",
                f"撤销合作方 {partner['name']}（id={partner_id}）："
                f"停止受理新下载，{ready} 个既有导出仅供已开始的下载读完",
            )
        return True

    def blind_code_for(self, partner_id: int, sample_no: str) -> str:
        """派生单个盲码（供测试/界面展示，不暴露主密钥）。"""
        return blind_code(self.blind_master_key, partner_id, sample_no)

    # ---------- 已发布版本 ----------
    def published_versions(self) -> list[sqlite3.Row]:
        """所有已发布版本（供选择导出版本），仅基于 results 表中已提交的数据。"""
        with self._connect() as conn:
            return conn.execute(
                "SELECT version, MIN(batch_no) AS batch_no, COUNT(*) AS row_count "
                "FROM results GROUP BY version ORDER BY version DESC"
            ).fetchall()

    # ---------- 盲化导出 ----------
    def list_exports(self, partner_id: int) -> list[sqlite3.Row]:
        with self._connect() as conn:
            return conn.execute(
                "SELECT * FROM blind_exports WHERE partner_id = ?"
                " ORDER BY rowid DESC",
                (partner_id,),
            ).fetchall()

    def get_ready_export(self, token: str):
        """下载入口查询：仅当导出与合作方均有效时返回记录，否则返回 None。

        合作方撤销后，这里对任何状态都返回 None → 旧地址不再取数。
        """
        with self._connect() as conn:
            return conn.execute(
                "SELECT b.*, p.name AS partner_name, p.revoked_at "
                "FROM blind_exports b JOIN partners p ON p.id = b.partner_id "
                "WHERE b.token = ? AND b.status='ready' AND p.revoked_at IS NULL",
                (token,),
            ).fetchone()

    def export_path(self, file_name: str) -> str:
        # 文件名由服务端按固定模板生成（blind_<pid>_v<ver>_<token>.csv），
        # 这里再做一次 basename 防护，杜绝数据库被篡改后的路径穿越
        return os.path.join(self.blind_export_dir, os.path.basename(file_name))

    def create_blind_export(self, partner_id: int, version: int) -> dict:
        """为合作方生成某已发布版本的盲化 CSV（完整文件原子可见）。

        保证：
        * 只能基于**已发布的完整版本**生成，导出内容恰好是该版本的全量结果；
        * 合作方已撤销则拒绝受理；
        * 生成失败（版本不存在/盲码碰撞/IO 错误）不会留下任何可用的部分导出：
          登记置 failed、半成品文件删除，原始供数目录完全不被触碰。
        """
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            partner = conn.execute(
                "SELECT * FROM partners WHERE id = ?", (partner_id,)
            ).fetchone()
            if partner is None:
                raise PartnerError("合作方不存在")
            if partner["revoked_at"] is not None:
                raise PartnerError(
                    f"合作方“{partner['name']}”已撤销，不再受理新下载"
                )
            exists = conn.execute(
                "SELECT 1 FROM results WHERE version = ? LIMIT 1", (version,)
            ).fetchone()
            if exists is None:
                raise ExportError(f"版本 v{version} 不存在，只能基于已发布版本导出")

            token = uuid.uuid4().hex
            file_name = f"blind_{partner_id}_v{version}_{token}.csv"
            conn.execute(
                "INSERT INTO blind_exports(token, partner_id, version, row_count,"
                " file_name, content_hash, created_at, status)"
                " VALUES (?,?,?,0,?, '', ?, 'building')",
                (token, partner_id, version, file_name, _now()),
            )

            def _fail(detail: str) -> None:
                # 显式提交 failed 状态：不能随外层异常一起回滚，
                # 否则崩溃/失败后会残留 building 的半成品导出
                conn.execute(
                    "UPDATE blind_exports SET status='failed' WHERE token=?",
                    (token,),
                )
                self._safe_unlink(self.export_path(file_name))
                self._log(conn, "blind", detail)
                conn.commit()

            try:
                csv_text, row_count = self._build_blind_csv(conn, partner_id, version)
            except BaseException as exc:
                _fail(
                    f"合作方 {partner['name']} 的 v{version} 盲化导出生成失败"
                    f"（{type(exc).__name__}），登记 failed，无部分导出"
                )
                if isinstance(exc, BlindCodeCollision):
                    raise ExportError(str(exc)) from exc
                raise

            content_hash = hashlib.sha256(csv_text.encode("utf-8")).hexdigest()
            try:
                self._atomic_write(
                    csv_text, self.blind_export_dir, file_name
                )
            except BaseException:
                _fail(
                    f"合作方 {partner['name']} 的 v{version} 盲化导出写盘失败，"
                    "登记 failed，无部分导出"
                )
                raise

            conn.execute(
                "UPDATE blind_exports SET status='ready', row_count=?,"
                " content_hash=? WHERE token=?",
                (row_count, content_hash, token),
            )
            self._log(
                conn, "blind",
                f"合作方 {partner['name']} 生成 v{version} 盲化导出"
                f"（{row_count} 行，token {token[:8]}…）",
            )
            conn.commit()
            return {
                "token": token,
                "file_name": file_name,
                "version": version,
                "content_hash": content_hash,
            }
        except BaseException:
            conn.rollback()
            raise
        finally:
            conn.close()
