"""合作方盲码的确定性派生。

设计目标
--------
* **跨版本稳定**：同一份主密钥、同一合作方、同一样本号，盲码永远相同，
  因此合作方拿到多个版本的导出后能追踪同一样本的修订。
* **跨合作方不同**：盲码以合作方 id 作为域分隔（domain separation）参与
  HMAC，两个合作方对同一样本得到的盲码互不相关，无法互相串联。
* **不可推算**：盲码是 HMAC-SHA256 的截断输出，样本号或顺序编号都无法
  反推；连续样本号（如 S001、S002）经 PRF 后输出相互独立、不可枚举。
* **重启保持**：主密钥持久化在数据目录的 ``blind_master_key`` 文件中
  （由 Storage 负责加载/生成，权限 0600），进程重启后盲码不变。

盲码取 HMAC 的前 10 字节做 base32hex 编码（80 bit），定长 16 字符；
单一合作方内 2^25 量级以下碰撞概率可忽略，应用侧仍对碰撞做显式校验。
"""
from __future__ import annotations

import base64
import hashlib
import hmac

BLIND_CODE_LENGTH = 16  # 10 字节经 base32hex 编码（80 bit / 5 = 16 字符）
_DOMAIN = b"wq-blind-code/v1"


def blind_code(master_key: bytes, partner_id: int, sample_no: str) -> str:
    """为 (合作方, 样本号) 确定性派生盲码。"""
    msg = b"|".join(
        [
            _DOMAIN,
            str(partner_id).encode("ascii"),
            sample_no.encode("utf-8"),
        ]
    )
    digest = hmac.new(master_key, msg, hashlib.sha256).digest()
    # b32hex 编码（RFC 4648 base32hex，0-9A-V）；Python 3.10/3.11 用无下划线名
    encoder = getattr(base64, "b32hex_encode", base64.b32hexencode)
    return encoder(digest[:10]).decode("ascii")


def assert_unique_within_partner(
    master_key: bytes, partner_id: int, sample_nos
) -> dict[str, str]:
    """为一批样本号生成盲码，并显式校验合作方内无碰撞。

    返回 {样本号: 盲码}；若 50 bit 空间内仍发生碰撞，抛出 ``BlindCodeCollision``，
    由上层拒绝生成导出（绝不输出含重码的不完整导出）。
    """
    mapping: dict[str, str] = {}
    for sample_no in sample_nos:
        code = blind_code(master_key, partner_id, sample_no)
        previous = mapping.get(code)
        if previous is not None and previous != sample_no:
            raise BlindCodeCollision(partner_id, code, previous, sample_no)
        mapping[code] = sample_no
    return {sample: code for code, sample in mapping.items()}


class BlindCodeCollision(Exception):
    """盲码碰撞（概率极低的安全兜底）。"""

    def __init__(self, partner_id: int, code: str, sample_a: str, sample_b: str):
        super().__init__(
            f"合作方 {partner_id} 的盲码碰撞：{code} 同时映射 {sample_a} 与 {sample_b}"
        )
        self.partner_id = partner_id
        self.code = code
        self.sample_a = sample_a
        self.sample_b = sample_b
