from netstack.udp import build_udp_pseudo_header, verify_udp_checksum
from netstack.checksum import internet_checksum

SRC_IP = "10.10.0.1"
DST_IP = "10.10.0.2"

# 擬似ヘッダーが、仕様どおりの12バイトになっているか
expected_pseudo_header = bytes.fromhex(
    "0A 0A 00 01 "
    "0A 0A 00 02 "
    "00 11 "
    "00 0D"
)

pseudo_header = build_udp_pseudo_header(SRC_IP, DST_IP, 13)

assert len(pseudo_header) == 12
assert pseudo_header == expected_pseudo_header

# チェックサム欄をゼロにした計算用データ
without_checksum = bytes.fromhex(
    "C3 50 30 39 00 0D 00 00 48 45 4C 4C 4F"
)

assert internet_checksum(
    expected_pseudo_header + without_checksum
) == 0x14A2

# 正しいチェックサムが入ったUDPデータ
valid_datagram = bytes.fromhex(
    "C3 50 30 39 00 0D 14 A2 48 45 4C 4C 4F"
)

valid = verify_udp_checksum(valid_datagram, SRC_IP, DST_IP)

assert valid is True
print("Valid checksum:", valid)

# 最後の1バイトだけを4Fから4Eへ変更
damaged_datagram = bytes.fromhex(
    "C3 50 30 39 00 0D 14 A2 48 45 4C 4C 4E"
)

damaged = verify_udp_checksum(damaged_datagram, SRC_IP, DST_IP)

assert damaged is False
print("Damaged payload:", damaged)

# UDP本体は同じでも、外側の宛先IPが違えば今回の検算は不一致
wrong_ip = verify_udp_checksum(
    valid_datagram, SRC_IP, "10.10.0.3"
)

assert wrong_ip is False
print("Wrong destination IP:", wrong_ip)

# チェックサム未使用は今回のIPv4受信方針では許可
unchecked = verify_udp_checksum(without_checksum, SRC_IP, DST_IP)

assert unchecked is True
print("No checksum (IPv4):", unchecked)

# チェックサム未使用でも、長さが不正なら拒否
truncated = bytes.fromhex(
    "C3 50 30 39 00 0E 00 00 48 45 4C 4C 4F"
)

assert verify_udp_checksum(truncated, SRC_IP, DST_IP) is False

# ヘッダーが短すぎる場合も拒否
assert verify_udp_checksum(b"\x00", SRC_IP, DST_IP) is False

# UDP Lengthより後ろのバイトは検算に混ぜない
assert verify_udp_checksum(
    valid_datagram + b"\xAA\xBB", SRC_IP, DST_IP
) is True

# 5バイトのHELLOを使っても、計算用のゼロは元データに増えない
assert len(valid_datagram) == 13
assert valid_datagram[8:] == b"HELLO"

print("UDP checksum tests: OK")