from netstack.udp import (
    build_udp,
    parse_udp,
    verify_udp_checksum,
    build_udp_pseudo_header
)
from netstack.checksum import internet_checksum

SRC_IP = "10.10.0.1"
DST_IP = "10.10.0.2"

# 1. 既知のバイト列と一致するか
datagram = build_udp(
    SRC_IP, DST_IP, 50000, 12345, b"HELLO"
)

expected = bytes.fromhex(
    "C3 50 30 39 00 0D 14 A2 48 45 4C 4C 4F"
)

assert datagram == expected
assert len(datagram) == 13
assert verify_udp_checksum(datagram, SRC_IP, DST_IP) is True

udp = parse_udp(datagram)

assert udp is not None
assert udp["src_port"] == 50000
assert udp["dst_port"] == 12345
assert udp["length"] == 13
assert udp["checksum"] == 0x14A2
assert udp["payload"] == b"HELLO"

print("UDP:", datagram.hex(" "))
print("Normal / odd-length payload: OK")

# 2. データが空でもUDPヘッダー8バイトを作れる
empty = build_udp(
    SRC_IP, DST_IP, 50000, 12345, b""
)

assert len(empty) == 8
assert empty[8:] == b""
assert verify_udp_checksum(empty, SRC_IP, DST_IP) is True

print("Empty payload: OK")

# 3. チェックサム計算結果が0になるケース
zero_input = bytes.fromhex(
    "C3 50 30 39 00 0A 00 00 F8 39"
)

pseudo = build_udp_pseudo_header(SRC_IP, DST_IP, 10)

assert internet_checksum(pseudo + zero_input) == 0

zero_case = build_udp(
    SRC_IP, DST_IP, 50000, 12345, bytes.fromhex("F8 39")
)

assert zero_case == bytes.fromhex(
    "C3 50 30 39 00 0A FF FF F8 39"
)

assert verify_udp_checksum(zero_case, SRC_IP, DST_IP) is True
assert internet_checksum(pseudo + zero_case) == 0

print("Computed-zero checksum: OK")
print("UDP builder tests: OK")