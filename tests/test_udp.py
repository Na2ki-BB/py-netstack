from netstack.udp import parse_udp

# UDPヘッダー8バイト + HELLOの5バイト
datagram = bytes.fromhex(
    "C3 50 "
    "30 39 "
    "00 0D "
    "00 00 "
    "48 45 4C 4C 4F"
)

udp = parse_udp(datagram)

assert udp is not None
assert udp["src_port"] == 50000
assert udp["dst_port"] == 12345
assert udp["length"] == 13
assert udp["checksum"] == 0
assert udp["payload"] == b"HELLO"

print("Source port:", udp["src_port"])
print("Destination port:", udp["dst_port"])
print("UDP length:", udp["length"])
print("Payload:", udp["payload"])

# ヘッダーが8バイト未満
assert parse_udp(bytes.fromhex("C3 50 30 39")) is None

# Lengthが7：ヘッダー自身の8バイトより短い
invalid_length = bytes.fromhex("C3 50 30 39 00 07 00 00")
assert parse_udp(invalid_length) is None

# Lengthは14なのに、実データは13バイトしかない
truncated = bytes.fromhex(
    "C3 50 30 39 00 0E 00 00 48 45 4C 4C 4F"
)
assert parse_udp(truncated) is None

# Lengthが8：データ部分が空でも正常
empty_datagram = bytes.fromhex("C3 50 30 39 00 08 00 00")
empty_udp = parse_udp(empty_datagram)

assert empty_udp is not None
assert empty_udp["length"] == 8
assert empty_udp["payload"] == b""

# Lengthより後ろのバイトをUDPのデータに混ぜない
extra_udp = parse_udp(datagram + bytes.fromhex("AA BB"))

assert extra_udp is not None
assert extra_udp["length"] == 13
assert extra_udp["payload"] == b"HELLO"

print("UDP parser: OK")