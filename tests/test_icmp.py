from netstack.icmp import parse_icmp_echo

# ICMP Echo Requestのサンプル
message = bytes.fromhex(
    "08 00 47 3A 12 34 00 01 50 49 4E 47"
)

icmp = parse_icmp_echo(message)

assert icmp is not None
assert icmp["type"] == 8
assert icmp["code"] == 0
assert icmp["checksum"] == 0x473A
assert icmp["identifier"] == 0x1234
assert icmp["sequence"] == 1
assert icmp["data"] == b"PING"

# 短すぎるデータは拒否する
assert parse_icmp_echo(bytes.fromhex("08 00")) is None

print("ICMP Type:", icmp["type"])
print("Sequence:", icmp["sequence"])
print("Data:", icmp["data"])
print("ICMP Echo parser: OK")