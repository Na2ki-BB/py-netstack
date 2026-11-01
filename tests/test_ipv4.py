from netstack.ethernet import parse_ethernet
from netstack.ipv4 import parse_ipv4

frame = bytes.fromhex(
    # Ethernetヘッダー（14バイト）
    "02 00 00 00 00 02 "
    "02 00 00 00 00 01 "
    "08 00 "

    # IPv4ヘッダー（20バイト）
    "45 00 00 20 00 01 00 00 40 01 "
    "66 C6 0a 0a 00 01 0a 0a 00 02 "

    # ICMPメッセージ（12バイト）
    "08 00 47 3a 12 34 00 01 50 49 4e 47"
)

ethernet = parse_ethernet(frame)

assert ethernet is not None
assert ethernet["protocol"] == "IPv4"

ipv4 = parse_ipv4(ethernet["payload"])

assert ipv4 is not None
assert ipv4["version"] == 4
assert ipv4["header_length"] == 20
assert ipv4["total_length"] == 32
assert ipv4["ttl"] == 64
assert ipv4["protocol"] == 1
assert ipv4["src_ip"] == "10.10.0.1"
assert ipv4["dst_ip"] == "10.10.0.2"
assert len(ipv4["payload"]) == 12

# 短すぎるIPv4パケットを拒否
assert parse_ipv4(bytes.fromhex("45 00")) is None

print("IPv4:", ipv4["src_ip"], "->", ipv4["dst_ip"])
print("Protocol:", ipv4["protocol"])
print("IPv4 parser: OK")