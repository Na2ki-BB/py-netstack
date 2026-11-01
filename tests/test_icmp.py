from netstack.icmp import parse_icmp_echo, build_icmp_echo_reply
from netstack.checksum import internet_checksum

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


# Echo Replyを生成する
reply_bytes = build_icmp_echo_reply(icmp)

assert reply_bytes is not None

# RFCの仕様に従って用意した期待バイト列
expected_reply = bytes.fromhex(
    "00 00 4F 3A 12 34 00 01 50 49 4E 47"
)

assert reply_bytes == expected_reply

# Replyのチェックサムを検証
assert internet_checksum(reply_bytes) == 0

# 自作パーサーでReplyを再解析
reply = parse_icmp_echo(reply_bytes)

assert reply is not None
assert reply["type"] == 0
assert reply["identifier"] == icmp["identifier"]
assert reply["sequence"] == icmp["sequence"]
assert reply["data"] == icmp["data"]

# Replyに対してさらにReplyを返さない
assert build_icmp_echo_reply(reply) is None

print("ICMP Echo Reply:", reply_bytes.hex(" "))
print("ICMP Echo Reply builder: OK")