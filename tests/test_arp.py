from netstack.ethernet import parse_ethernet, build_ethernet
from netstack.arp import parse_arp, build_arp_reply

frame = bytes.fromhex(
    "ff ff ff ff ff ff "
    "02 00 00 00 00 01 "
    "08 06 "
    "00 01 08 00 06 04 00 01 "
    "02 00 00 00 00 01 "
    "0a 0a 00 01 "
    "00 00 00 00 00 00 "
    "0a 0a 00 02"
)

ethernet = parse_ethernet(frame)

assert ethernet is not None
assert ethernet["protocol"] == "ARP"

arp = parse_arp(ethernet["payload"])

assert arp is not None
assert arp["opcode"] == 1
assert arp["sender_ip"] == "10.10.0.1"
assert arp["target_ip"] == "10.10.0.2"
assert arp["sender_mac"] == "02:00:00:00:00:01"
assert arp["target_mac"] == "00:00:00:00:00:00"

print("Opcode:", arp["opcode"])
print("Sender:", arp["sender_ip"], arp["sender_mac"]) 
print("Target:", arp["target_ip"], arp["target_mac"]) 

assert parse_arp(bytes.fromhex("00 01")) is None

print("ARP parser: OK")


# 自作スタックのIP・MACアドレス
LOCAL_IP = "10.10.0.2"
LOCAL_MAC = "02:00:00:00:00:02"

# ARP Replyを生成
reply_bytes = build_arp_reply(arp, LOCAL_MAC, LOCAL_IP)

assert reply_bytes is not None
assert len(reply_bytes) == 28

# 生成したReplyをもう一度解析して確認
reply = parse_arp(reply_bytes)

assert reply is not None
assert reply["opcode"] == 2
assert reply["sender_ip"] == LOCAL_IP
assert reply["sender_mac"] == LOCAL_MAC
assert reply["target_ip"] == "10.10.0.1"
assert reply["target_mac"] == "02:00:00:00:00:01"

print("ARP Reply:", reply_bytes.hex(" "))
print("ARP Reply builder: OK")

# 自分宛てでないARP Requestには返信しない
assert build_arp_reply(arp, LOCAL_MAC, "10.10.0.99") is None

# ARP Replyに対してARP Replyを返さない
assert build_arp_reply(reply, LOCAL_MAC, LOCAL_IP) is None

print("ARP Reply rejection tests: OK")

expected_reply = bytes.fromhex(
    "00 01 08 00 06 04 00 02 "
    "02 00 00 00 00 02 "
    "0a 0a 00 02 "
    "02 00 00 00 00 01 "
    "0a 0a 00 01"
)

assert reply_bytes == expected_reply

print("ARP Reply binary test: OK")

# ARP ReplyをEthernetフレームに格納
ethernet_reply = build_ethernet(
    arp["sender_mac"],
    LOCAL_MAC,
    0x0806,
    reply_bytes
)

assert len(ethernet_reply) == 42

# Ethernetヘッダーのバイト列を検証
expected_header = bytes.fromhex(
    "02 00 00 00 00 01 "
    "02 00 00 00 00 02 "
    "08 06"
)

assert ethernet_reply[:14] == expected_header
assert ethernet_reply[14:] == expected_reply

print("Ethernet Reply builder: OK")