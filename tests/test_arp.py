from netstack.ethernet import parse_ethernet
from netstack.arp import parse_arp

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