from netstack.ethernet import parse_ethernet

frame = bytes.fromhex(
    "ff ff ff ff ff ff 02 00 00 00 00 01 08 06 "
    "00 01 08 00 06 04 00 01"
    "02 00 00 00 00 01 0a 0a 00 01"
    "00 00 00 00 00 00 0a 0a 00 02"
)

header = parse_ethernet(frame)

assert header is not None
assert header["dst_mac"] == "ff:ff:ff:ff:ff:ff"
assert header["protocol"] == "ARP"
assert header["frame_length"] == 42
assert len(header["payload"]) == 28

assert parse_ethernet(bytes.fromhex("08 06")) is None

print("Ethernet paeser: OK  ")