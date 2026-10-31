frame = bytes.fromhex("ff ff ff ff ff ff 02 00 00 00 00 01 08 06")

print("bytes:", len(frame))
print("dstMAC:", frame[0:6].hex(":"))
print("srcMAC:", frame[6:12].hex(":"))
# print("EtherType:", hex(int.from_bytes(frame[12:14], "big")))

ether_type = int.from_bytes(frame[12:14], "big")

if ether_type == 0x0806:
    print("Protocol: ARP")
elif ether_type == 0x0800:
    print("Protocol: IPv4")
else:
    print("Protocol: Unknown")