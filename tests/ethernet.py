def identify_protocol(frame):
    if len(frame) < 14:
        return "Invalid"

    ether_type = int.from_bytes(frame[12:14], "big")

    if ether_type == 0x0806:
        return "ARP"
    elif ether_type == 0x0800:
        return "IPv4"
    elif ether_type == 0x86DD:
        return "IPv6"
    else:
        return "Unknown"

frame = bytes.fromhex("ff ff ff ff ff ff 02 00 00 00 00 01 86 DD")

protocol = identify_protocol(frame)

print("Protocol:", protocol)
print(identify_protocol(bytes.fromhex("08 06")))
# print("bytes:", len(frame))
# print("dstMAC:", frame[0:6].hex(":"))
# print("srcMAC:", frame[6:12].hex(":"))
# print("EtherType:", hex(int.from_bytes(frame[12:14], "big")))