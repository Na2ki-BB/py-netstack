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


def parse_ethernet(frame):
    if len(frame) < 14:
        return None

    dst_mac = frame[0:6].hex(":")
    src_mac = frame[6:12].hex(":")
    ether_type = int.from_bytes(frame[12:14], "big")
    frame_length = len(frame)

    return {
        "dst_mac": dst_mac,
        "src_mac": src_mac,
        "ether_type": ether_type,
        "protocol": identify_protocol(frame),
        "frame_length": frame_length,
        "payload": frame[14:]
    }