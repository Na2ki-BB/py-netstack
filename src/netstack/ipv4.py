from ipaddress import IPv4Address


def parse_ipv4(packet):
    if len(packet) < 20:
        return None

    version = packet[0] >> 4
    header_length = (packet[0] & 0x0F) * 4

    if version != 4 or header_length < 20:
        return None

    if header_length > len(packet):
        return None

    total_length = int.from_bytes(packet[2:4], "big")

    if total_length < header_length or total_length > len(packet):
        return None


    ttl = packet[8]
    protocol = packet[9]

    src_ip = str(IPv4Address(packet[12:16]))
    dst_ip = str(IPv4Address(packet[16:20]))


    payload = packet[header_length:total_length]

    return {
        "version": version,
        "header_length": header_length,
        "total_length": total_length,
        "ttl": ttl,
        "protocol": protocol,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "payload": payload 
    }