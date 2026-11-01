from ipaddress import IPv4Address
from netstack.checksum import internet_checksum

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


def build_ipv4(src_ip, dst_ip, protocol, payload):
    total_length = 20 + len(payload)
    if total_length > 65535:
        raise ValueError("IPv4パケットが大きすぎる")


    header = (
        bytes([0x45, 0x00]) +
        total_length.to_bytes(2, "big") +
        (0).to_bytes(2, "big") +
        (0).to_bytes(2, "big") +
        bytes([64, protocol]) +
        b"\x00\x00" +
        IPv4Address(src_ip).packed +
        IPv4Address(dst_ip).packed
    )

    checksum = internet_checksum(header)

    header = (
        header[:10] +
        checksum.to_bytes(2, "big") +
        header[12:]
    )

    return header + payload