from ipaddress import IPv4Address
from netstack.checksum import internet_checksum

def parse_udp(datagram):
    if len(datagram) < 8:
        return None

    src_port = int.from_bytes(datagram[0:2], "big")
    dst_port = int.from_bytes(datagram[2:4], "big")
    length = int.from_bytes(datagram[4:6], "big")
    checksum = int.from_bytes(datagram[6:8], "big")

    if length < 8:
        return None
    
    if length > len(datagram):
        return None

    payload = datagram[8:length]

    return {
        "src_port": src_port,
        "dst_port": dst_port,
        "length": length,
        "checksum": checksum,
        "payload": payload
    }


def build_udp_pseudo_header(src_ip, dst_ip, udp_length):
    
    if udp_length < 8 or udp_length > 65535:
        raise ValueError("UDPの長さは8~65535で指定してね")

    
    return(
        IPv4Address(src_ip).packed +
        IPv4Address(dst_ip).packed +
        bytes([0, 17]) +
        udp_length.to_bytes(2, "big")
    )


def verify_udp_checksum(datagram, src_ip, dst_ip):
    udp = parse_udp(datagram)

    if udp is None:
        return False

    if udp["checksum"] == 0:
        return True

    pseudo_header = build_udp_pseudo_header(
        src_ip, dst_ip, udp["length"]
    )

    udp_bytes = datagram[:udp["length"]]

    result = internet_checksum(pseudo_header + udp_bytes)

    return result == 0