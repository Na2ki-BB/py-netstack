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

    # 実際の値でなくheader内に記載されたサイズをpayloadに入れる
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
        # 値をバイト列表現にしてつなぎ合わせる
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


def build_udp(src_ip, dst_ip, src_port, dst_port, payload):
    if src_port < 0 or src_port > 65535:
        raise ValueError("送信元ポート番号がおかしいよ")

    if dst_port < 0 or dst_port > 65535:
        raise ValueError("宛先ポート番号がおかしいよ")

    udp_length = 8 + len(payload)

    if udp_length > 65535 - 20:
        raise ValueError("IPv4に格納しきれない大きさだよ")

    datagram_without_checksum = (
        src_port.to_bytes(2, "big") +
        dst_port.to_bytes(2, "big") +
        udp_length.to_bytes(2, "big") +
        b"\x00\x00" +
        payload
    )

    pseudo_header = build_udp_pseudo_header(
        src_ip, dst_ip, udp_length
    )

    checksum = internet_checksum(
        pseudo_header + datagram_without_checksum
    )

    if checksum == 0:
        checksum = 0xFFFF

    return (
        datagram_without_checksum[:6] +
        checksum.to_bytes(2, "big") +
        datagram_without_checksum[8:]
    )