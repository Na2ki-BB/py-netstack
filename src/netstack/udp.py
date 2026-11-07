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
