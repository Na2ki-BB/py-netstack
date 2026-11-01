def parse_icmp_echo(message):
    if len(message) < 8:
        return None
    
    icmp_type = message[0]
    code = message[1]


    if icmp_type not in (0, 8) or code != 0:
        return None

    checksum = int.from_bytes(message[2:4], "big")
    identifier = int.from_bytes(message[4:6], "big")
    sequence = int.from_bytes(message[6:8], "big")
    data = message[8:]

    return {
        "type": icmp_type,
        "code": code,
        "checksum": checksum,
        "identifier": identifier,
        "sequence": sequence,
        "data": data
    }