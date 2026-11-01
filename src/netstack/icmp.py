from netstack.checksum import internet_checksum


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


def build_icmp_echo_reply(request):
    if request["type"] != 8 or request["code"] != 0:
        return None

    reply_without_checksum = (
        bytes([0, 0]) +
        b"\x00\x00" +
        request["identifier"].to_bytes(2, "big") +
        request["sequence"].to_bytes(2, "big") +
        request["data"]
    )

    checksum = internet_checksum(reply_without_checksum)

    reply = (
        reply_without_checksum[:2] +
        checksum.to_bytes(2, "big") +
        reply_without_checksum[4:]
    )

    return reply