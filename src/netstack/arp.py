from ipaddress import IPv4Address


def parse_arp(payload):
    if len(payload) < 28:
        return None

    hardware_type = int.from_bytes(payload[0:2], "big")
    protocol_type = int.from_bytes(payload[2:4], "big")
    hardware_size = payload[4]
    protocol_size = payload[5]

    if hardware_type != 1 or protocol_type != 0x0800:
        return None

    if hardware_size != 6 or protocol_size != 4:
        return None

    opcode = int.from_bytes(payload[6:8], "big")
    sender_mac = payload[8:14].hex(":")
    sender_ip = str(IPv4Address(payload[14:18]))
    target_mac = payload[18:24].hex(":")
    target_ip = str(IPv4Address(payload[24:28]))

    return {
        "opcode": opcode,
        "sender_mac": sender_mac,
        "sender_ip": sender_ip,
        "target_mac": target_mac,
        "target_ip": target_ip
    }