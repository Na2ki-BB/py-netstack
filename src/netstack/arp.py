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


def build_arp_reply(request, local_mac, local_ip):
    # ARP Requestかつ自分のIP宛て以外は返信しない
    if request["opcode"] != 1:
        return None
    
    if request["target_ip"] != local_ip:
        return None

    
    local_mac_bytes = bytes.fromhex(local_mac.replace(":", ""))
    requester_mac_bytes = bytes.fromhex(
        request["sender_mac"].replace(":", "")
    )

    if len(local_mac_bytes) != 6 or len(requester_mac_bytes)  != 6:
        raise ValueError("MACアドレスが6バイトでないよ♪")

    header = (
        (1).to_bytes(2, "big") +
        (0x0800).to_bytes(2, "big") +
        bytes([6, 4]) +
        (2).to_bytes(2, "big")
    )


    reply = (
        header +
        local_mac_bytes +
        IPv4Address(local_ip).packed +
        requester_mac_bytes +
        IPv4Address(request["sender_ip"]).packed
    )

    return reply