def internet_checksum(data):
    if len(data) % 2 != 0:
        data += b"\x00"

    total = 0

    for i in range(0, len (data), 2):
        word = int.from_bytes(data[i:i+2], "big")
        total += word

    while total > 0xFFFF:
        total = (total & 0xFFFF) + (total >> 16)

    return (~total) & 0xFFFF