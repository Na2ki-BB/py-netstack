from netstack.checksum import internet_checksum

# 簡単な足し算
assert internet_checksum(
    bytes.fromhex("00 01 00 02")
) == 0xFFFC

# 16ビットの桁あふれ
assert internet_checksum(
    bytes.fromhex("FF FF 00 01")
) == 0xFFFE

# 実際のICMP Echo Request
# Checksum部分をゼロにして計算
message = bytes.fromhex(
    "08 00 00 00 12 34 00 01 50 49 4E 47"
)

assert internet_checksum(message) == 0x473A

# 正しいチェックサム入りのデータを検証
message_with_checksum = bytes.fromhex(
    "08 00 47 3A 12 34 00 01 50 49 4E 47"
)

assert internet_checksum(message_with_checksum) == 0

print("Internet Checksum: OK")