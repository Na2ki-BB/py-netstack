import os
import fcntl
import struct

from netstack.ethernet import parse_ethernet
from netstack.arp import parse_arp

TUNSETIFF = 0x400454CA
IFF_TAP = 0x0002
IFF_NO_PI  = 0x1000

fd = os.open("/dev/net/tun", os.O_RDWR)

ifr = struct.pack(
    "16sH22x", b"taplab0", IFF_TAP | IFF_NO_PI
)

try:
    fcntl.ioctl(fd, TUNSETIFF, ifr)
    print("TAP接続成功！フレーム受信たいきちゅう...")

    while True:
        frame = os.read(fd, 2048)

        ethernet = parse_ethernet(frame)

        if ethernet is None:
            continue

        if ethernet["protocol"] != "ARP":
            continue

        arp = parse_arp(ethernet["payload"])

        if arp is None:
            continue

        print(
            "ARP",
            arp["opcode"],
            arp["sender_ip"],
            "->",
            arp["target_ip"]
        )

except KeyboardInterrupt:
    print("受信終了")

finally:
    os.close(fd)