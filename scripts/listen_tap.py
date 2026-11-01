import os
import fcntl
import struct

from netstack.ethernet import parse_ethernet, build_ethernet
from netstack.arp import parse_arp, build_arp_reply

TUNSETIFF = 0x400454CA
IFF_TAP = 0x0002
IFF_NO_PI  = 0x1000
LOCAL_IP = "10.10.0.2"
LOCAL_MAC = "02:00:00:00:00:02"

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

        reply_payload = build_arp_reply(
            arp, LOCAL_MAC, LOCAL_IP
        )

        if reply_payload is None:
            continue

        reply_frame = build_ethernet(
            arp["sender_mac"],
            LOCAL_MAC,
            0x0806,
            reply_payload
        )

        written = os.write(fd, reply_frame)

        if written != len(reply_frame):
            raise RuntimeError("ARP Replyの送信が不完全だよ")

        print(
            "ARP返信:",
            LOCAL_IP,
            "->",
            arp["sender_ip"],
            "送信バイト数:",
            written
        )

except KeyboardInterrupt:
    print("受信終了")

finally:
    os.close(fd)