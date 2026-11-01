import os
import fcntl
import struct

from netstack.ethernet import parse_ethernet, build_ethernet
from netstack.arp import parse_arp, build_arp_reply
from netstack.ipv4 import parse_ipv4, build_ipv4
from netstack.icmp import parse_icmp_echo, build_icmp_echo_reply
from netstack.checksum import internet_checksum

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

        if ethernet["protocol"] == "IPv4":
            ip_packet = ethernet["payload"]
            ipv4 = parse_ipv4(ip_packet)

            if ipv4 is None:
                continue

            if ipv4["dst_ip"] != LOCAL_IP or ipv4["protocol"] != 1:
                continue

            if ipv4["header_length"] != 20:
                continue

            fragment_field = int.from_bytes(ip_packet[6:8], "big")

            if fragment_field & 0xBFFF:
                continue

            ip_header = ip_packet[:ipv4["header_length"]]

            if internet_checksum(ip_header) != 0:
                print("IPv4 Checksumエラー")
                continue

            if internet_checksum(ipv4["payload"]) != 0:
                print("ICMP Checksumエラー")
                continue

            icmp = parse_icmp_echo(ipv4["payload"])

            if icmp is None or icmp["type"] != 8:
                continue

            
            icmp_reply = build_icmp_echo_reply(icmp)

            if icmp_reply is None:
                continue

            ipv4_reply = build_ipv4(
                LOCAL_IP,
                ipv4["src_ip"],
                1,
                icmp_reply
            )

            reply_frame = build_ethernet(
                ethernet["src_mac"],
                LOCAL_MAC,
                0x0800,
                ipv4_reply
            )

            written = os.write(fd, reply_frame)

            if written != len(reply_frame):
                raise RuntimeError("ICMP返信の送信が不完全だよ")

            print(
                "ICMP Echo Reply送信:",
                ipv4["src_ip"],
                "Sequence:",
                icmp["sequence"],
                "Bytes:",
                written
            )

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