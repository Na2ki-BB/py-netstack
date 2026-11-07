import socket

SERVER_IP = "10.10.0.2"
SERVER_PORT = 12345

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

try:
    # 0はポート番号0ではなく自動割り当ての意
    sock.bind(("10.10.0.1", 0))
    sock.settimeout(3.0)

    print("Client:", sock.getsockname())

    for payload in (b"HELLO", b"ABCD", b""):
        sock.sendto(payload, (SERVER_IP, SERVER_PORT))
        print("送信:", payload)

        received, address = sock.recvfrom(2048)

        assert address == (SERVER_IP, SERVER_PORT)
        assert received == payload

        print("受信:", received, "送信元:", address)

    print("UDP Echo tests: OK")

except socket.timeout:
    raise RuntimeError("UDPの応答がタイムアウトしました。受信側のログを確認してください")

finally:
    sock.close()