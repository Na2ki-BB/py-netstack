## コマンド

### TAP作成
```bash
sudo ip tuntap add dev taplab0 mode tap user "$USER"
sudo ip addr add 10.10.0.1/24 dev taplab0
sudo ip link set taplab0 up
```

## 参考

### EtherType一覧
https://www.iana.org/assignments/ieee-802-numbers
| プロトコル | EtherType（16進数） | 用途 |
|---|---|---|
| ARP | `0x0806` | IPv4アドレスからMACアドレスを調べる |
| IPv4 | `0x0800` | IPv4パケット |
| IPv6 | `0x86DD` | IPv6パケット |


### ARPメッセージ28バイトの構造

EthernetとIPv4を使う一般的なARPメッセージは、次の構造になっている。

| 位置（バイト） | サイズ | 項目 | 意味 |
|---|---|---|---|
| 0〜1 | 2B | Hardware Type | Ethernetなら `1` |
| 2〜3 | 2B | Protocol Type | IPv4なら `0x0800` |
| 4 | 1B | Hardware Size | MACアドレスの長さ：`6` |
| 5 | 1B | Protocol Size | IPv4アドレスの長さ：`4` |
| 6〜7 | 2B | Opcode | Request＝`1`、Reply＝`2` |
| 8〜13 | 6B | Sender MAC | 送信元MACアドレス |
| 14〜17 | 4B | Sender IP | 送信元IPv4アドレス |
| 18〜23 | 6B | Target MAC | 対象MACアドレス |
| 24〜27 | 4B | Target IP | 対象IPv4アドレス |

※位置はARPメッセージの先頭を `0` としたもの。Ethernetフレーム全体の先頭ではない。

### カーネル仕様での定義

| 定数 | 値（16進数） | 意味 |
|---|---|---|
| `TUNSETIFF` | `0x400454CA` | TUN/TAPデバイスにインターフェース名や動作モードを設定する制御命令番号 |
| `IFF_TAP` | `0x0002` | Ethernetフレームを扱うTAPモードを指定する |
| `IFF_NO_PI` | `0x1000` | TUN/TAP独自の追加4バイトの情報（Packet Information）を付けない |