---
title: "Guess IP - AlpacaHack Daily"
category: "misc"
subcategory: "misc"
type: "writeup"
tags: ["misc", "alpacahack", "guess", "miscellaneous", "guess-ip", "alpacahack-daily"]
summary: "misc writeup for \"Guess IP\" from AlpacaHack Daily - techniques: alpacahack, guess, miscellaneous, guess-ip, alpacahack-daily."
source:
  name: "baumroll0928-spec/myRepository"
  url: "https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202606/d08_Guess_IP/README.md"
ctf:
  name: "AlpacaHack Daily"
  year: 2026
  challenge: "Guess IP"
---

## Source

- **CTF:** AlpacaHack Daily
- **Challenge:** Guess IP
- **Date:** 2026-06-08
- **Repository:** [baumroll0928-spec/myRepository](https://github.com/baumroll0928-spec/myRepository)
- **Directory:** <https://github.com/baumroll0928-spec/myRepository/tree/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202606/d08_Guess_IP>
- **File:** <https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202606/d08_Guess_IP/README.md>

---
# Guess IP

## 問題

10.0.0.1から10.255.255.254の中からIPアドレスを当ててみて！

### app
```py
print("Example: 10.123.45.67")
ip = input("Enter IP> ").strip()

try:
    ipaddress.IPv4Address(ip)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(1.0)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    sock.sendto(b"hello", (ip, 1234))

    try:
        data, _ = sock.recvfrom(4096)
        print(data.decode())
    except socket.timeout:
        print("no response")

except Exception as e:
    print(f"Error: {e}")
```

### server
```py
FLAG = os.environ.get("FLAG", "Alpaca{REDACTED}")

message = (
    f"Hello from {psutil.net_if_addrs()['eth0'][0].address}\n"
    f"Here is your flag: {FLAG}"
)

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("0.0.0.0", 1234))

while True:
    data, addr = sock.recvfrom(4096)
    sock.sendto(message.encode(), addr)
```
## 概要

この問題のサーバーでは、`app`と`server`の2つのサービスが稼働しています。

`app`は、IPアドレスを指定すると、そのIPアドレスのポート`1234`に`hello`というUDPパケットを送り付け、応答を待ちます。

`server`は、ポート`1234`でUDPパケットを待ち受け、パケットを受け取ると自身のIPアドレスとフラグを送り返します。

`server`のIPアドレスは`10.0.0.1`～`10.255.255.254`のどれかであることしかわかっていませんが、どうすればそんな`server`にパケットを送り付けてフラグを得ることができるのでしょうか？

## 方針

ブロードキャストアドレスを指定する。

## 解法

IPアドレスの範囲が`10.0.0.0`～`10.255.255.255`ではなく`10.0.0.1`～`10.255.255.254`になっていることからもわかるように、IPアドレスには個々の機器等には割り当てられない特別な意味を持つものがあります。

* ネットワークアドレス: ホスト部のビットが全て`0`であるアドレス。ネットワークそのものを表す。`10.0.0.0`や`192.168.1.0`など。

* ブロードキャストアドレス: ホスト部のビットが全て`1`であるアドレス。同一ネットワーク内に一斉送信するときに使う。`10.255.255.255`や`192.168.1.255`など。

だいぶメタいですが、Easy問題なのでとりあえずこの2つは試してみる価値があるでしょう。

```
$ nc localhost 1337
Example: 10.123.45.67
Enter IP> 10.0.0.0
no response
```
```
$ nc localhost 1337
Example: 10.123.45.67
Enter IP> 10.255.255.255
Hello from 10.99.99.99
Here is your flag: Alpaca{REDACTED}
```

ブロードキャストアドレスの方が正解でした。

あらためて、ブロードキャストアドレスは、同一ネットワーク内の相手に一斉送信することができる特殊なIPアドレスです。

例えば、「おーい、田中さーん！」と呼びかけると田中さんだけが返事をするのに対して、「おーい、みんなー！」と呼びかけると全員が返事をするというイメージですね。

今回の問題では「田中」という名前がわからなかったので、みんなに呼びかけたところ、結果的に田中さんから返事をもらえたというわけです。

なお、ブロードキャストアドレスに対してパケットを投げるには、今回の問題でも設定されている
```py
sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
```
の設定が必要なようです。

## その他

試しにサーバーを３つに増やして全て返してくれるか実験してみました。

`compose.yaml`に下記を追加します。
```yml
  server1:
    build: ./server
    restart: unless-stopped
    environment:
      FLAG: "Alpaca{REDACTED_111}"
    networks:
      ctfnet:
        ipv4_address: 10.111.111.111

  server2:
    build: ./server
    restart: unless-stopped
    environment:
      FLAG: "Alpaca{REDACTED_222}"
    networks:
      ctfnet:
        ipv4_address: 10.222.222.222
```
`app.py`も少し修正します。
``` py
    sock.sendto(b"hello", (ip, 1234))
    while True: # ADD
        try:
            data, _ = sock.recvfrom(4096)
            print(data.decode())
        except socket.timeout:
            print("no more response") # MOD
            break # ADD
```
`docker compose up --build`しなおして実行してみます。
```
$ nc localhost 1337
Example: 10.123.45.67
Enter IP> 10.255.255.255
Hello from 10.111.111.111
Here is your flag: Alpaca{REDACTED_111}
Hello from 10.99.99.99
Here is your flag: Alpaca{REDACTED}
Hello from 10.222.222.222
Here is your flag: Alpaca{REDACTED_222}
no more response
```
全て受け取ることができました。

次に、
```py
sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
```
を削除して実験してみました。

```
$ nc localhost 1337
Example: 10.123.45.67
Enter IP> 10.255.255.255
Error: [Errno 13] Permission denied
```
ちゃんとエラーになるようです。
