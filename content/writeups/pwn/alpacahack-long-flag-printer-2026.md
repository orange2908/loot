---
title: "Long Flag Printer 2026 - AlpacaHack Daily"
category: "pwn"
subcategory: "pwn"
type: "writeup"
tags: ["pwn", "alpacahack", "long", "printer", "binary-exploitation", "long-flag-printer-2026"]
summary: "pwn writeup for \"Long Flag Printer 2026\" from AlpacaHack Daily - techniques: alpacahack, long, printer, binary-exploitation, long-flag-printer-2026."
source:
  name: "baumroll0928-spec/myRepository"
  url: "https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202607/b17-21_Long_Flag_Printer_2026/README.md"
ctf:
  name: "AlpacaHack Daily"
  year: 2026
  challenge: "Long Flag Printer 2026"
---

## Source

- **CTF:** AlpacaHack Daily (bonus challenge)
- **Challenge:** Long Flag Printer 2026
- **Date:** 2026-07-17-21
- **Repository:** [baumroll0928-spec/myRepository](https://github.com/baumroll0928-spec/myRepository)
- **Directory:** <https://github.com/baumroll0928-spec/myRepository/tree/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202607/b17-21_Long_Flag_Printer_2026>
- **File:** <https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202607/b17-21_Long_Flag_Printer_2026/README.md>

---
# Long Flag Printer 2026

今回はB-SideにはめずらしくMedium難易度だったので挑戦してみました。

## 問題

おかげさまで Flag Printer 2026 のフラグが長くなりました
```py
import time

flag = "Alpaca{******** DUMMY ********}"
assert len(flag) == 31

for i, c in enumerate(flag):
    print(c, end="", flush=True)
    time.sleep(i)
```

## 概要

3月4日のDailyの過去問`Flag Printer 2026`の応用問題のようです。

違うのは`Alpaca{`と`}`を含めたフラグの長さが16文字から31文字に増えている点のみです。

これによってどのような違いが出るのでしょうか？

## 解法

`Flag Printer 2026`のときのように、`-T5`のタイムアウトで落ちないように4.8秒ごとにダミーデータを送信してみました。

※5秒ちょうどだとちょっと不安なので少し短めに4.8秒にしてあります。

```py
import pwn
import time

HOST, PORT = "localhost", 1337
p = pwn.remote(HOST, PORT)

flag = b""
for i in range(97):
    print(f"{i = }")
    p.send(b'a')
    time.sleep(4.8)

print(p.recvall())
```

全ての文字が出力されるのは、1 + 2 + ... + 30 = 465秒後なので、4.8秒×97回でいけると考えました。

しかし、実行してみると、73回目で落ちてしまいました。

最初はたまたま落ちただけかと思いましたが、何度やっても70～80回くらいで落ちてしまいます。

なぜ70回くらいで落ちてしまうのかは、Dockerfileやcompose.yamlを見てもわかりませんでしたが、送信間隔を短くしたり1回に送信するデータ量を増やしたりしても、落ちるまでの回数はあまり変わらないので、回数が重要なのでしょう。

ある程度の回数で落ちてしまうのは仕方なさそうなので、送信回数を節約する方向で考えてみます。

さて、このタイムアウトの`-T5`ですが、送信だけでなく受信でも通信があったとみなされます。

つまり、受信があったら、そこから5秒未満は送信する必要がないということです。

よって、受信があったときから次の受信があるまでの間、4.8秒ごとに受信が無い場合にだけダミーデータを送ってあげれば、送信回数を抑えて効率よくフラグを収集できるのではないでしょうか？

```py
import pwn

HOST, PORT = "localhost", 1337
# HOST, PORT = "34.170.146.252", 54416
p = pwn.remote(HOST, PORT)

flag = b""
cnt = 0
while True:
    try:
        d = p.recv(1, timeout=4.8)
    except:
        d = b''
    if d:
        print(f"received {d}")
        flag += d
        print(f"{flag = }")
    else:
        p.send(b'a')
        cnt += 1
        print("sent b'a'", cnt)
```

これを本番環境で実行したところ、フラグの30文字まで取得したところで落ちてしまいました。

でもまあ、フラグの最後の31文字目はあきらかに`}`ですので、手動で`}`を付け加えて提出しちゃいました。
