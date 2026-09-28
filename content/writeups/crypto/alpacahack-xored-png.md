---
title: "Xored PNG - AlpacaHack Daily"
category: "crypto"
subcategory: "crypto"
type: "writeup"
tags: ["crypto", "alpacahack", "xor", "xored", "png", "cryptography"]
summary: "crypto writeup for \"Xored PNG\" from AlpacaHack Daily - techniques: alpacahack, xor, xored, png, cryptography."
source:
  name: "baumroll0928-spec/myRepository"
  url: "https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202606/d16_Xored_PNG/README.md"
ctf:
  name: "AlpacaHack Daily"
  year: 2026
  challenge: "Xored PNG"
---

## Source

- **CTF:** AlpacaHack Daily
- **Challenge:** Xored PNG
- **Date:** 2026-06-16
- **Repository:** [baumroll0928-spec/myRepository](https://github.com/baumroll0928-spec/myRepository)
- **Directory:** <https://github.com/baumroll0928-spec/myRepository/tree/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202606/d16_Xored_PNG>
- **File:** <https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202606/d16_Xored_PNG/README.md>

---
# Xored PNG

## 問題

PNG画像がXORされてしまいました……

```js
import os

key_hex = os.getenv("KEY_HEX", "00112233445566778899aabbccddeeff")
key = bytes.fromhex(key_hex)
assert len(key) == 16

with open("flag.png", "rb") as f_in:
    png = bytearray(f_in.read())

for i in range(len(png)):
    png[i] ^= key[i % len(key)]

with open("flag.png.xored", "wb") as f_out:
    f_out.write(png)
```

## 概要

もともとあった画像`flag.png`が何らかの16バイトの`key`でXORされた`flag.png.xord`が与えられています。

`key`がわかればもう一度同じ`key`でXORすることで`flag.png`を復元できますが、どうすれば`key`を求めることができるのでしょうか？

## 方針

PNG画像のバイナリ構造上最初の16バイトは決まっていることを利用する。

## 解法

この問題は3月11日の過去問「Find XOR key」の応用版のようですね。

前回と同じように`key`が繰り返し使われているため、`key`1周分の平文の既知部分があれば逆算して`key`を復元できそうです。

ところで、PNG画像のバイナリ構造は通常下記のようになっています。

```
シグネチャ
IHDRチャンク
その他のチャンクたち
IENDチャンク
```

まず最初のシグネチャは、固定の８バイトで次のようになっています
```
バイナリ：\x89 P N G \r \n \x1a \n
１６進数：89 50 4e 47 0d 0a 1a 0a
```
このシグネチャによって、ブラウザやビューワーはPNG画像であると判断することができます。

そして、シグネチャの次には必ずIHDRチャンクがくることが規格上決まっています。

IHDRチャンクは次のようになっています。
```
Length: 4バイト
Type: 4バイト
Data: 13バイト
CRC: 4バイト
```
※多くのファイル形式では数値はリトルエンディアンで記録されますが、PNG画像ではなぜかビッグエンディアンです。

ここで、IHDRチャンクのLengthは13バイト固定であり、TypeはIHDRなので、頭の８バイトは
```
バイナリ: \x00 \x00 \x00 \r I H D R
１６進数: 00 00 00 0d 49 48 44 52
```
となります。

以上より、正しいPNGファイルの先頭16バイトはどんな画像でも
```
バイナリ：\x89 P N G \r \n \x1a \n \x00 \x00 \x00 \r I H D R
１６進数：89 50 4e 47 0d 0a 1a 0a 00 00 00 0d 49 48 44 52
```
であることがわかりました。

この問題で繰り返し使われる`key`の長さも16バイトなので、暗号文の先頭16バイトとこの正規のPNGの先頭16バイトのXORを取れば`key`が求められます。

解き方がわかったのでソルバーを書いてみます。

固定の16バイトを決め打ちで書き込んでも良いですが、今回はPillowライブラリでてきとーなPNG画像データを作ってそこから取ってみました。

```py
from PIL import Image
from io import BytesIO

img = Image.new("RGB", (16, 16), (0, 0, 0)) # 16×16の真っ黒な画像
buf = BytesIO()
img.save(buf, format="PNG")
img_bin = buf.getvalue()
png_head = img_bin[:16]

with open("flag.png.xored", "rb") as f_in:
    png = bytearray(f_in.read())

key_list = []
for i in range(16):
    key_list.append(png[i] ^ png_head[i])
key = bytes(key_list)

for i in range(len(png)):
    png[i] ^= key[i % len(key)]

with open("flag.png", "wb") as f_out:
    f_out.write(png)
```

## おまけ

もとの`flag.png`を復元すると、フラグ文字列の記載の他にQRコードがあり、スマホで読み取るとフラグ文字列の情報をもっていました。

スマホから何らかの方法でパソコンに転送しても良いですが、パソコンだけで画像から直接QRコードを読み込めないでしょうか？

調べたところ、画像からQRコードやバーコードを読み込むことができる`pyzbar`というモジュールを使うのが良さそうです。

```py
# pip install pyzbar
from pyzbar.pyzbar import decode
from PIL import Image

img = Image.open("flag.png")
res = decode(img)
for r in res:
    print("データ:", r.data.decode("utf-8"))
    print("種類:", r.type)
```

しかし、作り終わったあたりで、「このプログラムを作るくらいなら画像のフラグを手打ちした方が早かったんじゃないかな？」ということに気付いてしまいました（笑）

まあ、次回以降も使えることがあるかもしれませんし・・・
