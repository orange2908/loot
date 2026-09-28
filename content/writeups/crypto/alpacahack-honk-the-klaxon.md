---
title: "honk the klaxon - AlpacaHack Daily"
category: "crypto"
subcategory: "prng"
type: "writeup"
tags: ["crypto", "alpacahack", "sage", "xorshift", "honk", "klaxon"]
summary: "crypto writeup for \"honk the klaxon\" from AlpacaHack Daily - techniques: alpacahack, sage, xorshift, honk, klaxon."
source:
  name: "baumroll0928-spec/myRepository"
  url: "https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202606/d24_honk_the_klaxon/README.md"
ctf:
  name: "AlpacaHack Daily"
  year: 2026
  challenge: "honk the klaxon"
---

## Source

- **CTF:** AlpacaHack Daily
- **Challenge:** honk the klaxon
- **Date:** 2026-06-24
- **Repository:** [baumroll0928-spec/myRepository](https://github.com/baumroll0928-spec/myRepository)
- **Directory:** <https://github.com/baumroll0928-spec/myRepository/tree/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202606/d24_honk_the_klaxon>
- **File:** <https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202606/d24_honk_the_klaxon/README.md>

---
# honk the klaxon

やっぱりローカルにSageMath環境を構築しないといけないのかなと少しだけ思った１日でした。

## 問題

Originally “Carry the Flame”, but for AlpacaHack round 2
🌕🌕🌕🌕🌕🌕🌕

```py
KEY = os.urandom(BLOCK_SIZE)
FLAG = os.getenv("FLAG", "flag{example_flag}")

def pbox(bs):
    return bytes(reduce(lambda x, y: x ^ y, [bs[rowi] for rowi in row]) for row in PBOX)

def bxor(bs1, bs2):
    return bytes([b1 ^ b2 for b1, b2 in zip(bs1, bs2)])

def encrypt(pt, key):
    for _ in range(ROUNDS):
        pt = bxor(pt, key)
        pt = pbox(pt)
    return pt

CHALLENGE = os.urandom(32)
print(f"CHALLENGE: {encrypt(CHALLENGE, KEY).hex()}")

for i in range(210 * 2):
    inp = input("pt: ")
    if inp != "guess":
        pt = bytes.fromhex(inp)
        assert len(pt) == BLOCK_SIZE
        print(encrypt(pt, KEY).hex())

    else:
        challenge_guess = input("challenge: ")
        if bytes.fromhex(challenge_guess) == CHALLENGE:
            print(f"=== Your score is {i} ===")
            print("flag:", FLAG)
        exit()
```

## 概要

最初に、ランダムな32バイトの`CHALLENGE`をランダムな32バイトの`KEY`で暗号化した暗号文が与えられます。

その後、任意のバイト列を送るとこれを同じ`KEY`で暗号化したものを返してくれます。（419回まで。）

満足できるまで観測したら、`CHALLENGE`を推測して送信し、当たっていたらフラグを獲得できます。

`KEY`はわかりませんが、どうすれば`CHALLENGE`を推測することができるでしょうか？

## 方針

全ビットが`0`のデータと256ビットのうち各1ビットを`1`に変えたデータの257個のデータを送り、受け取った257個の結果から変換法則を解析して、暗号化CHALLENGEを逆変換する。

## 解法

encrypt関数の処理を見ると、下記の処理を32回繰り返していることがわかります。
- (1) 要素ごとにPBOXで指定した場所の要素を全てXORする
- (2) KEYとXORする

先日の過去問「xorshift521」のときのように、データを長さ256の0/1のベクトルとみなすと、(1)の変換でしているのはビットの切り出し、ビットシフト、XORだけなので、 $`y = Ax`$ のような線形変換になります。

しかし、(2)の変換で固定値を加算しているので、全体で見ると線形変換ではなく $`y = Ax + b`$のような「アフィン変換」として扱う必要があります。

$`A`$ と $`b`$ さえわかれば、 $`x = A^{-1}(y + b)`$ により $`y`$ から $`x`$ を逆変換で求めることができます。

具体的にどのように`A`と`b`を特定すればいいのでしょうか？

最初に暗号化CHALLENGEを取得した後、$`x`$ として全て0のゼロベクトルを送ります。

$`x`$ がゼロベクトルのとき $`Ax`$ もゼロベクトルになるので、 $`y = b`$ が成立し、返ってきた $`y`$ から $`b`$ を特定することができます。

```py
from pwn import *

io = process(['python', './honk_the_klaxon.py'])
fw = open("C:/ctf/sabemath_script.txt", "w")

def hex_to_list(hex_bin):
    bs = bytes.fromhex(hex_bin.decode())
    a = []
    for x in bs:
        for k in range(8):
            a.append((x >> k) & 1)
    return a

io.recvuntil(b"CHALLENGE: ")
C = hex_to_list(io.recvline().strip())
fw.write(f"C = vector(GF(2), {C})\n")

io.sendlineafter(b"pt: ", b"00" * 32)
B = hex_to_list(io.recvline().strip())
fw.write(f"B = vector(GF(2), {B})\n")
```
※print()だと`A`がでかすぎて全て出力できなかったので、ファイル出力にしました。

ここで、行列 $`A`$ の $`i`$ 列目だけを切り出したベクトルを $`A{i}`$、$`i`$ 行目だけ1で他が全て0のベクトルを $`x_{i}`$ と書くことにします。

すると、$`y = Ax_{i} + b = A_{i} + B`$ が成立するので、$`i = 0, 1, 2, ... , 255`$ で $`x_{i}`$ を全て送るとその結果から $`A`$ を組み立てることができます。

```py
fw.write("MS = MatrixSpace(GF(2), 256, 256)\n")
A = [[None for _ in range(256)] for _ in range(256)]
for i in range(32):
    for j in range(8):
        dt = ''.join([(f"{1<<j:02x}" if i == k else "00") for k in range(32)])
        io.sendlineafter(b"pt: ", dt.encode())
        A1 = hex_to_list(io.recvline().strip())
        for k in range(256):
            A[k][i*8+j] = A1[k] ^ B[k]

fw.write(f"A = MS([\n")
fw.write(",\n".join([f"{rowdata}" for rowdata in A]))
fw.write(f"\n])\n")
fw.write("""
C = A.inverse() * (C + B)
chall = ''
for i in range(0, 256, 8):
    x = 0
    for j in range(8):
        x += int(C[i + j]) << j
    chall += f'{x:02x}'
print(chall)
""")
fw.close()
```

その後、`guess`を送って解答モードに入り、interactive()で入力を受け付けるようにします。
```py
io.sendlineafter(b"pt: ", b"guess")
io.interactive()
```

このPythonスクリプトを実行すると、下記のようなSageMathスクリプトが出力されます。
```sage
C = vector(GF(2), [...])
B = vector(GF(2), [...])
MS = MatrixSpace(GF(2), 256, 256)
A = MS([
...
])

C = A.inverse() * (C + B)
chall = ''
for i in range(0, 256, 8):
    x = 0
    for j in range(8):
        x += int(C[i + j]) << j
    chall += f'{x:02x}'
print(chall)
```

これをSageMathで実行すると、例えば
```
87fc1436dbd3743b5e9c2d1765157b7caea6ed18eb8fa804e27b6f0522ea5c62
```
のような結果が出ますので、これをinteractive状態になったコンソールに入力すると、
```
challenge: 87fc1436dbd3743b5e9c2d1765157b7caea6ed18eb8fa804e27b6f0522ea5c62
=== Your score is 257 ===
flag: Alpaca{this_is_sample_flag}
```
サンプルフラグを得ることができました。

しかし、ここで問題が発生しました。

本番環境に切り替えて
```py
#io = process(['python', './honk_the_klaxon.py'])
io = remote("34.170.146.252", 59978)
```
実行すると、提出する前にプログラムが終了してしまうようです。

これは、おそらく本番環境のIOのタイムアウトが短め（20秒くらい？）に設定してあるものと思われます。

これでは、テキストファイルを開く→全選択してコピー→SageMathCellに貼り付ける→実行する→結果が出るのを待つ→結果を選択してコピー→コンソールに貼り付けてEnterを押す、という手順が間に合いそうにありません。

頭の悪い私はここで「ローカルにSageMath環境を構築してすべて自動化しよう」とはならず、「少し時間を稼げばいいんじゃない？」となりました。
```py
import time
for i in range(6):
    time.sleep(10)
    print(f"{i = }")
    io.sendlineafter(b"pt: ", b"00" * 32)
    io.recvline()
```
10秒ごとにダミーの送信を6回繰り返し1分間の猶予を稼ぎます。

これで本番環境でもなんとかフラグを得ることができました。

## その他

おかしな工夫してないで素直にSageMath環境を構築しなさいと言われたような気がした問題でした。

（いや、NumPyとか使って解けばいいじゃんという話かもしれませんが。）

SageMath環境の構築って簡単にできるんでしょうか？どれくらい便利になるんでしょうか？そして、パソコンの空き容量はどれくらい食うんでしょうか？

最近CTF関係でUbuntsuとかいろいろ入れまくっているせいで容量がやばいので、入れなくて済むものはなるべく入れたくないんですけどね。
