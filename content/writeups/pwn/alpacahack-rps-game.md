---
title: "RPS GAME - AlpacaHack Daily"
category: "pwn"
subcategory: "pwn"
type: "writeup"
tags: ["pwn", "alpacahack", "rps", "game", "binary-exploitation", "rps-game"]
summary: "pwn writeup for \"RPS GAME\" from AlpacaHack Daily - techniques: alpacahack, rps, game, binary-exploitation, rps-game."
source:
  name: "baumroll0928-spec/myRepository"
  url: "https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202606/d05_RPS_GAME/README.md"
ctf:
  name: "AlpacaHack Daily"
  year: 2026
  challenge: "RPS GAME"
---

## Source

- **CTF:** AlpacaHack Daily
- **Challenge:** RPS GAME
- **Date:** 2026-06-05
- **Repository:** [baumroll0928-spec/myRepository](https://github.com/baumroll0928-spec/myRepository)
- **Directory:** <https://github.com/baumroll0928-spec/myRepository/tree/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202606/d05_RPS_GAME>
- **File:** <https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202606/d05_RPS_GAME/README.md>

---
# RPS GAME

## 問題

✊️️🖐️✌️

```py
FLAG = "Alpaca{REDACTED}"
HANDS = ["r", "p", "s"]
ROUNDS = 1000
TARGET_WIN = int(ROUNDS * 0.6)

def shuffle(items):
    return sorted(items, key=lambda _: random.getrandbits(1))

print("ROCK PAPER SCISSORS GAME")
print(f"Win {TARGET_WIN} times in {ROUNDS} rounds.")
print("Hands: r / p / s")

win = 0
hands = HANDS[:]
for i in range(ROUNDS):
    hands = shuffle(hands)
    opponent = hands[0]
    you = input(f"Round {i+1} > ").strip()
    assert you in HANDS, "Invalid hand."
    result = (HANDS.index(you) - HANDS.index(opponent)) % 3
    win += (result == 1)

    print(f"Opponent: {opponent}, You: {you}")
    print(["Draw", "Win!", "Lose..."][result])
    print(f"Win count: {win}\n")

if win >= TARGET_WIN:
    print(f"Wow, you broke the game ... Flag: {FLAG}")
else:
    print("Leave the game.")
```

## 概要

CPU相手に1000回じゃんけん勝負をして、600回以上勝つとフラグをゲットできます。

普通に挑んだら333回くらいしか勝てませんが、どうすれば600回も勝つことができるのでしょうか？

## 方針

CPUが出す手の偏りを利用して勝率を上げる。

## 解法

過去問にも出たメルセンヌ・ツイスタ解析の問題かと思いましたが、それにしては利用できる情報が少なすぎる気がします。

また、乱数のシードが指定されていないようなので、シードを絞り込んでいって乱数を再現するような方法も使えなさそうです。

ここで、CPUの手を決める部分を見てみると、
```py
def shuffle(items):
    return sorted(items, key=lambda _: random.getrandbits(1))
```
`sample`関数などを使わずになにやら妙な方法でシャッフルしているようです。

`r`, `p`, `s`のリスト`hands`をこの関数でシャッフルし、先頭の要素`hands[0]`をCPUの手としています。

ここでひとつの疑問が浮かびあがりました。

「このシャッフル方法、本当にどの手も出る確率は均等なのかな？」

実験してみます。
```py
import random

HANDS = ["r", "p", "s"]

def shuffle(items):
    return sorted(items, key=lambda _: random.getrandbits(1))

counter = {'r':0, 'p':0, 's':0}
for i in range(100000):
    hands = HANDS[:]
    hands = shuffle(hands)
    counter[hands[0]] += 1

print(counter)
```
10万回試行して、`r`, `p`, `s`がそれぞれ先頭に来る回数を数えています。

これを何回か実行してみると、多少のブレはあるものの、だいたい次のような結果になりました。
```
{'r': 62671, 'p': 24758, 's': 12571}
```

均等であれば全て33333回くらいになるはずですが、かなりの偏りがあるようです。

これなら勝率6割を目指すことができそうですが、なぜこんな偏りがでるのでしょうか？

この`shuffle`関数では、`items`の各要素`r`, `p`, `s`にランダムに`0`or`1`を割り当て、その値が大きい順にソートしています。

`sorted`関数は安定ソートなので、同じ値の場合は順序が元と変わらないことが保証されます。

よって、もし、`r`に割り当てられた値が`1`であれば、ソート後も必ず`r`が先頭になります。

また、`r`の値が`0`であったとしても、`p`と`s`の値も`0`であればやはり`r`が先頭になります。

よって、

$`\frac{1}{2} + (\frac{1}{2})^{3} = \frac{5}{8} = 0.625`$

の確率で`r`が先頭になることになります。

この数値はさっきみた値と比較しても矛盾していません。

はい、もうわかりました。

`r`(グー)に勝つ手は`p`(パー)だから、1000回全部`p`を出せばいいということですね。 ← 馬鹿すぎて滅!

```py
import pwn

HOST, PORT = "localhost", 1337
ROUNDS = 1000

p = pwn.remote(HOST, PORT)
for _ in range(ROUNDS):
    p.sendlineafter(b'> ', b'p')

print(p.recvall().decode())
```
さっそく実行してみます。
```
Opponent: p, You: p
Draw
Win count: 313

Leave the game.
```
全然ダメでした。

ここでひとつ重大な勘違いをしていたことに気付きました。
```py
win = 0
hands = HANDS[:] # 初期化
for i in range(ROUNDS):
    hands = shuffle(hands) # シャッフル
    opponent = hands[0]
```
`hands`は毎回初期化してはいません。

2試合目以降は、前の試合後の`hands`を引き継ぐことになるので、必ずしも`r`が出やすいというわけではないのです。

一瞬諦めかけましたが、方向性は正しかったようです。

正しくは、「`r`を出す確率が`62.5%`」ではなく、「1回目は`r`、2回目以降は直前と同じ手を出す確率が`62.5%`」です。

よって、「1試合目は`p`を出し、2～1000試合目は前回相手が出した手に勝つ手を出す」のが最善策となります。

この戦略で修正したソルバーは下記のようになります。

```py
import pwn

#HOST, PORT = "localhost", 1337
HOST, PORT = "34.170.146.252", 45243
ROUNDS = 1000
win_hand = {'r':'p', 'p':'s', 's':'r'}

p = pwn.remote(HOST, PORT)
p.recvuntil(b'> ')
myhand = win_hand['r']
for _ in range(ROUNDS - 1):
    p.sendline(myhand.encode())
    d = p.recvuntil(b'> ')
    data = d.decode().split()
    opponent = data[1][0]
    myhand = win_hand[opponent]
p.sendline(myhand.encode())

print(p.recvall().decode())
```
