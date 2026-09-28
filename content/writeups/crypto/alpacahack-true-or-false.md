---
title: "True or False - AlpacaHack Daily"
category: "crypto"
subcategory: "crypto"
type: "writeup"
tags: ["crypto", "alpacahack", "eval", "true", "false", "cryptography"]
summary: "crypto writeup for \"True or False\" from AlpacaHack Daily - techniques: alpacahack, eval, true, false, cryptography."
source:
  name: "baumroll0928-spec/myRepository"
  url: "https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202607/d23_True_or_False/README.md"
ctf:
  name: "AlpacaHack Daily"
  year: 2026
  challenge: "True or False"
---

## Source

- **CTF:** AlpacaHack Daily
- **Challenge:** True or False
- **Date:** 2026-07-23
- **Repository:** [baumroll0928-spec/myRepository](https://github.com/baumroll0928-spec/myRepository)
- **Directory:** <https://github.com/baumroll0928-spec/myRepository/tree/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202607/d23_True_or_False>
- **File:** <https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202607/d23_True_or_False/README.md>

---
# True or False

## 問題

全ては二元論に通じます。陰と陽、昼と夜、真と偽。

```py
FLAG = "Alpaca{REDACTED}"
MAX_EVALS = 28

ALLOWED_CHARS = (
    "0123456789"
    "a"
    "+-*/()<>="
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

$`0 ～ 2^{44}-1`$のランダムな整数`a`を推測する数あてゲームです。

`0123456789a+-*/()<>=`のみで構成される任意のコード`code`を`eval()`に渡し計算結果を`bool()`で`True`または`False`のブール値に変換したものを28回教えてもらうことができます。

その後、答えを推測して送信し、あたっていたらフラグを獲得できます。

どうすれば答えを特定できるのでしょうか？

## 解法

送ったコードに対して`True`または`False`が返ってくることから、すぐに思いつくのは二分探索、またはビットごとの特定でしょう。

しかし、いずれの方法でも、1回の質問で半分にしか絞り込むことができないので、28回の質問では最大で$`2^{28}`$通りしか区別できません。

よって、可能性が$`2^{44}`$個ある答えの種類には全然足りないので、これらの方法ではダメです。

ところで、コードを送って返ってくる結果は本当に`True`か`False`だけでしょうか？

ブール値を計算している部分の周辺に注目してください。

```py
    try:
        ...
    except Exception:
        print("Error")
```

により、`eval`の計算でエラー（例えば0除算）が起こった場合は`True`でも`False`でもなく`Error`が返ってきます。

これにより、３つに分岐して絞り込んでいくことで答えを求めることを考えます。

$`2^{44} = 17592186044416`$

$`3^{28} = 22876792454961`$

より、$`2^{44} < 3^{28}`$なので、この方法なら十分に答えを特定できます。

具体的にはどのようなコードを送ればいいのでしょうか？

ここでは、答えを3進数で表したときの各桁の値を1つずつ特定していくことにします。

まず、答えを3進数で表したときの各桁を`x`で表せたと仮定します。

このとき、
```
2 // x == 1
```
を送ると、

- `x`が`0`のとき、0除算のエラーを起こす
- `x`が`1`のとき、`2 == 1`により`False`を返す
- `x`が`2`のとき、`1 == 1`により`True`を返す

によりそれぞれ区別することができます。

あとは、3進数の各桁`x`を求められればよさそうです。

ここで、
```
a // (3 ** i) % 3
```
としたいところですが、なんと今回は`%`が使えません。

よって、剰余（割り算のあまり）の計算は他の演算子を使って自分で実装する必要があります。

そもそも剰余って何でしょうか？

例えば、100÷7は、100から7を除けるだけ除いて残ったものがあまりになります。

この場合は、100を7で割った整数の商である数の分、14回除くことができるので、100-7×14=2があまりになります。

同じように計算すると、`x`の部分は
```
a // (3 ** i) - 3 * (a // (3 ** (i+1)))
```
となります。

以上より、送るべきコードは
```
2 // (a // (3 ** i) - 3 * (a // (3 ** (i+1)))) == 1
```
となります。（空白は使えないので除去します。あと`i`も正しく置き換えます。）

あとは、返ってきた`Error`,`False`,`True`を`0`,`1`,`2`として3進数を組み立てれば、答えを求めることができます。

```py
import pwn

HOST, PORT = "localhost", 1337
# HOST, PORT = "34.170.146.252", 5606
p = pwn.remote(HOST, PORT)

ans = 0
for i in range(28):
    code = f"2//(a//(3**{i})-3*(a//(3**{i+1})))==1"
    print(f"{code = }")
    p.sendlineafter(b'Eval > ', code.encode())
    res = p.recvline().strip()
    print(f"{res = }")
    if res == b'True':
        ans += 2 * (3 ** i)
    elif res == b'False':
        ans += (3 ** i)

print(f"{ans = }")
p.sendlineafter(b'Guess > ', str(ans).encode())
print(p.recvline())
```
