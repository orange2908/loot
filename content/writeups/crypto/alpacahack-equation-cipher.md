---
title: "Equation Cipher - AlpacaHack Daily"
category: "crypto"
subcategory: "crypto"
type: "writeup"
tags: ["crypto", "alpacahack", "sage", "equation", "cipher", "cryptography"]
summary: "(2x - A)(3x - l)(5x - p)(7x - a)(11x - c)(13x - a) ..."
source:
  name: "baumroll0928-spec/myRepository"
  url: "https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202605/d14_Equation_Cipher/README.md"
ctf:
  name: "AlpacaHack Daily"
  year: 2026
  challenge: "Equation Cipher"
---

## Source

- **CTF:** AlpacaHack Daily
- **Challenge:** Equation Cipher
- **Date:** 2026-05-14
- **Repository:** [baumroll0928-spec/myRepository](https://github.com/baumroll0928-spec/myRepository)
- **Directory:** <https://github.com/baumroll0928-spec/myRepository/tree/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202605/d14_Equation_Cipher>
- **File:** <https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202605/d14_Equation_Cipher/README.md>

---
# Equation Cipher

## 問題

(2x - A)(3x - l)(5x - p)(7x - a)(11x - c)(13x - a) ... SageMath に入門してみよう

```sage
import os

FLAG = os.getenv("FLAG", "Alpaca{REDACTED}")
ps = prime_range(200)
assert len(FLAG) <= len(ps)
var("x")
print(expand(prod(p*x - ord(c) for p, c in zip(ps, FLAG))))
```

## 概要

フラグの文字列から`x`の多項式を生成するSageMathスクリプトとその出力結果が与えられています。

この多項式からフラグを逆算するにはどうすればいいのでしょうか？

## 方針

SageMathを使って方程式の解を求め、各因子に割り当ててフラグを復元する。

## 解法

まずは数学のお話です。`x`の方程式

$`(a_{1}x - b_{1})(a_{2}x - b_{2}) ... (a_{N}x - b_{N}) = 0`$

の解は、

$`x = \frac{b_{1}}{a_{1}}, \frac{b_{2}}{a_{2}}, ..., \frac{b_{N}}{a_{N}}`$

になります。（どれかの因子が`0`であれば全体が`0`になるため。）

これは左辺を展開してももちろん変わりません。

この問題では、$`a_{i}`$は素数を小さい順に列挙したものであり、$`b_{i}`$はフラグの文字の文字コード（たぶん`0x21-0x7e`）を先頭から順にとったものです。

もし、$`a_{i}`$と$`b_{i}`$が互いに素である場合、つまり$`\frac{b_{i}}{a_{i}}`$が約分できない場合は、分母に$`a_{i}`$がそのまま出てくるはずです。

この場合、$`\frac{b_{i}}{a_{i}}`$に$`p_{i}`$を掛けたら整数になるような素数$`p_{i}`$を見つけることができれば、$`a_{i} = p_{i}, b_{i} = \frac{b_{i}}{a_{i}} \cdot p_{i}`$で$`a_{i}`$と$`b_{i}`$を一意に復元できそうです。

しかし、$`a_{i}`$と$`b_{i}`$が互いに素でない場合、つまり$`a_{i}`$が$`b_{i}`$を割り切って整数に約分できてしまう場合は、複数の候補が出てきてしまうかもしれません。

では、実際にSageMathを使って解いてみます。

※私はSageMathの環境を自分のローカルに構築するのは面倒なのでいつもオンラインのサービスを使っています。例えば[SageMathCell](https://sagecell.sagemath.org/)は、ブラウザでスクリプトを入力してサクッと実行できるのでとても便利です。

まず方程式を解いてみます。

```sage
x = var('x')
fx = output.txtからコピペ
res = solve(fx == 0, x)
```

この`res`は、
```
[
x == (116/73),
x == (105/79),
x == (101/37),
...
x == 9
]
```
のような有理数（整数の分数）の解のリストとして返ってきます。

これを使ってフラグを組み立てていきます。

```sage
ps = prime_range(200)
flag = {}
for r in res:
    for p in ps:
        v = r.rhs() * p
        if v.is_integer() and 0x20 < v < 0x7f:
            if p in flag:
                flag[p].append(chr(v))
            else:
                flag[p] = [chr(v)]
```

組み立てたら、いったん全部出力してみます。

```sage
for p in sorted(flag.keys()):
    print(f"{p}: {flag[p]}")
```

```
2: ['H', 'A']
3: ['l']
5: ['p', '-']
7: ['a', '?']
11: ['c']
13: ['u', 'a']
17: ['{']
19: ['o']
...
113: ['}']
```

やはり複数候補をもつ部分があるようですが、幸い複数候補があるのは`6`文字目までのようです。

フラグの先頭部分は`Alpaca{`に決まっていて、実際これらの文字は候補に入っているので、この部分はもう決め打ちにしてしまいましょう。

```sage
flag_str = "Alpaca{" + "".join(flag[p][0] for p in sorted(flag.keys())[7:])
print(flag_str)
```

これで正しいフラグを得ることができました。

これは次の問題の予告でしょうか？
