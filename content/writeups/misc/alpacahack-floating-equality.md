---
title: "Floating Equality - AlpacaHack Daily"
category: "misc"
subcategory: "misc"
type: "writeup"
tags: ["misc", "alpacahack", "regex", "floating", "equality", "miscellaneous"]
summary: "misc writeup for \"Floating Equality\" from AlpacaHack Daily - techniques: alpacahack, regex, floating, equality, miscellaneous."
source:
  name: "baumroll0928-spec/myRepository"
  url: "https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202606/d12_Floating_Equality/README.md"
ctf:
  name: "AlpacaHack Daily"
  year: 2026
  challenge: "Floating Equality"
---

## Source

- **CTF:** AlpacaHack Daily
- **Challenge:** Floating Equality
- **Date:** 2026-06-12
- **Repository:** [baumroll0928-spec/myRepository](https://github.com/baumroll0928-spec/myRepository)
- **Directory:** <https://github.com/baumroll0928-spec/myRepository/tree/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202606/d12_Floating_Equality>
- **File:** <https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202606/d12_Floating_Equality/README.md>

---
# Floating Equality

## 問題

浮動小数点型の比較には `==` の代わりに `EPS` を用いなさいという人もいますが…

```py
EPS = 1e-10
FLAG = os.environ.get("FLAG", "Alpaca{dummy}")


def validated_input(prompt: str) -> str:
    res = input(prompt)
    assert len(res) <= 16
    assert re.fullmatch(r"(?:0|[1-9][0-9]*)\.[0-9]{1,9}", res)
    return res


x_str = validated_input("value> ")
x = float(x_str)

xe9 = float(f"{x_str}e9")
x_1e9 = x * 1e9
err = abs(xe9 - x_1e9)

print(f"{xe9 = :.100g}")
print(f"{x_1e9 = :.100g}")
print(f"{err = :.100g}")

try:
    assert err < EPS
except AssertionError:
    print(f"FLAG: {FLAG}")
```

## 概要

最初に、全体で16文字以下かつ小数点以下が1～9桁の小数を表す文字列の入力を求められます。

その後、

* 入力文字列の右に"e9"を付けてからfloatにキャストした値
* floatにキャストしてから $`10^{9}`$ 倍した値

を比較し、誤差が`EPS` = $`10^{-10}`$ 以上の場合、`assert err < EPS`でAssertionErrorが発生しフラグをゲットできます。

普通に考えたら、"e9"をつけても $`10^{9}`$ 倍しても同じように思えますが、どんな小数を入力したら`EPS`以上の誤差が出るのでしょうか？

## 結論

例えば、$`99999999999999.8`$ を入力します。(9は14個)

```
value> 99999999999999.8
xe9 = 99999999999999807062016
x_1e9 = 99999999999999790284800
err = 16777216
FLAG: Alpaca{dummy}
```

`EPS` = $`10^{-10}`$どころではなくかなり大きい誤差がでています。

## 説明

Pythonのfloat型の仕様はIEEE754の倍精度浮動小数点の規格に準拠しています。

ここでIEEE754について少しだけおさらいしましょう。

倍精度浮動小数点では小数を64ビットで記録しますが、その内訳は、
```
符号部(1) | 指数部(11) | 仮数部(52)
```
であり、

$`(-1)^{符号部}×(1.仮数部)×2^{指数部-1023}`$

の形になるんでしたよね。

とりあえず、仮数部が52ビットであることだけは覚えておきましょう。

さて、十進数の $`99999999999999.8`$ をそのまま二進数に変換すると、

$`10110101111001100010000011110100011111111111111.110011001100110011001100...`$

のように無限に続くビット列になります。

※参考までに、私がビット列の調査に使ったコードは[こんな感じ](https://raw.githubusercontent.com/baumroll0928-spec/myRepository/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202606/d12_Floating_Equality/show_bits.py)です。

しかし、（頭の1を除いて）52ビットしか保持できないので、

$`1.0110101111001100010000011110100011111111111111110011 × 2^{-46}`$

という形に丸められます。これは十進数で表すと、

$`99999999999999.796875`$

になります。

これを $`10^{9}`$ 倍すると、

$`99999999999999796875000`$

になりますが、これを二進数に変換すると、

$`10101001011010000001011000111111000010100101011101010011001001000111011111000`$

となるので、ここでもさらに丸めが発生し、

$`1.0101001011010000001011000111111000010100101011101010 × 2^{76}`$

になります。

一方、$`99999999999999.8`$に"e9"を付けた$`99999999999999.8e9`$は、

$`99999999999999800000000`$

のように最初から整数として扱われ、これを二進数に変換すると、

$`10101001011010000001011000111111000010100101011101010100101000011111000000000`$

となるので、

$`1.0101001011010000001011000111111000010100101011101011 × 2^{76}`$

に丸められます。（切り上げが発生することに注意！）

先ほどの値と比較すると、最下位ビットだけが違うことがわかります。

仮数部のスケールで見るとたったの $`2^{-52}`$ の違いですが、指数部も加味するとこの差は $`2^{24} = 16777216`$ まで膨れ上がることになります。

小数から始めた場合は余分な丸めが発生したため、このような差が出たというわけですね。

さて、実はこの$`99999999999999.8`$というのは論理的に導いたわけではなく、いろいろ試していてたまたま見つけた値でした。

最初$`99999999999999.9`$で試したときはダメでしたが、なぜ0.1違うだけで結果が変わるのでしょうか？

$`10110101111001100010000011110100011111111111111.111001100110011001100110...`$

から、

$`1.0110101111001100010000011110100011111111111111111010 × 2^{-46}`$


$`99999999999999.90625`$

となり、

$`99999999999999906250000`$

$`10101001011010000001011000111111000010100101011110000111010010111110100010000`$

$`10101001011010000001011000111111000010100101011110001 × 2^{-46}`$

となります。

一方、

$`99999999999999900000000`$

$`10101001011010000001011000111111000010100101011110000100010100001111100000000`$

$`10101001011010000001011000111111000010100101011110001 × 2^{-46}`$

となるので、上位53ビットの範囲で一致してしまっていることがわかりました。

## Solver

### `show_bits.py`

<https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202606/d12_Floating_Equality/show_bits.py>

```python
def bits(x_str:str)->str:
    dot_pos = x_str.find(".")
    if dot_pos < 0:
        i = x_str
        f = "0"
    else:
        i = x_str[:dot_pos]
        f = x_str[dot_pos + 1:]
    s = f"{int(i):b}."
    m = 24
    n = int(f.ljust(m, "0"))
    base = pow(10, m)
    for _ in range(m):
        n *= 2
        s += str(n // base)
        n %= base
    return s

x = bits("3.14")
print(x)
di = x.find(".")
print("digits of integer:", di)
```
