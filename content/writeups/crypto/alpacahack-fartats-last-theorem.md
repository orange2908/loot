---
title: "Fartats Last Theorem - AlpacaHack Daily"
category: "crypto"
subcategory: "rsa"
type: "writeup"
tags: ["crypto", "alpacahack", "rsa", "subprocess", "fartats", "last", "theorem"]
summary: "crypto writeup for \"Fartats Last Theorem\" from AlpacaHack Daily - techniques: alpacahack, rsa, subprocess, fartats, last, theorem."
source:
  name: "baumroll0928-spec/myRepository"
  url: "https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202608/d11-12_Fartats_Last_Theorem/README.md"
ctf:
  name: "AlpacaHack Daily"
  year: 2026
  challenge: "Fartats Last Theorem"
---

## Source

- **CTF:** AlpacaHack Daily
- **Challenge:** Fartats Last Theorem
- **Date:** 2026-08-11-12
- **Repository:** [baumroll0928-spec/myRepository](https://github.com/baumroll0928-spec/myRepository)
- **Directory:** <https://github.com/baumroll0928-spec/myRepository/tree/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202608/d11-12_Fartats_Last_Theorem>
- **File:** <https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202608/d11-12_Fartats_Last_Theorem/README.md>

---
# Fartat's Last Theorem

## はじめに

C言語のマクロ関数を使った今回の問題は、以前から漠然としたアイデアはあったのですが、どうやって実現すればいいかわからず、しばらく温めていました。

## 問題

フェルマーの最終定理によると、3以上の整数$`N`$について、$`A^{N} + B^{N} = C^{N}`$を満たす正整数$`(A, B, C)`$の組は存在しません。

```py
FLAG = os.environ.get("FLAG", "Alpaca{dummy}")

def sanitize(txt:str):
    txt = re.sub(r'[^-0-9]', '', txt)
    return txt[:3]

a = sanitize(input("A> "))
b = sanitize(input("B> "))
c = sanitize(input("C> "))

code = """#include <stdio.h>
#define CUBE(x) (x * x * x)

int main(void)
{
    setbuf(stdin,  NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    if ("""+a+""" <= 0 || """+b+""" <= 0 || """+c+""" <= 0) {
        printf("Invalid.\\n");
    }
    else if (CUBE("""+a+""") + CUBE("""+b+""") == CUBE("""+c+""")) {
        printf("Seriously? Flag: """+FLAG+"""\\n");
    }
    else {
        printf("Expected.\\n");
    }

    return 0;
}
"""

open("/app/work/chall.c", "w").write(code)

try:
    subprocess.run(["gcc", "-o", "/app/work/chall", "/app/work/chall.c"], check=True)
    subprocess.run(["/app/work/chall"])
except:
    pass
```

## 概要

実行すると、`A`,`B`,`C`の入力を求められますが、これらの入力は`-0123456789`以外の文字が全て削除されたうえで、さらに4文字以上の場合は最初の3文字に切り捨てられます。

その後、入力された`A`,`B`,`C`は、C言語のソースコードに組み込まれてファイルに保存され、コンパイル、実行されます。

このとき、$`A, B, C \ge 1`$かつ$`A^{3} + B^{3} = C^{3}`$を満たしていればフラグを得ることができるようですが、フェルマーの最終定理によると、このような`A`,`B`,`C`は存在しないはずです。

各整数の最大値は999なので、オーバーフローを狙うこともできそうにありません。

この状況でどうすればフラグを得ることができるのでしょうか？

## 方針

C言語のマクロ関数の性質と演算子の優先順位の違いを利用して等式を成立させる。

## 解法

C言語のマクロ関数は普通の関数とは違い、コンパイルの下準備としてプリプロセッサの段階で単純に文字列の置換が行われます。

例えば、
```c
#define CUBE(x) (x * x * x)
```
のとき、
```c
CUBE(2-1)
```
は
```c
(1 * 1 * 1)
```
ではなく
```c
(2-1 * 2-1 * 2-1)
```
に展開されますが、C言語をはじめとする多くの言語では減算演算子`-`より乗算演算子`*`の方が計算の優先順位が高いので、
```c
(2 - (1*2) - (1*2) - 1)
```
と解釈され、$`1^{3}`$の`1`ではなく、`-3`になってしまいます。

これをなんとか利用して等式を成立させられないでしょうか？

いろいろな組み合わせが考えられますが、私が考えた一番簡単な組み合わせは、
```
A> 1
B> 1
C> 2-0 # (2 - 0*2 - 0*2 - 0) == 2
```
かなと思います。

```py
from pwn import remote

HOST, PORT = "localhost", 1337
p = remote(HOST, PORT)

p.sendlineafter(b'A> ', b'1')
p.sendlineafter(b'B> ', b'1')
p.sendlineafter(b'C> ', b'2-0')

print(p.recvall().decode())
```

ちなみに、`0`を使わない縛りでもできるでしょうか？興味ある方はちょっと考えてみてください。

<details>
<summary>0を使わない解答例</summary>

<pre>A> 1
B> 3-1 # -4
C> 2-1 # -3</pre>

</details>

## おわりに

今回は数学の問題とみせかけてそうでないヒッカケ問題を作ってみました。

このような現象は、攻撃によってではなく単なる実装ミスによって起こることも多いのかなと思っています。

正しくは、
```c
#define CUBE(x) ((x) * (x) * (x))
```
のように引数そのものをカッコで囲むべきですよね。

※引数をカッコで囲んだからといって全体のカッコを外すことはできません。`24/CUBE(2)`が`3`ではなく`48`になってしまいます。

また、`CUBE(x++)`のように副作用をともなう式を引数に使うのは想定外の動作を起こすことから避けるべきでしょう。

さて、「フェルマーの最終定理」といえば、ピエール・ド・フェルマー(1607-1665)が、「私は真に驚くべき証明を見つけたが、この余白はそれを書くには狭すぎる。」と記したことで、後の数学者たちを300年以上ものあいだ悩ませたというエピソードは、数学好きの方なら誰もが聞いたことがあるかと思います。

ただ、フェルマー自身が本当に証明できていたかどうかは結局わかっておらず、記録として残っているのはN=4の場合のみのようですね。

CTFに関係するところだと、「素数`p`と`p`の倍数でない整数`a`について$`a^{p-1} \equiv 1 \pmod{p}`$が成立する」とする「フェルマーの小定理」や、RSAでpとqが極めて近い場合の攻撃手法「Fermat Attack」あたりになるかと思います。

しかし、彼の本業は数学者ではなく法律家であり、数学の研究は趣味でやっていたというのだからさらにビックリです。天才というやつはよくわかりませんよね。
