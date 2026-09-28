---
title: "integer division - AlpacaHack Daily"
category: "misc"
subcategory: "integer"
type: "writeup"
tags: ["misc", "alpacahack", "integer-overflow", "scanf", "subprocess", "integer-division"]
summary: "misc writeup for \"integer division\" from AlpacaHack Daily - techniques: alpacahack, integer-overflow, scanf, subprocess, integer-division."
source:
  name: "baumroll0928-spec/myRepository"
  url: "https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202609/d14-15_integer_division/README.md"
ctf:
  name: "AlpacaHack Daily"
  year: 2026
  challenge: "integer division"
---

## Source

- **CTF:** AlpacaHack Daily
- **Challenge:** integer division
- **Date:** 2026-09-14-15
- **Repository:** [baumroll0928-spec/myRepository](https://github.com/baumroll0928-spec/myRepository)
- **Directory:** <https://github.com/baumroll0928-spec/myRepository/tree/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202609/d14-15_integer_division>
- **File:** <https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202609/d14-15_integer_division/README.md>

---
# integer division

出題期間内に間に合わなかったうえにちょいズルです。

## 問題

整数除算では、0除算にだけ気をつければ大丈夫ですよね？

### chal.c
```c
int main(void) {
    int x, y;
    printf("x> ");
    fflush(stdout);
    scanf("%d", &x);
    printf("y> ");
    fflush(stdout);
    scanf("%d", &y);

    if (y == 0) {
        puts("Division by zero is prohibited.");
    }
    else {
        int result = x / y;
        printf("result: %d\n", result);
    }

    return 0;
}
```
### server.py
```py
completed_process = subprocess.run(["./chal"])
if completed_process.returncode != 0:
    print("[server.py] Unbelievable! FLAG: Alpaca{REDACTED}")
else:
    print("[server.py] This is an expected behavior.")
```

## 概要

C言語のコードは、int型の整数`x`と`y`を入力して割り算の商`x / y`を計算し結果を出力するプログラムのようです。

これをPythonのコードから実行し、リターンコードが`0`でない、すなわち正常終了しなかった場合はフラグを表示してくれるようになっています。

ゼロ除算エラーが起こる`y == 0`のケースはきっちり弾かれてしまいますが、どうすればエラーを発生させられるのでしょうか？

## 方針

ゼロ除算のエラーではなく割り算のオーバーフロー（！？）のエラーを発生させる。

## 解法

server.pyはゼロ除算エラーを起こせとは言っていません。どんなエラーでも起こせれば勝ちです。

scanfのところで何らかのエラーを起こせないかいろいろ試してみましたが、私は見つけられませんでした。

そこで、ふと問題のTopicを見てみると、「Integer Overflow」となっているのに気づきました。

割り算なのにオーバーフロー？そんなことがあるんでしょうか？

そういえば、int型の範囲ってプラスとマイナスで1つ違ったような・・・

はい、int型（32ビット符号付整数）の範囲は $`-2^{-31}～2^{31}-1`$ すなわち `-2147483648`～`2147483647`です。

※余談ですが、int型がshort型（16ビット）かlong型（32ビット）かは実装依存らしいですね。

`0`には`+0`と`-0`が無いので有効な範囲をきっちり二つに分けることができず、プラスの範囲とマイナスの範囲に1つズレがあるのですね。

ということは、最小値の`-2147483648`の符号をひっくり返したら、最大値を飛び越えてオーバーフローが起こるのではないでしょうか？

```
$ nc localhost 1337
x> -2147483648
y> -1
[server.py] Unbelievable! FLAG: Alpaca{REDACTED}
```

というわけで、ちょいズル気味だけどフラグを得ることができました。

## 補足

しかし、足し算や引き算、掛け算ではオーバーフローしてもエラーにならないのに、割り算だけエラーになるのは不思議ですよね。

調べてみると、`INT_MAX + 1`も`INT_MIN * -1`も`INT_MIN / -1`もC言語の規格としては全て「未定義の動作（Undefined Behavior: UB）」のようです。

さらに不思議なのが、chalを直接実行してみると、

```
$ ./chal
x> -2147483648
y> -1
浮動小数点例外 (コアダンプ)
```

整数なのに浮動小数点例外が出るようです。
