---
title: "Lets analyze system calls - AlpacaHack Daily"
category: "pwn"
subcategory: "static-analysis"
type: "writeup"
tags: ["pwn", "alpacahack", "scanf", "objdump", "lets", "analyze", "system", "calls"]
summary: "pwn writeup for \"Lets analyze system calls\" from AlpacaHack Daily - techniques: alpacahack, scanf, objdump, lets, analyze, system, calls."
source:
  name: "baumroll0928-spec/myRepository"
  url: "https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202608/d27-28_Lets_analyze_system_calls/README.md"
ctf:
  name: "AlpacaHack Daily"
  year: 2026
  challenge: "Lets analyze system calls"
---

## Source

- **CTF:** AlpacaHack Daily
- **Challenge:** Lets analyze system calls
- **Date:** 2026-08-27-28
- **Repository:** [baumroll0928-spec/myRepository](https://github.com/baumroll0928-spec/myRepository)
- **Directory:** <https://github.com/baumroll0928-spec/myRepository/tree/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202608/d27-28_Lets_analyze_system_calls>
- **File:** <https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202608/d27-28_Lets_analyze_system_calls/README.md>

---
# Let's analyze system calls

最近難しすぎて解けません。誰かWriteup書いてくれないかな～？（他人任せ）

## 問題

x86-64版Linuxのシステムコールを解析してみましょう！

```c
#include <stdio.h>
#include <stdlib.h>

int main() {
    unsigned long result_1, result_2, sum, input;

    asm("syscall"
        : /* No outputs. */
        : "a"(318), "D"(&result_1), "S"(sizeof(result_1)), "d"(0)
        : "rcx", "r11", "memory");

    asm("syscall"
        : "=a"(result_2)
        : "a"(102)
        : "rcx", "r11");

    sum = result_1 + result_2;

    printf("result_1: %lu\n", result_1);
    printf("What will be the sum? ");
    fflush(stdout);
    scanf("%lu", &input);

    if (input == sum) {
        const char *env_flag = getenv("FLAG");
        printf("Correct! FLAG: %s\n", env_flag ? env_flag : "Alpaca{DUMMY}");
    }
    else {
        puts("Incorrect...");
    }
}
```

## 概要

実行すると、`result_1`の値が表示され、`sum`の入力を求められます。

そして、入力した`sum`の値が`result_1 + result_2`と等しい場合はフラグを得ることができるようです。

この`result_2`には何が入るのでしょうか？

## 解法

### フラグ取得

まずはズルしてフラグを取ってみました。全然わからないときはズルすることも必要でしょう（？）

C言語のソースコードの`result_1`を出力する部分で、ついでに`result_2`と`sum`も出力するようにしてみます。
```c
    printf("result_1: %lu\n", result_1);
    printf("result_2: %lu\n", result_2); // ADD
    printf("sum: %lu\n", sum);           // ADD
    printf("What will be the sum? ");
```

今回の問題ではメモリ番地などは特に関係なさそうなので、いつもの`-no-pie`などのオプションはつけずにコンパイルします。
```
gcc -o chal chal.c
```

ローカルのDockerで実行してみると、下記のようになりました。
```
$ nc localhost 1337
result_1: 8141263141696778809
result_2: 404
sum: 8141263141696779213
What will be the sum? 8141263141696779213
Correct! FLAG: Alpaca{REDACTED}
```

何度か実行してみると、`result_1`は毎回変わるものの、`result_2`については毎回同じ値でした。

この`404`って何でしょうか？

Dockerfileを見てみると、次のような見慣れない記述がありました。
```
# Sets UID and GID
USER 404:404
```
このどっちかの`404`をとっているのかもしれないので、これを
```
# Sets UID and GID
USER 405:406
```
に書き換えて実行してみると、
```
result_1: 3190819722784802507
result_2: 405
sum: 3190819722784802912
```
のようになり、`UID`の方であることがわかりました。

```py
import pwn

HOST, PORT = "localhost", 1337
# HOST, PORT = "34.170.146.252", 19291
p = pwn.remote(HOST, PORT)

d = p.recvuntil(b'sum? ')
res1 = int(d.decode().split()[1])
res2 = 404
s = res1 + res2
p.sendline(str(s).encode())
print(p.recvline().decode())
```

### 攻略

順序が逆になってしまいましたが、なぜこれでいいのか考えてみます。

前提として、`result_1`については提示される数（おそらく64ビットの乱数）なので、`result_2`の方だけ考えれば良さそうです。

そうすると、関係ありそうなのはここでしょうか。
```c
    asm("syscall"
        : "=a"(result_2)
        : "a"(102)
        : "rcx", "r11");
```
asm関数について調べてみると、
```
asm(アセンブリ命令 : 出力オペランド : 入力オペランド : 破壊リスト)
```
のようになっているようです。

アセンブリ命令は、実行したいコードを文字列で指定します。ここでは`syscall`がこれにあたります。

出力オペランドは、実行後に結果を入れる変数を指定します。ここでは`result_2`が指定されています。（`a`は`rax`を意味します。）

入力オペランドは、実行前にレジスタに入れる値を指定します。ここでは`102`を入れています。

破壊リストは、内部で使用するレジスタを指定しコンパイラに伝えます。`syscall`の場合は`rcx`と`r11`が使用されるようです。

これをふまえて、`objdump -d`でアセンブリ化して該当する部分を見てみると、
```
    1219:	b8 66 00 00 00       	mov    $0x66,%eax
    121e:	0f 05                	syscall
    1220:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
```
のように、レジストリに`0x66(=102)`をセットして`syscall`を実行した後、戻り値`rax`を変数`result_2`に写していることがわかりました。

さて、システムコールに番号`102`が渡されると何が行われるのでしょうか？

```
$ ausyscall --dump
```
を実行するとシステムコールの番号の一覧が取得できるようなので、`grep`で絞ってみると、
```
$ ausyscall --dump | grep 102
102     getuid
```
`102`は`getuid`であることがわかりました。

ここまでをまとめると、
```c
    asm("syscall"
        : "=a"(result_2)
        : "a"(102)
        : "rcx", "r11");
```
は、「uidを取得してその結果を`result_2`変数に格納する」という処理を行うことがわかります。

この問題では`result_1`と`result_2 = uid = 404`の合計をきかれているので、この合計値を答えればフラグを得ることができます。
