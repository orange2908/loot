---
title: "Lets Shut Down Linux - AlpacaHack Daily"
category: "crypto"
subcategory: "hash"
type: "writeup"
tags: ["crypto", "alpacahack", "birthday-attack", "lets", "shut", "down", "linux"]
summary: "crypto writeup for \"Lets Shut Down Linux\" from AlpacaHack Daily - techniques: alpacahack, birthday-attack, lets, shut, down, linux."
source:
  name: "baumroll0928-spec/myRepository"
  url: "https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202609/d03-04_Lets_Shut_Down_Linux/README.md"
ctf:
  name: "AlpacaHack Daily"
  year: 2026
  challenge: "Lets Shut Down Linux"
---

## Source

- **CTF:** AlpacaHack Daily
- **Challenge:** Lets Shut Down Linux
- **Date:** 2026-09-03-04
- **Repository:** [baumroll0928-spec/myRepository](https://github.com/baumroll0928-spec/myRepository)
- **Directory:** <https://github.com/baumroll0928-spec/myRepository/tree/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202609/d03-04_Lets_Shut_Down_Linux>
- **File:** <https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202609/d03-04_Lets_Shut_Down_Linux/README.md>

---
# Let's Shut Down Linux

## 問題

`reboot`システムコールに3個の引数を指定して、Linuxをシャットダウンしましょう！

```c
  my_write("arg1: ");
  uint32_t arg1 = my_read_uint32();
  my_write("arg2: ");
  uint32_t arg2 = my_read_uint32();
  my_write("arg3: ");
  uint32_t arg3 = my_read_uint32();
  my_write("Running a reboot system call!\n");
  my_syscall_4(SYS_reboot, arg1, arg2, arg3, (uint64_t)"A constant string");
  my_fatal("Failed to shut down. Kernel panic will occur...\n");
```

## 概要

3つのユーザー入力`arg1`、`arg2`、`arg3`を使ってシステムコールを実行してくれるようです。

`SYS_reboot`は`sys/syscall.h`で定義されているrebootを意味するシステムコールの番号`169`です。

```c
#include <stdio.h>
#include <sys/syscall.h>
int main(void)
{
    printf("SYS_reboot: %d\n", SYS_reboot); // SYS_reboot: 169
    return 0;
}
```

```
$ ausyscall --dump | grep 169
169     reboot
```

これによってLinuxをシャットダウンできればよさそうですが、`arg1`、`arg2`、`arg3`にそれぞれ何を指定すればいいのでしょうか？

## 解法

全く見当がつかないので、とりあえず
```
C言語 asm関数 システムコール linux シャットダウン
```
でWeb検索してみました。

すると、解説サイトなどは見つけられませんでしたが、AIモードで次の解答を得ることができました。

```
arg1: 0xfee1dead = 4276215469
arg2: 0x28121969 = 672274793
arg3: 0x4321fedc = 1126301404
```

なぜこのようなマジックナンバーが必要なのかというと、システムを破壊しかねないシャットダウンや再起動がプログラムのバグや実装ミスなどによって暴発しないようにするためのしかけのようです。

また、これらの数字にはLinuxの開発者リーナス・トーバルズ氏の遊び心が込められています。

0xfee1dead: FEEL DEAD(死にそう)をシステムの停止・再起動に掛けたもの。

0x28121969: リーナス・トーバルズ氏の誕生日(1969/12/28)から。（他にも彼の長女(0x05121996)、次女(0x16001998)、三女(0x20112000)の誕生日でも良いようです。）

0x4321fedc: カウントダウンを表す。

さっそく実行してみます。
```
$ nc 34.170.146.252 35059
Core dump limits :
        soft - NONE
        hard - NONE
（略）
Specify arg1, arg2, and arg3 in decimal to be used in the reboot system call to shut down Linux.
arg1: 4276215469
4276215469
arg2: 672274793
672274793
arg3: 1126301404
1126301404
Running a reboot system call!
reboot: Power down

[server.py] p.returncode = 0
[server.py] Linux has been shut down properly! FLAG: Alpaca{*********************************************************************}
```
無事フラグをゲットすることができました。

フラグの中では、`arg2`にあたる`MAGIC2`について言及されていましたね。
