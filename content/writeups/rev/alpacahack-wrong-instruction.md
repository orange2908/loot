---
title: "wrong instruction - AlpacaHack Daily"
category: "rev"
subcategory: "static-analysis"
type: "writeup"
tags: ["rev", "alpacahack", "xor", "pie", "ghidra", "obfuscation", "lsb", "scanf", "objdump"]
summary: "rev writeup for \"wrong instruction\" from AlpacaHack Daily - techniques: alpacahack, xor, pie, ghidra, obfuscation, lsb, scanf, objdump."
source:
  name: "baumroll0928-spec/myRepository"
  url: "https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202608/d18-20_wrong_instruction/README.md"
ctf:
  name: "AlpacaHack Daily"
  year: 2026
  challenge: "wrong instruction"
---

## Source

- **CTF:** AlpacaHack Daily
- **Challenge:** wrong instruction
- **Date:** 2026-08-18-20
- **Repository:** [baumroll0928-spec/myRepository](https://github.com/baumroll0928-spec/myRepository)
- **Directory:** <https://github.com/baumroll0928-spec/myRepository/tree/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202608/d18-20_wrong_instruction>
- **File:** <https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202608/d18-20_wrong_instruction/README.md>

---
# wrong instruction

久しぶりにアセンブリをガッツリ読んだ気がします。

## 問題

フラグ検証処理を解析する必要があります……あれ？

配付ファイル: wrong-instruction

## 概要

配付ファイルはLinuxの実行形式ファイルです。
```
$ file wrong-instruction
wrong-instruction: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=0789381558577a57a8478ad7eb600774b85574a5, for GNU/Linux 3.2.0, not stripped
```

しかし、Ghidraで解析してみると、is_correct関数がおかしなことになってしまいます。

どうすればフラグを得ることができるのでしょうか？

## 解法

まずは配付ファイルをGhidraに食べさせて、`main`関数から見ていきます。

※主要部分のみ抜粋、変数リネーム済み。

```c
  printf("Input > ");
  __isoc23_scanf(&DAT_00102065,input_flag);
  len_input = strlen(input_flag);
  if (len_input == 0x3c) {
    result = is_correct(input_flag,encoded,0x3c);
    if (result == 0) {
      ok = true;
      goto LAB_00101296;
    }
  }
  ok = false;
LAB_00101296:
  if (!ok) {
    puts("Incorrect...");
  }
  else {
    printf("Correct! The flag is %s\n",input_flag);
  }
```

いわゆる「フラグチェッカー」というやつですね。

ユーザーに入力を求め、入力の長さが`0x3c(=60)`バイトであれば、is_correct関数に入力とencodedと`0x3c(=60)`を渡して実行します。

そして、is_correct関数が返す値が`0`の場合は「Correct!」が表示され、そうでない場合やそもそも長さが`60`でない場合は「Incorrect...」が表示されます。

encodedはバイナリファイルの0x2020の位置から始まる部分で、バイナリエディタで見ると
```
78 AB B7 B0 BA C0 E2 C3 DF E4 FA F4 F6 0C 0C 23 1F 2E 2B 42 36 40 59 54 56 62 68 7B 83 84 8B 8E 98 AD BB B8 84 C3 D0 E2 D8 F2 FA F4 04 01 13 28 16 33 2C 32 3F 4D 50 60 6C 64 7A 8C
```
のようなデータであることがわかります。

このis_correct関数がフラグの正誤判定の核心のようですが、解析結果が
```c
  (*(code *)&LAB_00101204)();
```
のようになっています。全然意味が分かりません。

問題のトピックがObfuscation（=難読化）であることから、容易に逆コンパイルできないように何らかの仕掛けが施されているのでしょう。

というわけで、アセンブリを読んでみることにします。
```
$ objdump -d wrong_instruction > asm.txt
```
すると、is_correct関数の部分はこんな感じでした。
```
00000000000011c9 <is_correct>:
    11c9:	f3 0f 1e fa          	endbr64
    11cd:	48 8d 05 30 00 00 00 	lea    0x30(%rip),%rax        # 1204 <is_correct+0x3b>
    11d4:	eb ff                	jmp    11d5 <is_correct+0xc>
    11d6:	d0 0f                	rorb   $1,(%rdi)
    11d8:	0b c3                	or     %ebx,%eax
    11da:	81 c1 4d 31 d2 49    	add    $0x49d2314d,%ecx
    11e0:	89 d3                	mov    %edx,%ebx
    11e2:	4a 0f b6 0c 17       	movzbq (%rdi,%r10,1),%rcx
    11e7:	4a 0f b6 14 16       	movzbq (%rsi,%r10,1),%rdx
    11ec:	74 04                	je     11f2 <is_correct+0x29>
    11ee:	75 02                	jne    11f2 <is_correct+0x29>
    11f0:	48 b9 42 8d 4c d1 37 	movabs $0x8d12837d14c8d42,%rcx
    11f7:	28 d1 08 
    11fa:	c8 49 ff c2          	enter  $0xff49,$0xc2
    11fe:	4d 39 da             	cmp    %r11,%r10
    1201:	7c df                	jl     11e2 <is_correct+0x19>
    1203:	c3                   	ret
    1204:	48 83 04 24 05       	addq   $0x5,(%rsp)
    1209:	31 c0                	xor    %eax,%eax
    120b:	c3                   	ret
    120c:	90                   	nop
    120d:	0f 0b                	ud2
```
いきなりすごく気になるところがありますね。
```
    11d4:	eb ff                	jmp    11d5 <is_correct+0xc>
    11d6:	d0 0f                	rorb   $1,(%rdi)
```
`0x11d4`のjmp命令で、自身の命令の途中に飛んでいます。

これによって命令の解釈が変わり、`ff d0`で始まる命令が実行されることになります。

この命令は何でしょうか？また区切りはどこまででしょうか？

アセンブリの命令の仕様を調べても良いですが、もっと楽な方法はないでしょうか？

結論からいうと、バイナリエディタで`11d4:	eb ff`の`eb`を`90`(nop=何もしない命令)に書き換えます。

どうせ1バイト進むのだから何もしないでそのまま進めてしまえばいいし、これなら命令の区切りを正しく解釈できるだろうという考えです。

書き換えたら再度アセンブリ化してみます。
```
00000000000011c9 <is_correct>:
    11c9:	f3 0f 1e fa          	endbr64
    11cd:	48 8d 05 30 00 00 00 	lea    0x30(%rip),%rax        # 1204 <is_correct+0x3b>
    11d4:	90                   	nop
    11d5:	ff d0                	call   *%rax
    11d7:	0f 0b                	ud2
    ...
    1204:	48 83 04 24 05       	addq   $0x5,(%rsp)
    1209:	31 c0                	xor    %eax,%eax
    120b:	c3                   	ret
    ...
```
狙い通り命令の解釈が変わりました。

そうすると、正しく逆コンパイルできなかった理由も説明がつきそうです。

Ghidraで解析するときは、頭から素直に１命令ずつ解釈していくので、実際に実行するときの命令の解釈との間にズレが発生してしまうわけですね。

しかし、正しい解釈に修正されたように見えるとはいえ、よく見るといろいろ不思議なことをしているようなので、慎重に読み進めていくことにします。

まず、
```
    11cd:	48 8d 05 30 00 00 00 	lea    0x30(%rip),%rax        # 1204 <is_correct+0x3b>
```
で、`0x30`に次の命令ポインタ`0x11d4`を加算した`0x1204`をレジスタ`%rax`に入れています。

次に、
```
    11d5:	ff d0                	call   *%rax
```
で、`%rax = 0x1204`の場所に関数呼び出しのように飛びます。

飛んだ先では、
```
    1204:	48 83 04 24 05       	addq   $0x5,(%rsp)
```
で、戻り先アドレスが入っているスタックポインタの場所に`5`を加算し、
```
    1209:	31 c0                	xor    %eax,%eax
    120b:	c3                   	ret
```
で`return 0;`して戻ります。

このとき、戻り先アドレスに`5`が加算されているので、本来の戻り先`0x11d7`ではなく`0x11dc`に戻ることになります。
```
    11d5:	ff d0                	call   *%rax
    11d7:	0f 0b                	ud2
    11d9:	c3                   	ret
    11da:	81 c1 4d 31 d2 49    	add    $0x49d2314d,%ecx
```
この`0x11dc`も命令の途中です。

なので、スキップされる`0x11d7`～`0x11db`の5バイトも全てnopで潰してしまいましょう。

するとこうなりました。（nopの部分は省略します）
```
    11d5:	ff d0                	call   *%rax
    11dc:	4d 31 d2             	xor    %r10,%r10
    11df:	49 89 d3             	mov    %rdx,%r11
    11e2:	4a 0f b6 0c 17       	movzbq (%rdi,%r10,1),%rcx
    11e7:	4a 0f b6 14 16       	movzbq (%rsi,%r10,1),%rdx
    11ec:	74 04                	je     11f2 <is_correct+0x29>
    11ee:	75 02                	jne    11f2 <is_correct+0x29>
    11f0:	48 b9 42 8d 4c d1 37 	movabs $0x8d12837d14c8d42,%rcx
```
引き続き読み進めてみます。
```
    11dc:	4d 31 d2             	xor    %r10,%r10
    11df:	49 89 d3             	mov    %rdx,%r11
```
で、`%r10`を`0`にクリアし、`%11`にis_correct関数の第３引数の`60`をセットします。

あとでわかりますが、これはループの初期化の部分で、`%r10`はループカウンタ、`%r11`は終了値です。

```
    11e2:	4a 0f b6 0c 17       	movzbq (%rdi,%r10,1),%rcx
```
は、`%rdi + %r10 × 1`のアドレスにあるメモリの値を`%rcx`にセットします。

`%rdi`はis_correct関数の第１引数なので、`%rcx`には入力したフラグの`%r10`番目の文字が入ります。

同様に
```
    11e7:	4a 0f b6 14 16       	movzbq (%rsi,%r10,1),%rdx
```
は、encodedの`%r10`番目の文字を`%rdx`にセットします。

その次に、なにやら奇妙な命令がありますね。
```
    11ec:	74 04                	je     11f2 <is_correct+0x29>
    11ee:	75 02                	jne    11f2 <is_correct+0x29>
```
によって、直前の演算結果`ZF`が`1`でも`0`でも`0x11f2`に飛ぶことになります。

この`0x11f2`は、
```
    11f0:	48 b9 42 8d 4c d1 37 	movabs $0x8d12837d14c8d42,%rcx
```
また命令の途中です。

であれば、この無駄なジャンプも含めて`0x11ec`～`0x11f1`の6バイトを全てnopで潰してしまいます。
```
    11dc:	4d 31 d2             	xor    %r10,%r10
    11df:	49 89 d3             	mov    %rdx,%r11
    11e2:	4a 0f b6 0c 17       	movzbq (%rdi,%r10,1),%rcx
    11e7:	4a 0f b6 14 16       	movzbq (%rsi,%r10,1),%rdx
    11f2:	42 8d 4c d1 37       	lea    0x37(%rcx,%r10,8),%ecx
    11f7:	28 d1                	sub    %dl,%cl
    11f9:	08 c8                	or     %cl,%al
    11fb:	49 ff c2             	inc    %r10
    11fe:	4d 39 da             	cmp    %r11,%r10
    1201:	7c df                	jl     11e2 <is_correct+0x19>
```

だいぶスッキリしてまいりました。

```
    11f2:	42 8d 4c d1 37       	lea    0x37(%rcx,%r10,8),%ecx
```
は、`0x37 + %rcx + %r10 × 8`を計算して、入力の文字を変換します。

```
    11f7:	28 d1                	sub    %dl,%cl
```
は、変換した入力の文字からencodedの文字を引いて差分を求めます。

※`%cl`は`%rcx`の下位8ビットなので、実質$`\pmod{256}`$での計算になります。

```
    11f9:	08 c8                	or     %cl,%al
```
は、`%al`にビットORで差分`%cl`を加算します。

これによって、全ての差分`%cl`が蓄積され、1つでも`0`でないものがあると、二度と`0`に戻ることはありません。

※`%al`の初期化しているところが見当たらないと思いましたが、
```
    1209:	31 c0                	xor    %eax,%eax
```
で`0`を返したときの値が引き継がれるのですね。

その後、
```
    11fb:	49 ff c2             	inc    %r10
    11fe:	4d 39 da             	cmp    %r11,%r10
    1201:	7c df                	jl     11e2 <is_correct+0x19>
```
で、ループカウンタをインクリメント（1つ増やすこと）し、終了値と比較して、終了値に達していなければループの頭に戻ります。

以上のことをまとめると、is_correct関数では概ね下記の処理をしていることがわかります。

```c
int is_correct(char *input_flag, unsigned char *encoded, long len)
{
    unsigned char result = 0;

    for (long i = 0; i < len; i++) {
        unsigned char x = input[i] + i * 8 + 0x37;
        x -= encoded[i];
        result |= x;
    }

    return result;
}
```

しくみがわかったところで、encodedを逆変換して正しいフラグを求める方法を考えます。

正しいフラグが入力されたとき、全ての`i = 0,1,...,59`について、
```
encoded[i] == input[i] + i * 8 + 0x37
```
が成立するはずです。

よって、
```
input[i] = encoded[i] - 0x37 - i * 8
```
によって逆算することができます。

```py
encoded = bytes.fromhex("78 AB B7 (略) 64 7A 8C")

flag_list = []
for i in range(60): 
    flag_list.append((encoded[i] - i * 8 - 0x37) & 0xff)

flag = bytes(flag_list)
print(f"{flag = }")
```

フラグを得たら、バイナリを実行してそのフラグを入力してみます。

```
$ ./wrong-instruction
Input > Alpaca{****************************************************}
Correct! The flag is Alpaca{****************************************************}
```

フラグが正しかったことがわかりました。

## その他

この問題の面白いところは、別にプログラムが壊れているわけではなく実行はちゃんとできるのに逆コンパイラだけ騙すことですね。

アンチディスアセンブル・・・そんなことができるのですね。勉強になりました。
