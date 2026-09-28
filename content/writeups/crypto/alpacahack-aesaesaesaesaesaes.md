---
title: "AESAESAESAESAESAES - AlpacaHack Daily"
category: "crypto"
subcategory: "aes"
type: "writeup"
tags: ["crypto", "alpacahack", "aes", "xor", "cryptography", "aesaesaesaesaesaes"]
summary: "crypto writeup for \"AESAESAESAESAESAES\" from AlpacaHack Daily - techniques: alpacahack, aes, xor, cryptography, aesaesaesaesaesaes."
source:
  name: "baumroll0928-spec/myRepository"
  url: "https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202608/d06-08_AESAESAESAESAESAES/README.md"
ctf:
  name: "AlpacaHack Daily"
  year: 2026
  challenge: "AESAESAESAESAESAES"
---

## Source

- **CTF:** AlpacaHack Daily
- **Challenge:** AESAESAESAESAESAES
- **Date:** 2026-08-06-08
- **Repository:** [baumroll0928-spec/myRepository](https://github.com/baumroll0928-spec/myRepository)
- **Directory:** <https://github.com/baumroll0928-spec/myRepository/tree/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202608/d06-08_AESAESAESAESAESAES>
- **File:** <https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202608/d06-08_AESAESAESAESAESAES/README.md>

---
# AESAESAESAESAESAES

最初はどうすればいいか全然わかりませんでしたが、気付いたらスッキリする面白い問題でした。

## 問題

大事なことなのでいっぱい言いました!

```py
flag_charset = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz{}_"
flag = os.environ.get("FLAG", "Alpaca{_________DUMMY_________}").encode()

assert flag.startswith(b"Alpaca{") and flag.endswith(b"}")
assert len(flag) == 31
assert all(c in flag_charset for c in flag)

key = os.urandom(16)
iv = os.urandom(16)
cipher = AES.new(key, AES.MODE_CBC, iv)

msg = b"FLAG IS:" + flag
msg_16 = msg * 16

ciphertext = cipher.encrypt(msg_16)
print(f"iv(hex): {cipher.iv.hex()}")
print(f"ciphertext(hex): {ciphertext.hex()}")

while True:
    user_input = bytes.fromhex(input("plaintext to encrypt (hex): "))

    if len(user_input) != 16:
        print("Input must be 16 bytes (32 hex characters).")
        continue

    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(user_input)
    print(f"iv(hex): {cipher.iv.hex()}")
    print(f"ciphertext(hex): {ciphertext.hex()}")
```

## 概要

実行すると、ランダムな`key`,`iv`が生成され、31文字のフラグの前に`FLAG IS:`を付けた39文字のメッセージを16回繰り返した
```
FLAG IS:Alpaca{???????????????????????}FLAG IS:Alpaca{???????????????????????}FLAG IS:Alpaca{???????????????????????}FLAG IS:Alpaca{???????????????????????}FLAG IS:Alpaca{???????????????????????}FLAG IS:Alpaca{???????????????????????}FLAG IS:Alpaca{???????????????????????}FLAG IS:Alpaca{???????????????????????}FLAG IS:Alpaca{???????????????????????}FLAG IS:Alpaca{???????????????????????}FLAG IS:Alpaca{???????????????????????}FLAG IS:Alpaca{???????????????????????}FLAG IS:Alpaca{???????????????????????}FLAG IS:Alpaca{???????????????????????}FLAG IS:Alpaca{???????????????????????}FLAG IS:Alpaca{???????????????????????}
```
をこれらの`key`,`iv`で暗号化した暗号文が`iv`とともに提示されます。

その後、任意の16バイトの平文を送るたびに、これを同じ`key`,`iv`で暗号化した暗号文を教えてもらえます。

`key`はわからないので復号はできそうにありませんが、どうすればフラグを特定できるのでしょうか？

## 説明

### AESについて

AESは、共通鍵暗号法（暗号化に使う鍵と復号に使う鍵が同じ暗号法）のひとつです。

平文を16バイトのブロックに分け、ブロックごとに暗号化されます。

鍵のサイズは16バイト、24バイト、32バイトの中から選択することができます。

詳しいしくみは私には全然わかりませんが、初心者向けCTFにおいては、

「$`2^{128}`$種類ある16バイトのデータを、鍵を使ってよくかき混ぜるもの」

ぐらいに理解しておけば十分かなと思っています。

平文と暗号文を得てもこれらから鍵を求めることは現実的にはできないように設計されています。

### CBCモードについて

単純にブロックに区切って暗号化していくだけの方法は「ECBモード」です。

このECBモードだと、同じ平文ブロックを同じ鍵で暗号化すると同じ暗号文になるため、いろいろな問題点があるようです。（関連問題: 2月12日「AAAAAAAAEEEEEEEESSSSSSSS」、4月10日「AES is dead」）

これを防ぐために、平文ブロックと直前の暗号文ブロック（最初のブロックについては`iv`）のXORをとってから暗号化する方法が「CBCモード」です。

## 解法

まず、最初のブロックに注目してみます。

最初の平文ブロックの判明している部分を埋めてみると、
```
FLAG IS:Alpaca{?
```
となり、未知部分は1バイトだけになります。

この未知の`?`のところにflag_charsetに含まれる`ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz{}_`を順番にあてはめたものを次々に送り、返ってきた暗号文を観測します。

すると、正しい文字のときだけ最初に提示された暗号文の最初のブロックと同じものが返ってくるはずです。

これにより、フラグの未知部分が1文字判明します。

まずはここまでのソルバーを作ってみましょう。

```py
import pwn

flag_charset = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz{}_"

# server.pyを実行する
io = pwn.process("python server.py", shell=True)

# ivを取得する
io.recvuntil(b'iv(hex): ')
iv_hex = io.recvline().decode().strip()
iv = bytes.fromhex(iv_hex)

# 暗号文を取得する
io.recvuntil(b'ciphertext(hex): ')
ct_hex = io.recvline().decode().strip()
ct = bytes.fromhex(ct_hex)

# 最初のブロックから1文字特定する
msg = b'FLAG IS:Alpaca{'
target = ct[0 : 16]
for b_int in flag_charset:
    # 送る平文を組み立てる
    b = bytes([b_int])
    payload = (msg + b).hex().encode()
    # 平文を送り暗号文を取得する
    io.sendlineafter(b'plaintext to encrypt (hex): ', payload)
    io.recvuntil(b'ciphertext(hex): ')
    res_hex = io.recvline().decode().strip()
    res = bytes.fromhex(res_hex)
    # 正しい暗号文が得られたらそのときの文字をメッセージに追加し繰り返しを抜ける
    if res == target:
        print(f"{b = }")
        msg += b
        break
else:
    print("Not found.")
    exit(1)
```

フラグはこのままだとわかりづらいので、同じ文字数で
```py
flag = os.environ.get("FLAG", "Alpaca{abcdefghijklmnopqrstuvw}").encode()
```
のように変えて実行してみました。

すると、
```
b = b'a'
```
のように、フラグの未知部分の1文字分を特定することができ、メッセージの既知部分が増えました。

これを利用して、他の部分も特定していきます。

平文ブロックが
```
LAG IS:Alpaca{a?
```
のように、先頭位置が繰り返しの頭から1文字右にずれているようなブロックをみつけたとします。

これは、ブロックサイズの16と繰り返し部分の長さ39が互いに素なので必ず見つけることができます。

ここで、最初のブロックのときと同じように、1バイトだけの未知部分`?`を変えながら順に観測して当てはまる文字を特定していきたいです。

しかし、今回の問題で使われる暗号化はCBCモードなので注意が必要です。

最初に提示される暗号文の暗号化では、最初のブロック以外のブロックは、直前の暗号文ブロックとXORしてから暗号化しています。

一方で、任意の平文を送ってしてもらう暗号化では、常に最初のブロックとして扱われるため、必ず`iv`とXORしてから暗号化します。

この違いを吸収するため、平文ブロックに直前の暗号文ブロックと`iv`をXORしたものを送る必要があります。

※最初のブロックのときは、いずれも`iv`を使うため差異が出ないので、そのままで大丈夫です。

それでは、ソルバーの続きを作ってみましょう。

まず、どのブロックを見ればいいかのリストを作っておきます。

```py
# ブロック位置リスト作成
order = [0] * 39
for y in range(1, 39):
    x = y * 16 % 39
    order[x] = y
```

このorderにより、x番目に見るブロックの位置がorder[x]であることがわかります。

残りの未知部分は22文字分なので、xを1～22で回せばいいでしょう。

```py
# 最初のブロック以外のブロックから他の未知部分も特定する
for x in range(1, 23):
    # 見るべきブロックを決める
    y = order[x]
    print(f"{x = }, {y = }")
    target = ct[y*16 : y*16+16]
    pre_block = ct[y*16-16 : y*16]
    for b_int in flag_charset:
        # 送る平文を組み立てる
        b = bytes([b_int])
        payload = pwn.xor(msg[x:] + b, pre_block, iv).hex().encode()
        # 平文を送り暗号文を取得する
        io.sendlineafter(b'plaintext to encrypt (hex): ', payload)
        io.recvuntil(b'ciphertext(hex): ')
        res_hex = io.recvline().decode().strip()
        res = bytes.fromhex(res_hex)
        # 正しい暗号文が得られたらそのときの文字をメッセージに追加し繰り返しを抜ける
        if res == target:
            print(f"{b = }")
            msg += b
            break
    else:
        print("Not found.")
        exit(1)

# できたメッセージを出力する
msg += b"}"
print(f"{msg = }")
```

これまでのコードをまとめて実行してみます。
```
b = b'a'
x = 1, y = 22
b = b'b'
x = 2, y = 5
b = b'c'
x = 3, y = 27
...
x = 22, y = 16
b = b'w'
msg = b'FLAG IS:Alpaca{abcdefghijklmnopqrstuvw}'
```
メッセージを全て復元することができました！

あとは本番サーバーに接続するため、最初のserver.pyの実行の部分を
```py
# 本番サーバーに接続する
io = pwn.remote("34.170.146.252", 57189)
```
のように書き換えて実行すればOKです。
