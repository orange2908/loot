---
title: "biribiri - AlpacaHack Daily"
category: "pwn"
subcategory: "pwn"
type: "writeup"
tags: ["pwn", "alpacahack", "biribiri", "binary-exploitation", "alpacahack-daily", "daily"]
summary: "pwn writeup for \"biribiri\" from AlpacaHack Daily - techniques: alpacahack, biribiri, binary-exploitation, alpacahack-daily, daily."
source:
  name: "baumroll0928-spec/myRepository"
  url: "https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202607/d17_biribiri/README.md"
ctf:
  name: "AlpacaHack Daily"
  year: 2026
  challenge: "biribiri"
---

## Source

- **CTF:** AlpacaHack Daily
- **Challenge:** biribiri
- **Date:** 2026-07-17
- **Repository:** [baumroll0928-spec/myRepository](https://github.com/baumroll0928-spec/myRepository)
- **Directory:** <https://github.com/baumroll0928-spec/myRepository/tree/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202607/d17_biribiri>
- **File:** <https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202607/d17_biribiri/README.md>

---
# biribiri

## 問題

証明書を発行してみた！

```py
FLAG = getenv("FLAG", "Alpaca{REDACTED}")
SECRET = urandom(16)
ticket = json.dumps(
    {"user": "guest", "memo": "A" * 64, "admin": False}, separators=(",", ":")
).encode()
signature = bcrypt.hashpw(SECRET + ticket, bcrypt.gensalt())

print(f"ticket: {ticket.hex()}")
print(f"signature: {signature.decode()}")

try:
    submitted = bytes.fromhex(input("ticket hex > "))
    ok = bcrypt.checkpw(SECRET + submitted, signature) and json.loads(submitted)["admin"] is True
except (ValueError, KeyError, json.JSONDecodeError):
    ok = False

print(FLAG if ok else "nope")
```

## 概要

実行すると、`"admin": False`を含む`ticket`と、これから発行された証明書`signature`が16進数で表示されます。

その後、別の`ticket`の入力を求められます。

入力した`ticket`と`signature`で検証に成功し、かつ、入力した`ticket`に`"admin": True`が含まれていたら、フラグをゲットできます。

bcryptでは内部でハッシュ化が行われており、内容が少しでも変わると計算結果が大幅に変わって検証に失敗するはずですが、何を入力すればいいのでしょうか？

## 解法

まず、Dockerではなく手元の環境でそのまま実行してみたところ、
```
Traceback (most recent call last):
  File "c:\ctf\biribiri\prob.py", line 12, in <module>
    signature = bcrypt.hashpw(SECRET + ticket, bcrypt.gensalt())
ValueError: password cannot be longer than 72 bytes, truncate manually if necessary (e.g. my_password[:72])
```
なぜかエラーになってしまいました。

「`password`は72バイトより長くすることはできない、`my_password[:72]`のように切ってね」といっています。

Dockerで実行すると正しく実行できるようですが、この72バイトというのはこの問題に何か関係あるのでしょうか？

それはさておき、bcryptは、レインボーテーブル攻撃やブルートフォース攻撃に対抗できるように設計されたパスワードハッシュ化関数です。

Pythonのbcryptモジュールでは、
```py
hashed_password = bcrypt.passw(password, salt)
```
で証明書を発行し、
```py
ok = bcrypt.checkpw(password, hashed_password)
```
で検証します。

こんな感じですね。

```py
import bcrypt

password = '{"userid":"baumroll1234"}'.encode()
bad_pw = '{"userid":"yohshi34"}'.encode()

hashed_password = bcrypt.hashpw(password, bcrypt.gensalt())
print(hashed_password, type(hashed_password))

ok = bcrypt.checkpw(password, hashed_password)
print(ok)

ok = bcrypt.checkpw(bad_pw, hashed_password)
print(ok)
```
```
b'$2b$12$qXNeBY8eaRQCjxZa9DuuH.n.syhCiBaXnl6IylEc5co0tMXxNAjzm' <class 'bytes'>
True
False
```

さて、最初の`ticket`の`"admin": False`を`"admin": True`に書き換えると、証明書はどのように変化するのでしょうか？

```py
import json
import bcrypt

SECRET = bytes.fromhex("0123456789abcdef0123456789abcdef")
mysalt = bcrypt.gensalt()

ticket = json.dumps(
    {"user": "guest", "memo": "A" * 64, "admin": True}, separators=(",", ":")
).encode()
signature = bcrypt.hashpw(SECRET + ticket, mysalt)
print(f"ticket: {ticket.hex()}")
print(f"signature: {signature.decode()}")

ticket = json.dumps(
    {"user": "guest", "memo": "A" * 64, "admin": False}, separators=(",", ":")
).encode()
signature = bcrypt.hashpw(SECRET + ticket, mysalt)
print(f"ticket: {ticket.hex()}")
print(f"signature: {signature.decode()}")
```
```
ticket: 7b2275736572223a226775657374222c226d656d6f223a2241414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141222c2261646d696e223a747275657d
signature: $2b$12$K8g7i2Sdik8pkr2hVxlsc.pWbI7igBJjex3Le7xEHcqpEjFGS3VOS
ticket: 7b2275736572223a226775657374222c226d656d6f223a2241414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141222c2261646d696e223a66616c73657d
signature: $2b$12$K8g7i2Sdik8pkr2hVxlsc.pWbI7igBJjex3Le7xEHcqpEjFGS3VOS
```

あれ？？？`ticket`が違うのに`signature`は全く同じじゃないですか？

それならば、試しに`"admin": True`にして提出してみましょう。

```py
import pwn
import json

HOST, PORT = "localhost", 1337
# HOST, PORT = "34.170.146.252", 41071
p = pwn.remote(HOST, PORT)

ticket = json.dumps(
    {"user": "guest", "memo": "A" * 64, "admin": True}, separators=(",", ":")
).encode()
payload = ticket.hex().encode()
p.sendlineafter(b'ticket hex > ', payload)

print(p.recvall().decode())
```
```
Alpaca{REDACTED}
```
ちゃんと出ました…ね…？

フラグは取れたものの、これでいけた理由が全然わかりません。

その理由については、本番環境で得られた本物のフラグにヒントが書かれていました。

「bcrypt 脆弱性」などをWeb検索でいろいろ調べたところ、bcryptはパスワードの72バイトを越えた部分を無視することがわかりました。

今回の問題の場合、`"admin":`の`:`までで既に114バイトあるので、それ以降が`False`でも`True`でも発行される証明書に影響はなかったといういわけですね。

そうすると、この解法の冒頭ででてきたエラー
```
ValueError: password cannot be longer than 72 bytes, truncate manually if necessary (e.g. my_password[:72])
```
についても説明がつきそうです。

配布のDocker関連ファイル`requirements.txt`では、
```
bcrypt==4.3.0
```
となっており、bcryptのバージョンに4.3.0を指定しています。

一方、私のローカルの環境は
```
> pip show bcrypt
Name: bcrypt
Version: 5.0.0
...
```
のように、バージョン5.0.0になっていました。

バージョン5.0.0で、このような脆弱性を防ぐために`password`が72バイトを超える場合のエラー処理が実装されたようです。
