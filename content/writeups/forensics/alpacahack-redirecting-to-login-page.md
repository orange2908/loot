---
title: "Redirecting to Login Page - AlpacaHack Daily"
category: "forensics"
subcategory: "network"
type: "writeup"
tags: ["forensics", "alpacahack", "wireshark", "redirecting", "login", "page"]
summary: "forensics writeup for \"Redirecting to Login Page\" from AlpacaHack Daily - techniques: alpacahack, wireshark, redirecting, login, page."
source:
  name: "baumroll0928-spec/myRepository"
  url: "https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202607/d13_Redirecting_to_Login_Page/README.md"
ctf:
  name: "AlpacaHack Daily"
  year: 2026
  challenge: "Redirecting to Login Page"
---

## Source

- **CTF:** AlpacaHack Daily
- **Challenge:** Redirecting to Login Page
- **Date:** 2026-07-13
- **Repository:** [baumroll0928-spec/myRepository](https://github.com/baumroll0928-spec/myRepository)
- **Directory:** <https://github.com/baumroll0928-spec/myRepository/tree/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202607/d13_Redirecting_to_Login_Page>
- **File:** <https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202607/d13_Redirecting_to_Login_Page/README.md>

---
# Redirecting to Login Page

## はじめに

今回はWebジャンルの問題の作成に挑戦してみました。

既にWriteupを書いてくれている方もいるようですが、私もせっかく書いたので投稿しておきますね。

## 問題

ユーザーIDは`alpaca`、パスワードは`pacapaca`です。
```php
<?php
header("Location: login.php");

echo "Flag: " . getenv('FLAG') . "\n";
```

## 概要

問題文のとおり、ユーザーID:`alpaca`、パスワード:`pacapaca`でログインできるログイン機能が実装されていますが、フラグの取得には一切関係ありません。

`index.php`には`login.php`にリダイレクトするような記述があります。

これにより、`/`（ルート）にアクセスするとまず`/index.php`が開かれ、そこから`/login.php`に飛ぶことになるので、ユーザーは`/`にアクセスするだけで自動的に`/login.php`を開くことができるようになります。

これ自体はよくある記法のようですが、この問題では`index.php`の処理はそれだけで終わらず、その後にフラグを出力しています。

ブラウザで開いた場合は`login.php`に飛んでしまうので確認できませんが、どうすれば`index.php`に出力されたフラグを確認することができるのでしょうか？

## 解法

リダイレクトって、サーバー側で勝手に処理してくれるようなイメージがありますが、実際はクライアント側に対して「こっちを見にいってください」と伝えるだけです。

ブラウザは素直にそれに従いリクエストを投げなおしますが、あくまでもそれをサーバーが強制するわけではないということです。

具体的には、サーバーが
```php
header("Location: login.php");
```
を実行するとき、ステータスコード302(Found)とともにレスポンスヘッダー「Location: login.php」を出力します。

※より正確にいえば、送信予定のレスポンスデータにヘッダー「Location: login.php」を追加し、ステータスコードを302(Found)に書き換えて、リダイレクトの情報を含むレスポンスを送る準備をします。

しかし、そこで処理を中断したり自動的に`login.php`の処理に移ったりすることはなく、`index.php`の処理は続行されます。

そして、
```php
echo "Flag: " . getenv('FLAG') . "\n";
```
が実行され、環境変数がもつフラグがレスポンスボディに出力されます。

しかし、Chromeをはじめとする普通のブラウザは、302(Found)を読むと画面に描画することなく新しいページに飛んでしまいます。

よって、ブラウザからのアクセスではフラグを確認することができないので、別の方法を使う必要があります。

### 方法１: curlコマンドを使う

これが一番簡単かなと思います。

curlコマンドは既定ではリダイレクトを自動的に追跡しません。

```
curl http://34.170.146.252:12209/
```
を実行すると、index.phpの出力内容を確認することができます。

また、`-i`オプションを付けるとより詳細な情報を見ることができます。
```
curl -i http://34.170.146.252:12209/
```

※リダイレクトを自動的に追跡したいときは`-L`オプションを付けます。

※つい最近までcurlコマンドってWindowsには無いと思っていたのですが、コマンドプロンプトから実行できるんですね。

### 方法２: requestsモジュールでallow_redirects=Falseを指定する

Pythonのrequestsモジュールのget関数は逆に規定でリダイレクトを追跡します。

なので、allow_redirects=Falseオプションをつけて明示的に追跡しないようにする必要があります。
```py
import requests

URL = "http://34.170.146.252:12209/"

res = requests.get(URL, allow_redirects=False)
print(res.status_code)
print(res.headers.get('Location', None))
print(res.text)
```

### 方法３: Wireshark等でパケットを拾う

ブラウザで開いたときも、パケット自体は流れているので、Wireshark等で拾うことができます。

Wiresharkを使って解く場合は、下記のようなフィルタをかけてあげるといいでしょう。
```
ip.src == 34.170.146.252 && tcp.srcport == 12209 && http.response.code == 302
```

## 補足

`content.php`の冒頭にも同じように、直接アクセスしたときに`login.php`に飛ばすような記述があります。

```php
session_start();

$uid = $_SESSION['uid'] ?? '';
if (!$uid) {
    header("Location: login.php");
    exit;
}
```

しかし、こちらはヘッダーを出力した後`exit;`できっちり処理を終了しているため、前記の方法を使っても`content.php`の出力内容を確認することはできません。

## おわりに

はい、というわけで、HTTPのリダイレクトのナゾに迫る今回の問題、いかがでしたでしょうか？

慣れている方にとっては瞬殺だったかもしれませんが、そうでない方には少しでも悩んだり楽しんだり理解を深めたりしていただけていたら嬉しいです。

これからもシンプルかつ面白そうな問題を作っていきたいものです。
