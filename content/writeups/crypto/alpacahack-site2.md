---
title: "SITE2 - AlpacaHack Daily"
category: "crypto"
subcategory: "number-theory"
type: "writeup"
tags: ["crypto", "alpacahack", "chinese-remainder", "site2", "number-theory", "cryptography"]
summary: "crypto writeup for \"SITE2\" from AlpacaHack Daily - techniques: alpacahack, chinese-remainder, site2, number-theory, cryptography."
source:
  name: "baumroll0928-spec/myRepository"
  url: "https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202606/d15_SITE2/README.md"
ctf:
  name: "AlpacaHack Daily"
  year: 2026
  challenge: "SITE2"
---

## Source

- **CTF:** AlpacaHack Daily
- **Challenge:** SITE2
- **Date:** 2026-06-15
- **Repository:** [baumroll0928-spec/myRepository](https://github.com/baumroll0928-spec/myRepository)
- **Directory:** <https://github.com/baumroll0928-spec/myRepository/tree/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202606/d15_SITE2>
- **File:** <https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202606/d15_SITE2/README.md>

---
# SITE/2

## 問題

HTTP/2 に対応した Web サイトを作ったんだけど、アクセスできなくて困ってます

```js
import http2 from "node:http2";

const server = http2.createServer();

server.on("stream", (stream) => {
    stream.end("🦙 Welcome to my website 🦙\nFlag: Alpaca{REDACTED}");
});

server.listen(3000, () => { console.log("http://localhost:3000"); });
```

## 概要

`docker compose up`してchromeブラウザで`http://localhost:3000/`にアクセスしてみると、たしかに
```
このページは動作していません
localhost から無効な応答が送信されました。
ERR_INVALID_HTTP_RESPONSE
```
と表示されてしまいます。

どうすればこのページにアクセスしてフラグを確認することができるのでしょうか？

## 解法

まず「HTTP/2ってなに？」ってなったので調べるところから始めました。

HTTP/2は、Webサーバーからデータを取得するプロトコルで、HTTP/1.1のパフォーマンスを向上させる目的で誕生しました。

いろいろなサイトを見て回りましたがだいたい次のようなことが書いてありました。

メリット

- Webサイトの表示速度が向上する
- サーバーやネットワークの負荷が下がる
- モバイル環境や遅延のある回線でも体感速度が向上しやすい

デメリット

- HTTPS暗号化が必須
- パケットロスに弱い

デメリットの１つめが怪しいです。

そこで、Nodeのhttp2モジュールについて調べてみたところ、
```js
import http2 from "node:http2";
import fs from "node:fs";

const options = {
    key: fs.readFileSync("localhost.key"),
    cert: fs.readFileSync("localhost.crt"),
};
const server = http2.createSecureServer(options);

server.on("stream", (stream) => {
    stream.respond({
        ":status": 200,
        "content-type": "text/plain; charset=utf-8"
    });
    stream.end("🦙 Welcome to my website 🦙\nFlag: Alpaca{REDACTED}");
});

server.listen(3000, () => { console.log("https://localhost:3000"); });
```
のように、`http2.createServer`ではなく`http2.createSecureServer`を使わないといけないようです。

※これを実際に動かしたいときは、opensslを使って自己署名証明書を発行し、Dockerfileを書き換えてコンテナ内に取り込むといった手順が必要になります。

この方法で`https://localhost:3000`にアクセスすると、警告は出るもののページが表示されることを確認しました。

本番環境も同じように直せるならこれでいいですが、そんなことができてしまったらCTFの問題として成立しないので、別の方法を使う必要があります。

ブラウザからではなくcurlコマンドで取得しようと試みましたがダメでした。
```
$ curl http://localhost:3000
curl: (1) Received HTTP/0.9 when not allowed
```
なんとかできないでしょうか？

調べてみると、`--http2`オプションを付けると良いみたいです。
```
$ curl --http2 http://localhost:3000
curl: (1) Received HTTP/0.9 when not allowed
```
ダメでした。

さらに調べてみると、`--http2`ではなく`--http2-prior-knowledge`を付けると良いことがわかりました。

```
$ curl --http2-prior-knowledge http://localhost:3000
🦙 Welcome to my website 🦙
Flag: Alpaca{REDACTED}
```

なんとかフラグを得ることができました。

`--http2`の場合、まずHTTP/1.1で通信を始めてHTTP/2に対応しているか問い合わせるのに対し、`--http2-prior-knowledge`の場合はいきなりHTTP/2で通信を始めるという違いがあるようです。

今回の問題では、暗号化していない通信プロトコル（http://）が使われているにもかかわらずサーバーはHTTP/2しか受け付けないというズレがあったため、最初から強制的にHTTP/2で通信を開始する`--http2-prior-knowledge`オプションが必要であったのだと考えられます。

## その他

先週の土日、SECCON Biginners CTF 2026にソロで参戦してきました。

24問中13問解くことができ、630チーム中289位（45.9%）というまあまあそこそこな成績を残すことができました。

Daily AlpacaHackのおかげで徐々に力がついているようです。

いつもと違う雰囲気が新鮮で楽しめはしましたが、終わった後の疲労感がすごかったので、やっぱり１日１問でいいかなと思いました（笑）
