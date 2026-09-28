---
title: "Día Nacional de la Alpaca - AlpacaHack Daily"
category: "crypto"
subcategory: "crypto"
type: "writeup"
tags: ["crypto", "alpacahack", "nacional", "alpaca", "cryptography", "d-a-nacional-de-la-alpaca"]
summary: "🦙  El Perú cuenta con alrededor de 4.7 millones de alpacas, representando el 80% de la población mundial."
source:
  name: "baumroll0928-spec/myRepository"
  url: "https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202608/d01_D%C3%ADa_Nacional_de_la_Alpaca/README.md"
ctf:
  name: "AlpacaHack Daily"
  year: 2026
  challenge: "Día Nacional de la Alpaca"
---

## Source

- **CTF:** AlpacaHack Daily
- **Challenge:** Día Nacional de la Alpaca
- **Date:** 2026-08-01
- **Repository:** [baumroll0928-spec/myRepository](https://github.com/baumroll0928-spec/myRepository)
- **Directory:** <https://github.com/baumroll0928-spec/myRepository/tree/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202608/d01_D%C3%ADa_Nacional_de_la_Alpaca>
- **File:** <https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202608/d01_D%C3%ADa_Nacional_de_la_Alpaca/README.md>

---
# Día Nacional de la Alpaca

## 問題

🦙 < 今日はペルー政府が定める「アルパカの日」だよ

[ペルー政府の記事](https://www.gob.pe/institucion/midagri/noticias/997309-dia-nacional-de-la-alpaca-midagri-destaca-el-trabajo-de-mas-de-90-mil-productores-en-todo-el-pais) では、アルパカには2種類の品種があると説明されています。「カールした毛を持ち、もこもこに見える」として知られるほうの品種を、英小文字でフラグ形式で答えてください。例えば、品種名が「Bulldog」であればフラグは Alpaca{bulldog} です。

## 解法

「アルパカの日」なんていうのがあるんですね。

問題文に示されたリンクを開くと、スペイン語で書かれた記事が表示されます。

※問題のタイトル「Día Nacional de la Alpaca」は英語だと「National Alpaca Day」、日本語だと「全国アルパカの日」になります。

スペイン語が読める方ならそのまま読めば良さそうですが、私は全く読めません。どうしましょうか？

### 方法1: ブラウザの翻訳機能を使う

Chromeブラウザのアドレスバーの右端の「このページを翻訳」ボタンから「日本語」を選ぶと、ページ全体を翻訳してくれます。

これを使って、該当する文章の場所をおおまかに見つけ、原文と見比べて答えを探していきます。すると、

>El Perú cuenta con alrededor de 4.7 millones de alpacas, representando el 80% de la población mundial. Existen dos razas: Huacaya (abundante fibra rizada) y Suri (lacia ligeramente ondulada). La alpaca ofrece 23 tonos de colores naturales en las prendas sin hacer uso de teñidos. Las regiones alpaqueras son Puno, Huancavelica, Arequipa, Cusco y Apurímac.

>ペルーには約470万頭のアルパカが生息しており、これは世界のアルパカの80%を占めています。アルパカには、ワカヤ種（巻き毛が豊富）とスリ種（まっすぐでやや波打った毛）の2種類があります。アルパカは、染料を使わずに23種類の自然な色合いの衣類を作ることができます。アルパカの生産地域は、プーノ、ワンカベリカ、アレキパ、クスコ、アプルマックです。

「世界のアルパカの80%」というのは先月1日の「Alpaca Nation」でも確認しましたよね。

更に読み進めていくと、
```
ワカヤ種（巻き毛が豊富） = Huacaya (abundante fibra rizada)
スリ種（まっすぐでやや波打った毛） = Suri (lacia ligeramente ondulada)
```
のようです。

フラグの内容は全て小文字とされているので、フラグは`Alpaca{huacaya}`となります。

### 方法2: Wikipediaで調べる

やっぱり困ったときのWikipediaですよね。

[アルパカ - Wikipedia](https://ja.wikipedia.org/wiki/%E3%82%A2%E3%83%AB%E3%83%91%E3%82%AB)

読んでみると、

> アルパカの毛の種類は「ワカイヤ（Huacaya）」と「スリ（Suri）」の2種類がある。「ワカイヤ」はふわふわでもこもこしている毛で、「スリ」はさらさら、少しドレッドヘアのようにツイストしている。市場に出回るのは殆ど「ワカイヤ」である。

とありました。

### 方法3: チャッピーにきく

このような事実の調査についてはAIが強そうなので、[きいてみました](https://chatgpt.com/share/6a6e4b4d-7f9c-83e8-aff3-aef7e7e09a69)。

すると、

> もこもことした見た目で、毛に**カール（クリンプ）**がある品種は フアカヤ（Huacaya、ワカヤとも表記） です。

という回答を得ることができました。

## その他

最近何かのネットの記事で見たのですが、[市川市動植物園](https://www.city.ichikawa.lg.jp/site/zoo/3951.html)では、この日にちなんで「アルパカダッシュ」というイベントが行われたようです。

※このリンクの記事は昨年のものですね。

私もだいぶアルパカに敏感になってきたみたいです（笑）
