---
title: "Renda - AlpacaHack Daily"
category: "rev"
subcategory: "rev"
type: "writeup"
tags: ["rev", "alpacahack", "renda", "reverse-engineering", "alpacahack-daily", "daily"]
summary: "rev writeup for \"Renda\" from AlpacaHack Daily - techniques: alpacahack, renda, reverse-engineering, alpacahack-daily, daily."
source:
  name: "baumroll0928-spec/myRepository"
  url: "https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202607/d04_Renda/README.md"
ctf:
  name: "AlpacaHack Daily"
  year: 2026
  challenge: "Renda"
---

## Source

- **CTF:** AlpacaHack Daily
- **Challenge:** Renda
- **Date:** 2026-07-04
- **Repository:** [baumroll0928-spec/myRepository](https://github.com/baumroll0928-spec/myRepository)
- **Directory:** <https://github.com/baumroll0928-spec/myRepository/tree/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202607/d04_Renda>
- **File:** <https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202607/d04_Renda/README.md>

---
# Renda

## 問題

連打するだけ!

```html
Click!

<p id="cnt">count: 0</p>
<p id="flag">Click 100,000 times to get the flag!</p>

<script>function u(U,h){U=U-(0x2439+0x1d1f+-0x40d6);const（略）hV.hD)+'+)+$');}});</script>
```

## 概要

index.htmlファイルをブラウザで開くと、「フラグを得るために10万回クリックして！」というメッセージとともにカウンターが表示されます。

クリックするたびにカウンターが増えていきますが、本当に10万回クリックしないといけないのでしょうか？

## 方針

10万回クリックするスクリプトを追加する。

## 解法

すぐに思いつく方法は、カウントの内容を保持している例えばcounter変数などをみつけてこれを99990あたりに改ざんする方法でしょう。

しかし、Javascriptの部分が難読化されています。

私はインデントや改行、空白を整えて静的解析しようと試みましたが、わりと早い段階で挫折しました。

なので静的解析は諦めて、10万回クリックする方法で解くことにしました。

とはいっても本当にマウスを使って手動で10万回クリックするのではなく、10万回クリックしたという情報をブラウザに伝えるだけです。

※問題のジャンルがWebではなくRevなので、作問者の意図した解法ではないかもしれません。

具体的には、配布のindex.htmlの末尾に次の6行を追加します。
```html
<script>
    const me = new MouseEvent('click', {bubbles: true});
    for (let i = 0; i < 100000; i++) {
        document.dispatchEvent(me);
    }
</script>
```
new MouseEventでマウスクリックのイベントを作り、dispatchEventで10万回繰り返し送っています。

人間が手動で10万回クリックするのは大変ですが、スクリプトならあっという間に終わります。

メモ帳やVSCodeなどのテキストエディタで編集したら、ページを読み込みなおすと、無事フラグが表示されています。

このフラグをコピペして提出したいところですが、一つ注意点があります。

普通にドラッグ＆ドロップで選択しようとすると、マウスボタンを離したときにカウントアップが走り選択が消えてしまいます。

なので、ドラッグで引っ張った後、マウスボタンを離す前にCtrl+Cでコピーする必要があります。

※Ctrl+Aで全選択してからCtrl+Cでコピーして、いったんテキストエディタに貼り付けてもいいですね。
