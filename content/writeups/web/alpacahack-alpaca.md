---
title: "Alpaca++ - AlpacaHack Daily"
category: "web"
subcategory: "web"
type: "writeup"
tags: ["web", "alpacahack", "alpaca++", "web-exploitation", "alpaca", "alpacahack-daily"]
summary: "web writeup for \"Alpaca++\" from AlpacaHack Daily - techniques: alpacahack, alpaca++, web-exploitation, alpaca, alpacahack-daily."
source:
  name: "baumroll0928-spec/myRepository"
  url: "https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202605/d01_Alpaca%2B%2B/README.md"
ctf:
  name: "AlpacaHack Daily"
  year: 2026
  challenge: "Alpaca++"
---

## Source

- **CTF:** AlpacaHack Daily
- **Challenge:** Alpaca++
- **Date:** 2026-05-01
- **Repository:** [baumroll0928-spec/myRepository](https://github.com/baumroll0928-spec/myRepository)
- **Directory:** <https://github.com/baumroll0928-spec/myRepository/tree/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202605/d01_Alpaca%2B%2B>
- **File:** <https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202605/d01_Alpaca%2B%2B/README.md>

---
# Alpaca++

最近体調が悪すぎてしばらくDaily AlpacaHackをサボってました。

## 問題

Unicodeコードポイント順において、「🦙」の次に位置する絵文字をフラグ形式で答えてください。

例えば、その絵文字が「️🦀」であれば、フラグは Alpaca{🦀} となります。

## 解法

Unicodeは、絵文字を含む世の中のありとあらゆる文字に一意のコードを割り当てる文字コード規格です。

当然「🦙」にも何らかのコードが割り当てられているはずなので、そのコード+1にあたる文字を答えよ、という問題ですね。

タイトルの`Alpaca++`というのは、「🦙」をインクリメント（１増やすこと）せよという意味でしょうか。

あと例示で「️🦀」が使われているのは「それフラグやない、クラブや。」っていうツッコミ待ちでしょうか。（考えすぎ。）

### 方針１：Web検索を使って解く

「🦙 unicode」等でWeb検索すると、「🦙」のUnicodeポイントが`1f999`であることがわかります。

`1f999`の次は`1f99a`ですので、「unicode 1f99a」等で再度Web検索すると該当する絵文字が何であるかがわかります。

### 方針２：Pythonを使って解く

`ord`関数で文字をUnicodeポイントに変換でき、`chr`関数でその逆の変換ができます。
```py
print(chr(ord("🦙") + 1))
```

### 方針３：Excelを使って解く

Excelにも同様にUnicodeポイントと文字を相互変換する関数`UNICODE`と`UNICHAR`があります。
```
=UNICHAR(UNICODE("🦙") + 1)
```

### 方針４：Wordを使って解く

Wordで本文に「🦙」を貼り付けてから`Alt`+`X`を押すと、Unicodeポイントの`1F999`に変換されます。

これを`1F99A`に書き換えてから再度`Alt`+`X`を押すと、答えの絵文字に変換されます。
