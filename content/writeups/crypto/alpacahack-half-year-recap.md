---
title: "Half-Year Recap - AlpacaHack Daily"
category: "crypto"
subcategory: "rsa"
type: "writeup"
tags: ["crypto", "alpacahack", "rsa", "aes", "half-year", "recap"]
summary: "crypto writeup for \"Half-Year Recap\" from AlpacaHack Daily - techniques: alpacahack, rsa, aes, half-year, recap."
source:
  name: "baumroll0928-spec/myRepository"
  url: "https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202606/d01_Half-Year_Recap/README.md"
ctf:
  name: "AlpacaHack Daily"
  year: 2026
  challenge: "Half-Year Recap"
---

## Source

- **CTF:** AlpacaHack Daily
- **Challenge:** Half-Year Recap
- **Date:** 2026-06-01
- **Repository:** [baumroll0928-spec/myRepository](https://github.com/baumroll0928-spec/myRepository)
- **Directory:** <https://github.com/baumroll0928-spec/myRepository/tree/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202606/d01_Half-Year_Recap>
- **File:** <https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202606/d01_Half-Year_Recap/README.md>

---
# Half-Year Recap

謎のアルパカに突然「フラグは2100年1月のカレンダーにあるパカ！」って言い放たれたあの日から、もう半年も経つのですね。

## 問題

Daily AlpacaHack がスタートしてから半年が経ちました！

半年間の統計です:

* 公開された問題数: 182
* 提出されたフラグ数: 44,846
* 正解のフラグ数: 34,818
* 1問でも解いたプレイヤー数: 2,572
* Writeup数: 615
* 作問者数: 36
* 全ての問題を解いた人数: 24 ... 🦙 < wow!

フラグは`Alpaca{thx_for_6_months_lets_build_next_gen_ctf_in_ai_era_see_u_tmr}`です

## 概要

Half-Year Recap = 半年の総括 という意味だそうです。

あらためて数字で見てみるとすごいですね。

## 解法

この問題のフラグについては問題文に示されているので、これをそのままコピペして提出すればOKです。

ちなみに、このフラグの中身の`_`を空白に変えてGoogle翻訳にかけてみると、
```
6ヶ月間ありがとう。AI時代の次世代CTFを構築しよう。また明日。
```
となりました。

## その他

まずは6か月おめでとうございます。

私はこのDaily AlpacaHackでCTFを始めたので、私自身のCTF歴も6か月ということになります。

簡単でも面白い問題や、難しくて全く歯が立たなかった問題、あと一歩のところで解けず悔しい思いをした問題もたくさんありましたが、どれも勉強に、また良い想い出になりました。

さらに先月から問題作成にも関与させていただけることになり、もう完全にCTFにハマってしまいました。

さて、せっかくですので、6か月を記念して、勝手ながら個人的にお気に入りの問題をいくつかピックアップさせていただこうと思います。（他にもお気に入りの問題はたくさんありますが。）

### 1月7日 [Square RSA](https://alpacahack.com/daily/challenges/square-rsa)

やっとRSAに少し慣れ始めた当時の私にとってこの問題はかなり革新的でした。$`\phi(n) = (p - 1)(q - 1)`$という教科書どおりの知識だけでは解けない程度のひねりがとても勉強になりました。

### 1月31日 [optimal-sort](https://alpacahack.com/daily/challenges/optimal-sort)

比較によるソートの計算量は`O(n log n)`であり`n`が大きくなると`O(n)`ではできないことは知っていたので（何ならこの問題では比較すらしていない）、正面突破は無理だとすぐに気付きましたが、ここをこうやってこうすればいいんだとわかったときの爽快感はすごかったです。

### 2月12日 [AAAAAAAAEEEEEEEESSSSSSSS](https://alpacahack.com/daily/challenges/aaaaaaaaeeeeeeeessssssss)

AESのECBモードの性質についてはWeb検索で調べればすぐにわかりますが、その性質をこんな風に問題に落とし込めるものなんだなぁと、まだ問題作成を始める前でしたがとても感心した記憶があります。問題タイトルのインパクトもあって、かなり印象に残っています。

### 3月17日 [Free Coupon](https://alpacahack.com/daily/challenges/free-coupon)

普段難しすぎて全然解けないWebジャンルの問題がこの日はわりと順調に解けたので、嬉しすぎてフラグを提出するのも忘れてすぐにWriteupを書き始めたのを覚えています。ちなみに当時の私はまだ「レースコンディション」なんていう言葉は微塵も知りませんでした。

### 3月18日 [PPPPParse](https://alpacahack.com/daily/challenges/ppppparse)

JSONの`parse`を使ったパズル問題です。試行錯誤を繰り返しながら一歩ずつ答えに近づいていく過程が楽しかったです。

### 3月27日 [encrypted-p](https://alpacahack.com/daily/challenges/encrypted-p)

この問題を初めて見たとき、「どうやって解けばいいのかな？」よりも「この問題の作成者はなぜ`p`を暗号化しようと思ったんだろう？どうしたらそんな面白ことが思いつくんだろう？」の方が強くてとても印象に残っています。

### 4月24日 [Image Python](https://alpacahack.com/daily/challenges/image-python)

各種画像ファイル形式のバイナリ構造を調べたり、Pythonのコードとの接点を考えたりして、最終的にペイロードがバシッと仕上がったときはすごく気持ちよかったです。

### 5月8日 [Vending Machine](https://alpacahack.com/daily/challenges/vending-machine)

最後は宣伝です（笑）Pythonの仕様を利用して不可能にみえる要件を達成する問題です。手前味噌ですが結構キレイな問題に仕上がっていると思っていて、実際自分でも結構気に入っていたりします。
