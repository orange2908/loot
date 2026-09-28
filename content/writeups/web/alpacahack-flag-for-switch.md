---
title: "Flag for Switch - AlpacaHack Daily"
category: "web"
subcategory: "web"
type: "writeup"
tags: ["web", "alpacahack", "switch", "web-exploitation", "flag-for-switch", "alpacahack-daily"]
summary: "web writeup for \"Flag for Switch\" from AlpacaHack Daily - techniques: alpacahack, switch, web-exploitation, flag-for-switch, alpacahack-daily."
source:
  name: "baumroll0928-spec/myRepository"
  url: "https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202605/d18_Flag_for_Switch/README.md"
ctf:
  name: "AlpacaHack Daily"
  year: 2026
  challenge: "Flag for Switch"
---

## Source

- **CTF:** AlpacaHack Daily
- **Challenge:** Flag for Switch
- **Date:** 2026-05-18
- **Repository:** [baumroll0928-spec/myRepository](https://github.com/baumroll0928-spec/myRepository)
- **Directory:** <https://github.com/baumroll0928-spec/myRepository/tree/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202605/d18_Flag_for_Switch>
- **File:** <https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202605/d18_Flag_for_Switch/README.md>

---
# Flag for Switch

## 問題

Switchでアクセスすればフラグが見えるよ！

```js
const htmlForSwitch = `
<!DOCTYPE html>
<html>
  <body>
    <h1>Welcome, Switch user! Here is your flag: ${FLAG}</h1>
  </body>
</html>
`;

app.get("/", async (req, res) => {
  const userAgent = req.headers['user-agent'] || '';
  if (userAgent.includes("Switch")) {
    res.send(htmlForSwitch);
  } else {
    res.send(html);
  }
});
```

## 概要

Switchでアクセスしたときだけフラグが表示されるようになっているようです。

Switchのeショップを探してみましたが、ブラウザアプリは見つけられませんでした。

どうすればSwitch専用ページを表示することができるのでしょうか？

## 方針

User Agentを偽装する。

## 解法

ソースコードを見ると、Switchからアクセスしたか判断するためにリクエストヘッダーの`user-agent`を参照しているようです。

通常`user-agent`には、アクセスした端末のOSやブラウザの情報などが記録されます。

この問題では、その`user-agent`に`Switch`という文字列が含まれていたら、Switchからのアクセスと判断してフラグを表示してくれます。

リクエストヘッダーはクライアント側の自己申告なので、偽装することができます。

例えば、
```
curl -H "User-Agent: Alpaca Switch" http://34.170.146.252:13697/
```
のような`curl`コマンドでフラグを得ることができます。

## 補足

フラグを見ると、「本当にスイッチで解けるよ！試してみて！」と書いてあります。

どうすればSwitchで問題サーバーのページを開くことができるのでしょうか？

調べてみると、DNSを手動で専用のアドレスに設定することで、Switchが内部でもっているブラウザを使ってアクセスできるようです。

※公式の方法ではないようなので、試す場合は自己責任でお願いします。

* 設定＞インターネット設定から、普段使っているネットワークを選ぶ。
* 設定の変更＞DNS設定を「手動」に変更し、優先DNSを「045.055.142.122」にする。
* 保存して、「このネットワークに接続」する。
* すると「このネットワークを使うには、手続きが必要です。」と表示される。
* 「つぎへ」を押すと、ブラウザで「BrowseDNS」と表記されたポータルサイトが表示される。
* 「Enter URL Directly」（キーボードのアイコン）を押す。
* 「`http://34.170.146.252:13697/`」を入力して「VISIT」を押す。

この方法によって自分のSwitchの画面にフラグが表示されることを確認しました。

※実験が終わったら速やかにDNS設定を「自動」に戻すことをおすすめします。（試してはいませんがオンラインゲームのプレイに支障が出るっぽいです。）
