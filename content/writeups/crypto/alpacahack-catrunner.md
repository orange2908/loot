---
title: "Catrunner - AlpacaHack Daily"
category: "crypto"
subcategory: "rsa"
type: "writeup"
tags: ["crypto", "alpacahack", "rsa", "path-traversal", "os-system", "catrunner"]
summary: "crypto writeup for \"Catrunner\" from AlpacaHack Daily - techniques: alpacahack, rsa, path-traversal, os-system, catrunner."
source:
  name: "baumroll0928-spec/myRepository"
  url: "https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202605/d25_Catrunner/README.md"
ctf:
  name: "AlpacaHack Daily"
  year: 2026
  challenge: "Catrunner"
---

## Source

- **CTF:** AlpacaHack Daily
- **Challenge:** Catrunner
- **Date:** 2026-05-25
- **Repository:** [baumroll0928-spec/myRepository](https://github.com/baumroll0928-spec/myRepository)
- **Directory:** <https://github.com/baumroll0928-spec/myRepository/tree/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202605/d25_Catrunner>
- **File:** <https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202605/d25_Catrunner/README.md>

---
# Catrunner

Catrunnerというとネコの遊び場みたいなのを想像してしまうのは私だけでしょうか？

## 問題

```py
import os

filename = input("Example: hello.txt\n$ cat /app/")
assert ".." not in filename, "Path traversal is not allowed"
path = os.path.join("/app", filename)
if os.path.isfile(path):
    os.system(f"cat {path}")
else:
    print("File not found")
```

## 概要

`Dockerfile`を見ると、カレントディレクトリは`/app`であり、フラグは`/flag.txt`にあることがわかります。

実行すると、文字列`filename`の入力を求められ、`/app`に`os.path.join`で`filename`を結合したパス`path`を作成し、そのパスのファイルが存在する場合は`cat`コマンドで`path`の内容を表示してくれます。

入力した`filename`に`..`が含まれると弾かれてしまうようですが、どのように入力すればフラグを得ることができるのでしょうか？

## 解法

普通に考えたら`../flag.txt`と入力してパストラバーサル攻撃をしたいところですが、入力に`..`が含まれていないかチェックしていることから、
```
$ nc localhost 1337
Example: hello.txt
$ cat /app/../flag.txt
Traceback (most recent call last):
  File "/app/jail.py", line 4, in <module>
    assert ".." not in filename, "Path traversal is not allowed"
           ^^^^^^^^^^^^^^^^^^^^
AssertionError: Path traversal is not allowed
```
このように弾かれてしまいます。

相対パスがダメなら絶対パスといきたいところですが、頭に`/app`が結合されていることから、`/flag.txt`と入力すると、
```
$ nc localhost 1337
Example: hello.txt
$ cat /app//flag.txt
Alpaca{*** REDACTED ***}
```
このように失敗してしま・・・っていませんね？？？

なぜこれでうまくいくのでしょうか？

調べてみると、その理由は`os.path.join`関数の仕様にありました。

[os.path.join(path, /, *paths)](https://docs.python.org/ja/3/library/os.path.html#os.path.join)

私は英語はよく読めませんが、「セグメントが絶対パスの場合、それまでのパスを全て無視する」と書いてあり、LinuxとWindowsのそれぞれの例があげられているようです。

今回の問題の場合、`/app`に絶対パスの`/flag.txt`を結合しようとすることでそれより前の`/app/`が無視されて`/flag.txt`になってしまったというわけですね。

実際、`os.path.join`を使わずに
```py
#path = os.path.join("/app", filename)
path = "/app/" + filename
```
のように単純に`+`で結合すると、
```
$ nc localhost 1337
Example: hello.txt
$ cat /app//flag.txt
File not found
```
このように失敗することを確認しました。

## その他

Pythonについてはある程度わかったつもりになっていましたし、問題作成を始めてからは面白そうなネタを探すために色々な関数などの仕様を調べたりもしていました。

それでもこのようなよく使う身近な関数に全く知らない仕様があるのに気づくのは、すごく楽しいですし、だからこそCTFはやめられなくなっちゃうんですよね。

さて、今日は私が作成した問題第二弾が公開される日です。

ちょっとワケあってドキドキしていますが、無事皆さんに楽しんでいただけることを願っています。
