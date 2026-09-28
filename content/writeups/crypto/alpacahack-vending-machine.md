---
title: "Vending Machine - AlpacaHack Daily"
category: "crypto"
subcategory: "rsa"
type: "writeup"
tags: ["crypto", "alpacahack", "rsa", "vending", "machine", "cryptography"]
summary: "crypto writeup for \"Vending Machine\" from AlpacaHack Daily - techniques: alpacahack, rsa, vending, machine, cryptography."
source:
  name: "baumroll0928-spec/myRepository"
  url: "https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202605/d08_Vending_Machine/README.md"
ctf:
  name: "AlpacaHack Daily"
  year: 2026
  challenge: "Vending Machine"
---

## Source

- **CTF:** AlpacaHack Daily
- **Challenge:** Vending Machine
- **Date:** 2026-05-08
- **Repository:** [baumroll0928-spec/myRepository](https://github.com/baumroll0928-spec/myRepository)
- **Directory:** <https://github.com/baumroll0928-spec/myRepository/tree/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202605/d08_Vending_Machine>
- **File:** <https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202605/d08_Vending_Machine/README.md>

---
# Vending Machine

## はじめに

この度`Vending Machine`の問題作成をさせていただきました`baumroll1234`です。

私はCTFというものにこのDaily AlpacaHackで初めて挑戦しましたが、おかげさまですっかりハマってしまいました。

C言語やPythonなどのプログラミングには多少心得があり、入りやすいところもありましたが、一方で「RSA？なにそれおいしいの？」という状態から始めました。

また、数学は得意な方なのでCrypto問題はけっこう解けたりしますが、Web問題はいまだに苦手です。

そんな私が問題作成に携わらせていただけたこと、大変光栄に思いますし、感慨深いものがあります。

さて、前置きはこれくらいにして、私の記念すべき初投稿問題のAuther's Writeupです。

※気づいたら既にたくさんの方がWriteupを投稿されていてすごく嬉しいです。全て目を通させていただきました。もう私が投稿しなくてもいいんじゃないかなとも思いました（笑）

## 問題

自販機でフラグを購入してください。
```py
class VendingMachine:
    def __init__(self):
        self.stock = 'a'*30 + 'b'*60 + 'c'*20 + 'd'*50 + 'e'*40 + 'f' # 'aaa...eeef'
        self.item_names = {
            'a': 'apple juice',
            'b': 'banana juice',
            'c': 'coke',
            'd': 'draft beer',
            'e': 'energy drink',
            'f': 'flag'
        }

    def buy(self, mark:str):
        # check choice
        if mark not in ['a', 'b', 'c', 'd', 'e']: # No 'f'? Hmm...
            print("Invalid choice.")
            return
        # check stock
        if len(self.stock) <= 0:
            print("All sold out.")
            return
        # find the location of the product
        loc = self.stock.find(mark)
        # take the product from stock
        stock_list = list(self.stock)
        item = stock_list.pop(loc)
        self.stock = ''.join(stock_list)
        # dispense the product
        name = self.item_names[item]
        print(f"You bought {name}.")
        if item == 'f':
            print(f"Flag:", FLAG)
        else:
            print("Thank you!")
```

## 概要

実行すると、自販機のメニューが表示されます。
```
Please select an item.
----------------
a: apple juice
b: banana juice
c: coke
d: draft beer
e: energy drink
f: flag
x: exit
----------------
your choice>
```

入力を求められるので、`a`や`b`などの記号を入力すると、メニュー上で対応する商品を購入することができます。（代金等については気にしなくてよさそうです。）
```
your choice> a
You bought apple juice.
Thank you!
```

フラグを購入して取得するには`f`を入力する必要があるようですが、なぜか`f`は入力チェックが受け付けてくれないようになっています。
```
your choice> f
Invalid choice.
```

どうすればフラグを購入することができるのでしょうか？

## 方針

Pythonの`find`関数と`pop`関数の意外な性質を利用する。

## 解法

`VendingMachine`クラスの`buy`関数をみると、下記のような処理をしていることがわかります。

* 入力チェック：入力した記号が`a`,`b`,`c`,`d`,`e`のいずれかであるかチェックし、そうでない場合はその旨のメッセージを表示して終了する。
* 在庫数チェック：在庫全体の残数をチェックし、空の場合はその旨のメッセージを表示して終了する。
* 商品検索：入力した記号が在庫内に最初に現れる位置を`find`関数で検索する。
* 商品取り出し：在庫からその位置の文字を取り出す。（在庫の文字列をリストに変換し、`pop`関数で取り出した後、残ったリストの要素を結合して文字列に戻す。）
* 商品排出：取り出した商品が`f`であった場合はフラグを表示する。

このうち、`find`関数と`pop`関数の挙動がこの問題のネックになります。

Pythonの`find`関数は、文字列の中から引数の文字列を探して最初に一致する位置のインデックスを返す関数ですが、存在しない文字列を探そうとすると、エラーを発生させたりすることなく黙って`-1`を返します。
```py
text = "The Daily AlpacaHack Challenge"
print(text.find("Alpaca")) # 10
print(text.find("Llama"))  # -1
```

また、`pop`関数は、インデックスを指定してリストの要素を削除しその要素を返す関数ですが、インデックスに負の値を渡すと後ろからの順番で指定されます。この場合もやはりエラーは発生しません。（ただし、正数でも負数でも反対端をはみだした場合は`IndexError`が発生します。）
```py
text = "The Daily AlpacaHack Challenge"
parts = text.split()
print(parts)       # ['The', 'Daily', 'AlpacaHack', 'Challenge']
item = parts.pop(1)
print(parts, item) # ['The', 'AlpacaHack', 'Challenge'] Daily
item = parts.pop(-1)
print(parts, item) # ['The', 'AlpacaHack'] Challenge
```

在庫の初期状態をみると、フラグを意味する`f`は一番後ろに置かれています。

つまり、在庫に存在しない商品の記号を指定することで、`find`関数が返してきた`-1`が`pop`関数に渡されることになり、一番後ろにあるフラグを購入することができます。

ところが、購入が許可されるのは`a`,`b`,`c`,`d`,`e`のみであり、`g`などの関係ない記号を使って購入することはできません。

しかし、これらの記号であっても同じ商品を何度も繰り返し購入し続ければ、いずれその商品は在庫が尽き、存在しない記号になるので、`find`関数に`-1`を返させることができます。

在庫数チェックは行っていますが、このチェックは全商品の合計在庫数の確認にすぎず、個別の商品の在庫切れについては検知しません。

例えば一番少ない`c`の在庫は20個なので、`c`を21回購入しようとすると、21回目にフラグを取得できることになります。

これくらいなら手動で解いた方が早いような気がしなくもないですが、ソルバーを組みたい場合は下記のようになります。
```py
import pwn

HOST, PORT = "34.170.146.252", 30573
p = pwn.remote(HOST, PORT)

for _ in range(21):
    p.sendlineafter(b'choice> ', b'c')

d = p.recvuntil(b'choice> ')
print(d.decode())
```

## おわりに

Pythonの関数の仕様から抜け道をみつける今回の問題、お楽しみいただけましたでしょうか？

余談になりますが、実はこの問題、私自身の過去にあった実際のミスから着想を得ています。

そのときは`pop`関数ではなく`ch = self.stock[loc]`のような形の参照でしたが、同様の現象が起こります。

文字が存在しないのにまるで存在するかのように振舞いしれっと違う文字を取り出してくるの、ちょっと怖いですよね。

前述のとおり`find`関数は文字列がみつからないときのエラーを吐かないので、`try` - `except`では拾うことができません。

よって、もしきちんと防ぎたいのであれば、下記のように修正する必要があります。
```py
        # Find the location of the product.
        loc = self.stock.find(mark)
        if loc < 0:
            print("The product is sold out.")
            return
```

あと、ついさっき気づいたのですが、フラグ出力部分

```py
            print(f"Flag:", FLAG)
```

は、間違いではないけど間違っていますね（？）

`{...}`で置き換えをしていないので、`f"Flag:"`の`f`は不要でした。ちょっとお恥ずかしいです。
