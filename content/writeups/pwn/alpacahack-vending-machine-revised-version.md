---
title: "Vending Machine Revised Version - AlpacaHack Daily"
category: "pwn"
subcategory: "pwn"
type: "writeup"
tags: ["pwn", "alpacahack", "vending", "machine", "revised", "version"]
summary: "pwn writeup for \"Vending Machine Revised Version\" from AlpacaHack Daily - techniques: alpacahack, vending, machine, revised, version."
source:
  name: "baumroll0928-spec/myRepository"
  url: "https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202609/d05_Vending_Machine_Revised_Version/README.md"
ctf:
  name: "AlpacaHack Daily"
  year: 2026
  challenge: "Vending Machine Revised Version"
---

## Source

- **CTF:** AlpacaHack Daily
- **Challenge:** Vending Machine Revised Version
- **Date:** 2026-09-05
- **Repository:** [baumroll0928-spec/myRepository](https://github.com/baumroll0928-spec/myRepository)
- **Directory:** <https://github.com/baumroll0928-spec/myRepository/tree/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202609/d05_Vending_Machine_Revised_Version>
- **File:** <https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202609/d05_Vending_Machine_Revised_Version/README.md>

---
# Vending Machine: Revised Version

## はじめに

あの`Vending Machine`が、新たなバグを携えて帰ってきました。

というわけで、今回の私の作成問題は、初投稿問題の続編となっております。

初めて作成させていただいた問題であることもあって、私にとってこの問題にはかなり思い入れがありました。

そんな問題の続編を出すことができて嬉しい限りです。

## 問題

[Vending Machine](https://alpacahack.com/daily/challenges/vending-machine)で、特定の条件下においてお客様が意図しない商品を提供してしまう不具合を修正しました。ご迷惑をおかけしてしまい申し訳ありません。

（注意）この問題には`Vending Machine`のネタバレが含まれるため、なるべくこちらを先に解くことをおすすめします。
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
# 2026.09.05 Cleaned up the implementation ------------------------- MOD Start
#        if mark not in ['a', 'b', 'c', 'd', 'e']: # No 'f'? Hmm...
# ------------------------------------------------------------------
        if 'abcde'.find(mark) < 0: # No 'f'? Hmm...
# 2026.09.05 Cleaned up the implementation ------------------------- MOD End
            print("Invalid choice.")
            return
        # check stock
        if len(self.stock) <= 0:
            print("All sold out.")
            return
        # find the location of the product
        loc = self.stock.find(mark)
# 2026.09.05 Fixed a bug ------------------------------------------- ADD Start
        if loc < 0:
            print("The product is sold out.")
            return
# 2026.09.05 Fixed a bug ------------------------------------------- ADD End
        # take the product from stock
        stock_list = list(self.stock)
        item = stock_list.pop(loc)
        self.stock = ''.join(stock_list)
        # dispense the product
        name = self.item_names[item]
        print(f"You bought {name}.")
        if item == 'f':
# 2026.09.05 Fixed a minor mistake --------------------------------- MOD Start
#            print(f"Flag:", FLAG)
# ------------------------------------------------------------------
            print(f"Flag: {FLAG}")
# 2026.09.05 Fixed a minor mistake --------------------------------- MOD End
        else:
            print("Thank you!")
```

## 概要

[Vending Machine](https://github.com/baumroll0928-spec/myRepository/tree/main/Daily_AlpacaHack/m202605/d08_Vending_Machine)の関連問題です。

ソースコードの`buy`関数の中の`2026.09.05`の日付で修正履歴コメントがついている部分が今回の修正箇所です。

前回の失敗を踏まえ、個別の商品の在庫切れチェックをきちんと行っているようです。

```py
        # find the location of the product
        loc = self.stock.find(mark)
# 2026.09.05 Fixed a bug ------------------------------------------- ADD Start
        if loc < 0:
            print("The product is sold out.")
            return
# 2026.09.05 Fixed a bug ------------------------------------------- ADD End
```

この修正自体は適切であり、前回利用できていたバグは潰されてしまいましたが、今回はどうやってフラグを購入すればいいのでしょうか？

## 解法

今回の修正で、`pop`関数に`-1`を渡してフラグを購入する方法は使えなくなっているようです。

しかし、ソースコードをよく見ると、その修正の他にも変更箇所があることがわかります。

それは、フラグの`f`やその他の関係ない記号の入力を弾く入力チェックの部分です。

Befure:
```py
        if mark not in ['a', 'b', 'c', 'd', 'e']: # No 'f'? Hmm...
```
After:
```py
        if 'abcde'.find(mark) < 0: # No 'f'? Hmm...
```

`find`関数のことがわかったつもりになって、よりスマートに書いてみたくなってしまったようですね。

※ちなみに最後のやつはホントのミスなので気にしないでください（笑）

この書き方だと、`mark`が`ab`や`bcd`などでもチェックを通ってしまいます。

しかし、いずれにしても`f`を含めることはできないうえに、`find`関数が返すのは在庫の中から最初に見つけた`mark`の先頭にあたる位置なので、その点についてはこの場面では大した問題ではなさそうです。

この入力チェックの書き方の最大の欠陥は、**空文字列を通してしまう**点にあります。
```py
text = "The Daily AlpacaHack Challenge"
print(text.find("Alpaca")) # 10
print(text.find("Llama"))  # -1
print(text.find(""))       # 0
```

このように、`mark`が空文字列のとき、`'abcde'.find(mark)`は`0`を返すので、`'abcde'.find(mark) < 0`は`False`になってしまい、入力チェックを通過してしまいます。

空文字列が入力チェックを通過し、今回追加された個別在庫チェックまで到達するとどうなるでしょうか？
```py
        # find the location of the product
        loc = self.stock.find(mark)
        if loc < 0:
            print("The product is sold out.")
            return
```
この`find`関数も`0`を返すので、個別在庫チェックも通過してしまいます。

あとはどうなるかおわかりでしょう。
```py
        item = stock_list.pop(loc)
```
によって、`pop`関数には在庫の状態にかかわらず必ず`0`が渡され、常に先頭の商品が取り出されます。

したがって、`f`以外の商品を全て買い尽くしたあと、空文字列を入力（何も入れずにエンターキーだけ押下）すれば、フラグを得ることができます。

ただ、いちいち回数を数えながら商品の記号を入力するのは面倒くさいので、空文字列を201回入力する、すなわちエンターキーを201回連打するだけの脳筋ゲームをプレイしても解くことができます。

※エンターキーを押しっぱなしでもいけそう。

または、下記のようなソルバーを組むと良いでしょう。
```py
import pwn

HOST, PORT = "34.170.146.252", 45305
p = pwn.remote(HOST, PORT)

for _ in range(201):
    p.sendlineafter(b'choice> ', b'')

d = p.recvuntil(b'choice> ')
print(d.decode())
```

あと、前回の[他の方のWriteup](https://github.com/nozokare/my-alpaca-ctf/tree/main/2026-05/08-daily-vending-machine)を見て知ったのですが、Linuxには同じ文字列をひたすら打ち続ける`yes`コマンドというのがあって、これを使うとこんなシンプルな解き方もできます。
```
$ yes '' | head -n 201 | nc 34.170.146.252 45305
```

## おわりに

バグを直すだけでなく余計なことをした結果、新たなバグを生んでしまったというシナリオの今回の問題、いかがでしたでしょうか？

今回の修正方法としては、
```py
        if len(mark) != 1 or 'abcde'.find(mark) < 0:
```
のように`mark`の文字数を1文字に限定するか、いっそのこともとのホワイトリスト方式に戻すかのどちらかになると思います。

ちなみに、`mark`が空文字列のとき、`mark in ['a','b','c','d','e']`は`False`ですが、`mark in 'abcde'`は`True`になるので気を付けましょう。

今回の問題をもって`Vending Machine`シリーズは最終回となる予定ですが、また面白そうなバグを思いついたら出すかもしれませんので、あまり期待せずにお待ちください。
