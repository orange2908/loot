---
title: "Anyrunner - AlpacaHack Daily"
category: "web"
subcategory: "web"
type: "writeup"
tags: ["web", "alpacahack", "anyrunner", "web-exploitation", "alpacahack-daily", "daily"]
summary: "web writeup for \"Anyrunner\" from AlpacaHack Daily - techniques: alpacahack, anyrunner, web-exploitation, alpacahack-daily, daily."
source:
  name: "baumroll0928-spec/myRepository"
  url: "https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202607/d30_Anyrunner/README.md"
ctf:
  name: "AlpacaHack Daily"
  year: 2026
  challenge: "Anyrunner"
---

## Source

- **CTF:** AlpacaHack Daily
- **Challenge:** Anyrunner
- **Date:** 2026-07-30
- **Repository:** [baumroll0928-spec/myRepository](https://github.com/baumroll0928-spec/myRepository)
- **Directory:** <https://github.com/baumroll0928-spec/myRepository/tree/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202607/d30_Anyrunner>
- **File:** <https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202607/d30_Anyrunner/README.md>

---
# Anyrunner

## 問題

distroless ── cat すら存在しない世界。

```java
import java.io.*;
import java.net.*;

class Server {
    public static void main(String[] args) throws Exception {
        try (var listener = new ServerSocket(1337)) {
            while (true) {
                try (var connection = listener.accept()) {
                    var output = connection.getOutputStream();
                    output.write("$ ".getBytes());

                    var line = new BufferedReader(new InputStreamReader(connection.getInputStream())).readLine();
                    if (line == null || line.isBlank()) continue;

                    try {
                        var process = new ProcessBuilder(line.strip().split("\\s+"))
                            .redirectErrorStream(true).start();
                        process.getOutputStream().close();
                        process.getInputStream().transferTo(output);
                        if (process.waitFor() != 0) output.write("Error\n".getBytes());
                    } catch (Exception exception) {
                        output.write("Error\n".getBytes());
                    }
                } catch (Exception ignored) {}
            }
        }
    }
}

```

## 概要

実行するとコマンドの入力を求められ、それが実行されるようになっているようです。

ただ、問題文に示されているとおり、`cat`をはじめとしたいつも使っているようなコマンドが全然使えなくなっています。

フラグは/flag.txtにあるようですが、どうすればフラグを取得できるのでしょうか？

## 解法

問題文のとおり、
```
$ cat /flag.txt
Error
```
のみならず、
```
$ ls
Error
```
も、
```
$ pwd
Error
```
もなにもかもエラーになってしまいます。

これは、Dockerfileで
```
FROM gcr.io/distroless/java25-debian13@sha256:73f2263db8defa233004a7c700fd81e25c8747a530c413bddf74367b68663468
```
となっているように、Javaアプリの実行に必要な最低限のものしか入っていないdistrolessイメージが使われているからですね。

しかし、そんなcatすら存在しない世界にも1つだけ使えそうなコマンドがあります。

それは
```
java
```
です。

試しに
```
java --version
```
としたところ、
```
$ java --version
openjdk 25.0.3 2026-04-21 LTS
OpenJDK Runtime Environment Temurin-25.0.3+9 (build 25.0.3+9-LTS)
OpenJDK 64-Bit Server VM Temurin-25.0.3+9 (build 25.0.3+9-LTS, mixed mode, sharing)
```
のようにバージョン情報が出たので、使えそうです。

このjavaコマンドを使ってフラグを取得することはできないでしょうか？

すぐに思いつくのは
```
java /flag.txt
```
ですが、これだと
```
$ java /flag.txt
Error: Could not find or load main class .flag.txt
Caused by: java.lang.ClassNotFoundException: /flag/txt
Error
```
のようになってしまい、flag.txtの内容はわかりませんでした。

なんとかしてflag.txtの内容を使って実行したいところです。

調べてみると、
```
java @ファイル名
```
のように`@`をつけると引数ファイルを指定して実行できることがわかりました。

よって、
```
java @/flag.txt
```
とすると、
```
java Alpaca{REDACTED}
```
を実行しようとするので、
```
$ java @/flag.txt
Error: Could not find or load main class Alpaca{REDACTED}
Caused by: java.lang.ClassNotFoundException: Alpaca{REDACTED}
Error
```
のように、エラーメッセージからフラグを取得することができました。

## 補足

ちょっと気になったので調べてみたのですが、従来は、例えば、

Hello.java
```java
public class Hello {
    public static void main(String[] args) {
        String name = (args.length > 0) ? args[0] : "world";
        System.out.println("Hello, " + name + "!");
    }
}
```
を実行するために、
```
javac Hello.java
java Hello alpaca
```
のように、コンパイル・実行という2段階を踏まなければいけませんでした。

これが、Java 11からは、
```
java Hello.java alpaca
```
で一発で実行までできるようになったようです。

また、今回でてきた`@`の引数ファイルについてですが、

args.txt
```
Hello.java
alpaca
```
として
```
java @args.txt
```
を実行すると、同じようにHello.javaを実行することができました。
