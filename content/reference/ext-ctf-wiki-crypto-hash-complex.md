---
title: "Complex - 综合题目 (CTF Wiki)"
category: "crypto"
subcategory: "hash"
type: "reference"
tags: ["ctf-wiki", "crypto", "rsa", "sage", "xor", "base64", "hash", "complex", "chinese", "zh"]
summary: "可以看出，程序的大概意思是上传一个 zip 压缩包，然后对 signeddata 目录下的文件进行签名验证。其中，最后验证的手法是大概是将每一个文件进行 sha256 哈希，然后异或起来作为输入传递给 rsa 进行签名。如果通过验证的话，就会执行对应的 pre-copy.py 和 post-copy.py 文件。"
source:
  name: "CTF Wiki"
  url: "https://github.com/ctf-wiki/ctf-wiki/blob/e225ddfcd420a7f54a5940f47336ebdf8c29b875/docs/zh/docs/crypto/hash/complex.md"
license: "CC BY-NC-SA 4.0"
---

# 综合题目

## 2017 34c3 Software_update

可以看出，程序的大概意思是上传一个 zip 压缩包，然后对 signed_data 目录下的文件进行签名验证。其中，最后验证的手法是大概是将每一个文件进行 sha256 哈希，然后**异或**起来作为输入传递给 rsa 进行签名。如果通过验证的话，就会执行对应的 pre-copy.py 和 post-copy.py 文件。

很自然的想法是我们修改 pre-copy.py 或者 post-copy.py 文件，使其可以读取 flag，然后再次绕过签名即可。主要有两种思路

1. 根据给定的公钥文件获取对应的私钥，进而再修改文件后伪造签名，然后大概看了看公钥文件几乎不可破，所以这一点，基本上可以放弃。
2. 修改对应文件后，利用**异或的特性使得其哈希值仍然与原来相同**，从而绕过签名检测。即使得 signed_data 目录下包含多个文件，使得这些文件的哈希值最后异或起来可以抵消修改 pre-copy.py 或者 post-copy.py文件所造成的哈希值的不同。

这里，我们选择第二种方法，这里我们选择修改 pre-copy.py 文件，具体思路如下

1. 计算 pre-copy.py 的原 hash 值。
2. 修改 pre-copy.py 文件，使其可以读取 flag。与此同时，计算新的 hash 值。将两者异或，求得异或差值 delta。
3. 寻找一系列的文件，使其 hash 值异或起来正好为 delta。

关键的步骤在于第三步，而其实这个文件可以看做是一个线性组合的问题，即寻找若干个 256 维01向量使其异或值为 delta。而 
$$
(F=\{0,1\},F^{256},\oplus ,\cdot)
$$
是一个 256 维的向量空间。如果我们可以求得该向量空间的一个基，那么我们就可以求得该空间中任意指定值的所需要的向量。

我们可以使用 sage 来辅助我们求，如下
```python
# generage the base of <{0,1},F^256,xor,*>
def gen_gf2_256_base():
    v = VectorSpace(GF(2), 256)
    tmphash = compute_file_hash("0.py", "")
    tmphash_bin = hash2bin(tmphash)
    base = [tmphash_bin]
    filelist = ['0.py']
    print base
    s = v.subspace(base)
    dim = s.dimension()
    cnt = 1
    while dim != 256:
        tmpfile = str(cnt) + ".py"
        tmphash = compute_file_hash(tmpfile, "")
        tmphash_bin = hash2bin(tmphash)
        old_dim = dim
        s = v.subspace(base + [tmphash_bin])
        dim = s.dimension()
        if dim > old_dim:
            base += [tmphash_bin]
            filelist.append(tmpfile)
            print("dimension " + str(s.dimension()))
        cnt += 1
        print(cnt)
    m = matrix(GF(2), 256, 256, base)
    m = m.transpose()
    return m, filelist
```

关于更加详细的解答，请参考 `exp.py`。

这里我修改 pre-copy 多输出  `!!!!come here!!!!` 字眼，如下
```shell
➜  software_update git:(master) python3 installer.py now.zip
Preparing to copy data...
!!!!come here!!!!
Software update installed successfully.
```

参考文献

- https://sectt.github.io/writeups/34C3CTF/crypto_182_software_update/Readme
- https://github.com/OOTS/34c3ctf/blob/master/software_update/solution/exploit.py

## 2019 36c3 SaV-ls-l-aaS

这个题的分类是 Crypto&Web，捋一下流程：

60601端口开着一个Web服务，题目描述给了连接方法：
```bash
url='http://78.47.240.226:60601' && ip=$(curl -s "$url/ip") && sig=$(curl -s -d "cmd=ls -l&ip=$ip" "$url/sign") && curl --data-urlencode "signature=$sig" "$url/exec"
```

可以看到，先是访问 `/ip` 得到 ip，再向 `/sign` post 过去 ip 和我们要执行的命令，得到签名，最后向 `/exec` post signature 来执行命令。我们执行这一行可以发现回显了`ls -l`执行的结果，发现有个 flag.txt。

看源码，Web 服务是由 go 起的：
```go
package main

import (
	"bytes"
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

func main() {
	m := http.NewServeMux()

	m.HandleFunc("/ip", func(w http.ResponseWriter, r *http.Request) {
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			return
		}
		fmt.Fprint(w, ip)
	})

	m.HandleFunc("/sign", func(w http.ResponseWriter, r *http.Request) {
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			return
		}
		remoteAddr := net.ParseIP(ip)
		if remoteAddr == nil {
			return
		}

		ip = r.PostFormValue("ip")
		signIP := net.ParseIP(ip)
		if signIP == nil || !signIP.Equal(remoteAddr) {
			fmt.Fprintln(w, "lol, not ip :>")
			return
		}

		cmd := r.PostFormValue("cmd")
		if cmd != "ls -l" {
			fmt.Fprintln(w, "lol, nope :>")
			return
		}

		msg := ip + "|" + cmd
		digest := sha1.Sum([]byte(msg))

		b := new(bytes.Buffer)
		err = json.NewEncoder(b).Encode(string(digest[:]))
		if err != nil {
			return
		}

		resp, err := http.Post("http://127.0.0.1/index.php?action=sign", "application/json; charset=utf-8", b)
		if err != nil || resp.StatusCode != 200 {
			fmt.Fprintln(w, "oops, hsm is down")
			return
		}

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			fmt.Fprintln(w, "oops, hsm is bodyless?")
			return
		}

		var signature string
		err = json.Unmarshal(body, &signature)
		if err != nil {
			fmt.Fprintln(w, "oops, hsm is jsonless?")
			return
		}

		fmt.Fprint(w, signature+msg)
	})

	m.HandleFunc("/exec", func(w http.ResponseWriter, r *http.Request) {
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			return
		}
		remoteAddr := net.ParseIP(ip)
		if remoteAddr == nil {
			return
		}

		signature := r.PostFormValue("signature")
		digest := sha1.Sum([]byte(signature[172:]))

		b := new(bytes.Buffer)
		err = json.NewEncoder(b).Encode(signature[:172] + string(digest[:]))
		if err != nil {
			fmt.Fprintln(w, "oops, json encode")
			return
		}

		resp, err := http.Post("http://127.0.0.1/index.php?action=verify", "application/json; charset=utf-8", b)
		if err != nil || resp.StatusCode != 200 {
			fmt.Fprintln(w, "oops, hsm is down?")
			return
		}

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			fmt.Fprintln(w, "oops, hsm is bodyless?")
			return
		}

		var valid bool
		err = json.Unmarshal(body, &valid)
		if err != nil {
			fmt.Fprintln(w, "oops, json unmarshal")
			return
		}

		if valid {
			t := strings.Split(signature[172:], "|")
			if len(t) != 2 {
				fmt.Fprintln(w, "oops, split")
			}

			signIP := net.ParseIP(t[0])
			if signIP == nil || !signIP.Equal(remoteAddr) {
				fmt.Fprintln(w, "lol, not ip :>")
				return
			}

			conn, err := net.DialTimeout("tcp", "127.0.0.1:1024", 1*time.Second)
			if err != nil {
				fmt.Fprintln(w, "oops, dial")
				return
			}
			fmt.Fprintf(conn, t[1]+"\n")
			conn.(*net.TCPConn).CloseWrite()
			io.Copy(w, conn)
		}
	})

	s := &http.Server{
		Addr:           ":60601",
		Handler:        m,
		ReadTimeout:    5 * time.Second,
		WriteTimeout:   5 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}
	log.Fatal(s.ListenAndServe())
}

```

代码很容易看，限制了 cmd 只能是`ls -l`，其余不给签名，看样子我们是要伪造其他命令的签名来读flag，这里注意到签名和验签的过程是传给本地起的一个 php 来完成的，看一下这部分源码：
```php
<?php
define('ALGO', 'md5WithRSAEncryption');
$d = json_decode(file_get_contents('php://input'), JSON_THROW_ON_ERROR);

if ($_GET['action'] === 'sign'){
    $pkeyid = openssl_pkey_get_private("file:///var/www/private_key.pem");
    openssl_sign($d, $signature, $pkeyid, ALGO);
	echo json_encode(base64_encode($signature));
    openssl_free_key($pkeyid);
}
elseif ($_GET['action'] === 'verify') {
    $pkeyid = openssl_pkey_get_public("file:///var/www/public_key.pem");
    echo json_encode(openssl_verify(substr($d, 172), base64_decode(substr($d,0, 172)), $pkeyid, ALGO) === 1);
    openssl_free_key($pkeyid);
}

```

采用的是`md5WithRSAEncryption`的方式签名，本地试了一下，是把我们传入的 `$d` md5 后转为hex，填充到`0x1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff003020300c06082a864886f70d020505000410`后面，组成数字然后用RSA签名。

看样子整个逻辑找不到一点问题，用的都是标准库，基本无法攻击。有个思路是通过代理更换 ip，可以拿到两个 ip|ls -l 的签名，这样我们就拥有了两组 RSA 的 m 和 c，因为题目给了 dockerfile 给了生成公私钥的方法，使用 openssl 默认生成，e为65537，那么我们可以通过求公因数的方式来求出 n。

在得到两组签名后，我们要得到 RSA 的m，就是填充后的数，所以按照代码逻辑，在 go 里面先是 sha1:
```go
msg := ip + "|" + cmd
digest := sha1.Sum([]byte(msg))

b := new(bytes.Buffer)
err = json.NewEncoder(b).Encode(string(digest[:]))
```

再 php 里的 md5，得到两组 m 和 c，但是总是求不出公因数 n，怀疑求的 m 不对。看代码发现 go 里把 sha1的结果用 json 编码，然后传到 php里 json 解码。这部分非常可疑，为何要用 json 编码（用 hex 传过去它不香么），本地搭一下环境跟一下。（题目给了dockerfile）

起个docker，改一下 index.php，加一个`var_dump($d);`，再改一下 go，返回一下 php 的结果：
```go
fmt.Fprintln(w,string(body))
```

现在让程序签名，返回结果：
```
string(38) "	��.���?-�KC��@�"
"K4FEmxz4yuTsjDAbRZQmHJ+MBiCSGaOnpZTLbThXpCkDYe3siAIPfihX6ppjN2Tz6XqOr4tF\/u1\/+ccfhj8NNLIL+2hknyDXbosmMBV8mEGYsMqQHAE0f+3OhDWlzN5RnteSMYNZbTipFErB8ZOWCiXmynWxsqJhyaN9J6\/\/h6I="
oops, hsm is jsonless?
```

$d 竟然是长度为 38 的字符串，看来果然是这里编码有问题，我们需要看一下每个步骤的结果，先看一下 go 里 json编码后的 sha1 结果是什么：
```go
package main

import (
	"bytes"
	"crypto/sha1"
	"encoding/json"
	"fmt"
)
func main() {
	msg := "172.17.0.1|ls -l"
	digest := sha1.Sum([]byte(msg))

	b := new(bytes.Buffer)
	json.NewEncoder(b).Encode(string(digest[:]))
	fmt.Print(string(b.Bytes()));
}
```

运行一下：
```
"\u000e\t\u001d\ufffd\u0012\ufffd.\ufffd\ufffd\ufffd?-\ufffdKC\ufffd\u0005\ufffd@\ufffd"
```

和正常的sha1的结果来比较一下：
```bash
Python 2.7.16 (default, Sep  2 2019, 11:59:44)
[GCC 4.2.1 Compatible Apple LLVM 10.0.1 (clang-1001.0.46.4)] on darwin
Type "help", "copyright", "credits" or "license" for more information.
>>> "\u000e\t\u001d\ufffd\u0012\ufffd.\ufffd\ufffd\ufffd?-\ufffdKC\ufffd\u0005\ufffd@\ufffd"
'\\u000e\t\\u001d\\ufffd\\u0012\\ufffd.\\ufffd\\ufffd\\ufffd?-\\ufffdKC\\ufffd\\u0005\\ufffd@\\ufffd'
>>> from hashlib import *
>>> sha1('172.17.0.1|ls -l').digest()
'\x0e\t\x1d\xbd\x12\x90.\xca\xf0\xd9?-\x98KC\xeb\x05\xa1@\xd1'
```

由于 go 的 json 编码，很多不可见字符都被转为了 `U+fffd`，丢失了很多信息。

再经过 php 接口的接收，我们来看一下结果：
```php
$d = json_decode(file_get_contents('php://input'), JSON_THROW_ON_ERROR);
var_dump(file_get_contents('php://input'));
var_dump($d);
var_dump(bin2hex($d));
```

结果：
```
string(89) ""\u000e\t\u001d\ufffd\u0012\ufffd.\ufffd\ufffd\ufffd?-\ufffdKC\ufffd\u0005\ufffd@\ufffd"
"
string(38) "	��.���?-�KC��@�"
string(76) "0e091defbfbd12efbfbd2eefbfbdefbfbdefbfbd3f2defbfbd4b43efbfbd05efbfbd40efbfbd"
"K4FEmxz4yuTsjDAbRZQmHJ+MBiCSGaOnpZTLbThXpCkDYe3siAIPfihX6ppjN2Tz6XqOr4tF\/u1\/+ccfhj8NNLIL+2hknyDXbosmMBV8mEGYsMqQHAE0f+3OhDWlzN5RnteSMYNZbTipFErB8ZOWCiXmynWxsqJhyaN9J6\/\/h6I="
oops, hsm is jsonless?

```

`U+fffd`变成了`\xef\xbf\xbd`。所以由于 go 的 json 编码问题，丢失了很多信息，造成了 md5 前的数据有很多相同字符。当时做题时往下并没有细想，得到 n 后总是想构造出任意命令的签名，也很疑惑如果构造出岂不是这种签名就不安全了？其实是无法得到的。

正解是 go 的这种问题 ，为碰撞创造了条件。我们可以碰撞出在这种编码情况下与 `ls -l `有相同结果的`cat *` 此类命令。但是问题是我们需要非常大量 ip 来提供碰撞的数据。

可以发现，go 取 ip 的时候，是先用`net.ParseIP`解析了 ip，我们在 ip 每个数字前面加 0 ，解析后还是原来的 ip 结果，每个数字最多添加 256 个 0，四个数字就已经产生了 `2^32`种不同的组合，足以碰撞出 `ls -l `与 `cat *`之间的冲突。

官方题解的 c++ 碰撞脚本我本地编译的有点问题，加了一些引入的头文件：
```c++
// g++ -std=c++17 -march=native -O3 -lcrypto -lpthread gewalt.cpp -o gewalt

#include <cassert>
#include <iomanip>
#include <string>
#include <sstream>
#include <iostream>
#include <functional>
#include <random>
#include <unordered_map>
#include <algorithm>
#include <thread>
#include <atomic>
#include <mutex>
#include <array>
#include <openssl/sha.h>

const unsigned num_threads = std::thread::hardware_concurrency();


static std::string hash(std::string const& s)
{
    SHA_CTX ctx;
    if (!SHA1_Init(&ctx)) throw;
    if (!SHA1_Update(&ctx, s.data(), s.length())) throw;
    std::string d(SHA_DIGEST_LENGTH, 0);
    if (!SHA1_Final((uint8_t *) &d[0], &ctx)) throw;
    return d;
}

static std::u32string kapot(std::string const& s)
{
    std::u32string r(s.size(), 0);
    size_t o = 0;

    for (size_t i = 0; i < s.length(); ) {

        auto T = [](uint8_t c) {
            return (c < 0x80)         ? 1   /* ASCII */
                 : (c & 0xc0) == 0x80 ? 0   /* continuation */
                 : (c & 0xe0) == 0xc0 ? 2   /* 2-byte chunk */
                 : (c & 0xf0) == 0xe0 ? 3   /* 3-byte chunk */
                 : (c & 0xf8) == 0xf0 ? 4   /* 4-byte chunk */
                 : -1;
        };

        uint32_t c = s[i++];
        auto cont = [&]() { c = (c << 6) | (s[i++] & 0x3f); };

        switch (T(c)) {

        case -1:
        case  0:
        invalid: c = 0xfffd; /* fall through */

        case  1:
        valid:   r[o++] = c; break;

        case  2:
                 if (c &= 0x1f, i+0 >= s.size() || T(s[i+0]))
                     goto invalid;
                 goto one;

        case  3:
                 if (c &= 0x1f, i+1 >= s.size() || T(s[i+0]) || T(s[i+1]))
                     goto invalid;
                 goto two;

        case  4:
                 if (c &= 0x1f, i+2 >= s.size() || T(s[i+0]) || T(s[i+1]) || T(s[i+2]))
                     goto invalid;
                 cont();
        two:     cont();
        one:     cont();
                 goto valid;

        }

    }

    r.resize(o);

    return r;
}

std::atomic<uint64_t> hcount = 0, kcount = 0;
typedef std::unordered_map<std::u32string, std::string> tab_t;
tab_t tab0, tab1;
std::mutex mtx;

std::array<uint8_t,4> ip;
std::string cmd0, cmd1;

class stuffer_t
{
    private:
        std::array<size_t,4> cnts;
        size_t step;
        std::string cmd;
    public:
        stuffer_t(size_t t, size_t s, std::string c) : cnts{t}, step(s), cmd(c) {}
        std::string operator()()
        {
            //XXX this is by far not the most efficient way of doing this, but yeah
            if (++cnts[3] >= cnts[0]) {
                cnts[3] = 0;
                if (++cnts[2] >= cnts[0]) {
                    cnts[2] = 0;
                    if (++cnts[1] >= cnts[0]) {
                        cnts[1] = 0;
                        cnts[0] += step;
                    }
                }
            }
            std::stringstream o;
            for (size_t i = 0; i < 4; ++i)
                o << (i ? "." : "")
                  << std::string(cnts[i], '0')
                  << (unsigned) ip[i];
            o << "|" << cmd;
            return o.str();
        }
};

void go(size_t tid)
{
    //XXX tid stuff is a hack, but YOLO

    bool one = tid & 1;

    stuffer_t next(tid >> 1, (num_threads + 1) >> 1, one ? cmd1 : cmd0);

    tab_t& mytab = one ? tab1 : tab0;
    tab_t& thtab = one ? tab0 : tab1;

    uint64_t myhcount = 0, mykcount = 0;

    while (1) {

        std::string r = next();

        {

            ++myhcount;

            auto h = hash(r);
            if ((h.size()+3)/4 < (size_t) std::count_if(h.begin(), h.end(),
                                            [](unsigned char c) { return c < 0x80; }))
                continue;

            ++mykcount;

            auto k = kapot(h);
            if (k.size() > 3 + (size_t) std::count(k.begin(), k.end(), 0xfffd))
                continue;

            std::lock_guard<std::mutex> lck(mtx);

            hcount += myhcount, myhcount = 0;
            kcount += mykcount, mykcount = 0;

            if (thtab.find(k) != thtab.end()) {

                mytab[k] = r;

                std::cerr << "\r\x1b[K"
                          << "\x1b[32m";
                std::cout << tab0[k] << std::endl
                          << tab1[k] << std::endl;
                std::cerr << "\x1b[0m";

                std::cerr << std::hex;
                bool first = true;
                for (uint32_t c: k)
                    std::cerr << (first ? first = false, "" : " ") << c;
                std::cerr << std::endl;

                std::cerr << std::dec << "hash count:  \x1b[35m" << hcount << "\x1b[0m";
                {
                    std::stringstream s;
                    s << std::fixed << std::setprecision(2) << log(hcount|1)/log(2);
                    std::cerr << " (2^\x1b[35m" << std::setw(5) << s.str() << "\x1b[0m" << ")" << std::endl;
                }
                std::cerr << "kapot count: " << "\x1b[35m" << kcount << "\x1b[0m";
                {
                    std::stringstream s;
                    s << std::fixed << std::setprecision(2) << log(kcount|1)/log(2);
                    std::cerr << " (2^\x1b[35m" << std::setw(5) << s.str() << "\x1b[0m)" << std::endl;
                }
                std::cerr << "table sizes: \x1b[35m"
                          << tab0.size() << "\x1b[0m \x1b[35m"
                          << tab1.size() << "\x1b[0m" << std::endl;

                exit(0);

            }

            if (mytab.size() < (1 << 20))
                mytab[k] = r;

        }

        hcount += myhcount;
        kcount += mykcount;

    }
}

void status()
{
    while (1) {

        {
            std::lock_guard<std::mutex> lck(mtx);

            std::cerr << "\r\x1b[K";
            std::cerr << "hash count: \x1b[35m" << std::setw(12) << hcount << "\x1b[0m ";
            {
                std::stringstream s;
                s << std::fixed << std::setprecision(2) << log(hcount|1)/log(2);
                std::cerr << "(2^\x1b[35m" << std::setw(5) << s.str() << "\x1b[0m) | ";
            }
            std::cerr << "kapot count: \x1b[35m" << std::setw(12) << kcount << "\x1b[0m ";
            {
                std::stringstream s;
                s << std::fixed << std::setprecision(2) << log(kcount|1)/log(2);
                std::cerr << "(2^\x1b[35m" << std::setw(5) << s.str() << "\x1b[0m) | ";
            }
            std::cerr << "tables: \x1b[35m"
                      << std::setw(9) << tab0.size() << " "
                      << std::setw(9) << tab1.size() << "\x1b[0m "
                      << std::flush;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

int main(int argc, char **argv)
{

    if (argc < 2) {
        std::cerr << "\x1b[31mneed IPv4 in argv[1]\x1b[0m" << std::endl;
        exit(1);
    }
    {
        std::stringstream ss(argv[1]);
        for (auto& v: ip) {
            std::string s;
            std::getline(ss, s, '.');
            int n = std::atoi(s.c_str());
            if (n < std::numeric_limits<uint8_t>::min() || n > std::numeric_limits<uint8_t>::max())
                goto bad_ip;
            v = n;
        }
        if (!ss) {
bad_ip:
            std::cerr << "\x1b[31mbad IPv4 given?\x1b[0m" << std::endl;
            exit(2);
        }
    }


    if (argc < 4) {
        std::cerr << "\x1b[31mneed commands in argv[2] and argv[3]\x1b[0m" << std::endl;
        exit(2);
    }
    cmd0 = argv[2];
    cmd1 = argv[3];


    std::thread status_thread(status);
    std::vector<std::thread> ts;
    for (unsigned i = 0; i < num_threads; ++i)
        ts.push_back(std::thread(go, i));
    for (auto& t: ts)
        t.join();

}


```

编译可能会找不到 `lcrypto`，编译命令加上 lcrypto 路径（我本地是 /usr/local/opt/openssl/lib）
```bash
g++ -std=c++17 -march=native -O3 -lcrypto -lpthread gewalt.cpp -o gewalt -L/usr/local/opt/openssl/lib
```

与 go 交互的脚本：
```python
#!/usr/bin/env python3
import sys, requests, subprocess

benign_cmd = 'ls -l'
exploit_cmd = 'cat *'

ip, port = sys.argv[1], sys.argv[2]
url = 'http://{}:{}'.format(ip, port)

my_ip = requests.get(url + '/ip').text
print('[+] IP: ' + my_ip)

o = subprocess.check_output(['./gewalt', my_ip, benign_cmd, exploit_cmd])
print('[+] gewalt:' + o.decode())

payload = {}
for l in o.decode().splitlines():
    ip, cmd = l.split('|')
    payload['benign' if cmd == benign_cmd else 'pwn'] = ip, cmd

print(payload)

sig  = requests.post(url + '/sign', data={'ip': payload['benign'][0], 'cmd': payload['benign'][1]}).text
print('[+] sig: ' + sig)

r = requests.post(url + '/exec', data={'signature': sig[:172] + payload['pwn'][0]  + '|' + payload['pwn'][1]})
print(r.text)
```
```bash
 ⚙  SaV-ls-l-aaS  python solve.py 127.0.0.1 60601
[+] IP: 172.17.0.1
fffd fffd fffd fffd fffd fffd 55 fffd fffd fffd fffd c fffd fffd fffd fffd fffd fffd fffd fffd
hash count:  168104875 (2^27.32)
kapot count: 3477222 (2^21.73)
table sizes: 8745 8856
[+] gewalt:00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000172.000000000000000000000000000000000000000000000000000000000000000000000000000000000000000017.000000000000000000000000000000000000000000000000000000000000000000000000000000000.00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001|ls -l
00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000172.17.000000000000000000000000.0000000000000000000000000000000000000001|cat *

{'pwn': (u'00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000172.17.000000000000000000000000.0000000000000000000000000000000000000001', u'cat *'), 'benign': (u'00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000172.000000000000000000000000000000000000000000000000000000000000000000000000000000000000000017.000000000000000000000000000000000000000000000000000000000000000000000000000000000.00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001', u'ls -l')}
[+] sig: ODxSukwtu4rHICBpzT23WGD7DCJNawhA0DUN/tcyv1AgwNmS8OPUnO5FnBBDgiaVx5OTYd4OjH8LVbKiXUBUBuFx1OHDgKBKG5umkKMLt+350SlgMWY5qWny9tPIU3I+X0A9FcADCBCi6f0PkXfc0CSCZXuFu9rAKnVGsbmaUwY=00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000172.000000000000000000000000000000000000000000000000000000000000000000000000000000000000000017.000000000000000000000000000000000000000000000000000000000000000000000000000000000.00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001|ls -l
hxp{FLAG}
```

参考：

- https://ctftime.org/writeup/17966

---

## Source

CTF Wiki - <https://github.com/ctf-wiki/ctf-wiki/blob/e225ddfcd420a7f54a5940f47336ebdf8c29b875/docs/zh/docs/crypto/hash/complex.md>

Mirrored into CTF-Brain at commit `e225ddfcd420`. Licence: CC BY-NC-SA 4.0. The text is the original authors' work.
