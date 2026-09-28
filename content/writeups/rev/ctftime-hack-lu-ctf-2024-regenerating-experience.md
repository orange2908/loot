---
title: "REGenerating EXperience - Hack.lu CTF 2024"
category: "rev"
subcategory: "dotnet"
type: "writeup"
tags: [".net", "regex", "rev", "dotnet", "wordpress", "hack-lu-ctf", "hack-lu-ctf-2024", "2024", "ctf-writeup"]
summary: "For the full experience with images and videos see the original blog post!"
source:
  name: "CTFtime writeup #39631"
  url: "https://ctftime.org/writeup/39631"
original_source: "https://ik0ri4n.de/hacklu-24-regex"
ctf:
  name: "Hack.lu CTF 2024"
  year: 2024
  challenge: "REGenerating EXperience"
---

## Metadata

- **CTF:** Hack.lu CTF 2024
- **Task:** REGenerating EXperience
- **Author team:** KITCTF
- **CTFtime tags:** .net, regex, rev
- **CTFtime:** <https://ctftime.org/writeup/39631>
- **Original writeup:** <https://ik0ri4n.de/hacklu-24-regex>

---
*For the full experience with images and videos see the original blog post!*

I was knee-deep into [Hack.lu](http://Hack.lu)'s `Getting into Shape` reversing challenge and fighting with some particularly interesting tooling errors,  
when a team member notified us about a new batch of challenges including a reversing challenge.

Release announcement of new challenge batch

The title hinted heavily at the use of regular expressions which sounded interesting.  
Now, at that point I didn't know how they were used of course, but I needed something refreshing just like that to clear my head.  
Of course, solving the challenge took a bit more time than I initially expected...

## REGenerating EXperience

The challenge handout contains a single file, `REGenerating-EXperience.dll`, which, according to `file`, contains Mono/.Net assembly.  
One initial thing I always try when working with .NET applications is extracting as much information as possible with available tools  
because DLLs often contain a lot of that.  
JetBrains' decompiler [dotPeek](<https://www.jetbrains.com/decompiler/>) is free and one of the best tools I know for the purpose.  
Sadly, the tool only runs on Windows, so a nice teammate helped me out and sent me the tools output.  
However, since October 16, JetBrain's cross-platform .NET IDE [Rider](<https://www.jetbrains.com/rider/>) has become free for non-commercial use  
and is thus the better choice unless you are low on disk space or working on commercial projects.  
There are similar tools with partial or full cross-platform support too, in case you want to try that.  
I have used [AvaloniaILSpy](<https://github.com/icsharpcode/AvaloniaILSpy>), the cross-platform UI of [ILSpy](<https://github.com/icsharpcode/ILSpy>),  
with other challenges, for example.

## Analyzing the program

The decompiler output of the main program looks as follows:

> WARNING: The blog's current markdown parser has some issues, especially with backslashes. I included an archive with scripts and resources for download above.

```csharp  
// Decompiled with JetBrains decompiler  
// Type: REGenerating_EXperience.Program  
// Assembly: REGenerating-EXperience, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null  
// MVID: [Redacted UUID]  
// Assembly location: [Redacted]\REGenerating-EXperience.dll

using System;  
using System.Collections.Generic;  
using System.Linq;  
using System.Text;  
using System.Text.RegularExpressions;

#nullable enable  
namespace REGenerating_EXperience  
{  
public class Program  
{  
private static readonly Regex RuneAlchemist = new Regex("(?=(?<Q>.*?(?<F>[lLuY7DGbtSHTP])))\\\A(?:(?:(?_)(? <=\\\A(?=\\\k<Q>(?<=[Ma6xXUfg3Rpn9])).*)|(?<C>)(?<=\\\A(?=\\\k<Q>(?<F>[X2aM6wg3RpfcxCFvrV95WnU81])(?<=(?<Q>\\\A.*))).*)|(?<G>)(?<=\\\A(?=\\\k<Q>(?<=(?<F>[8v1FRgx9cnfWaCVXM5rw2p6U3])(?<=(?<Q>\\\A.*)).)).*)|(?<T>)(?<=\\\A(?=\\\k<Q>(?>(?<=(?<=[ksZ4NJiAmzEd])(?<X>[^kJNEmz4isAZd])*[^dkzJENsmZ4Ai])[^NsimJdkzA4EZ]*[N4msZJkdiAzE](?<-X>[^mzZJiN4dEAsk])*(?(X)(?!)))(?<F>[VR8wp9fnMavFr5CUcgXW26x13])(?<=(?<Q>\\\A.*))).*)|(?)(?<=\\\A(?=\\\k<Q>(?<=(?=(?>(?<-X>[^AkNiZJm4sdzE])*(?(X)(?!)))(?<F>[rFx1XRVfwvaWMn5U68pc3g9C2])(?s:(?<=(?<Q>\\\A.*))))(?>(?<=[dAiZz4mNJksE])[^Jkz4EsNZmAid]*[AZ4mNisJzEkd](?<=[NEkds4zmiJAZ])(?<X>[^ZJ4imAsNzdEk])*[^di4EsZNJzAmk]))).*)).(?<=\\\A(?=(?<R>(?<J>\\\k<Q>))(?<-Q>)).*)(?<=\\\A(?:(?<=\\\A(?=(?<R>\\\k<Q>)(?)(?<-Q>)).*).)*.)(?<=\\\A(?:(?<=\\\A(?=\\\k<R>(?<=(?<Q>\\\A.*))(?<-R>)).*).)*))+?(?(U)|(?!))", RegexOptions.Multiline | RegexOptions.Compiled | RegexOptions.Singleline);  
private static readonly Dictionary<char, string> GrimoireOfTongues = new Dictionary<char, string>()  
{  
{  
'G',  
"CV9UQG0RAh8wcfuqBsXNt2WPExOKe5dmY4oJLZ6vFjga1ry7lD3MSnkHIbizpToUY3eE5CP2LRFQdqZ6svTBSin0lbHKkVMOtzJ7r8D4w1WcGN9jpAIuamXxfhyg"  
},  
{  
'C',  
"6q5PAC82RnbigxuLhkmHoIXptvdaBSswYf4EOFyJ7KZDMe3GVjlUrTzcW1N90QWxNPRke3pTrE5JA4HngO0KwZQXDubqItLdV1iYG82omcasMfC6vS9Byhz7UjlF"  
},  
{  
'A',  
"6DCzPVlAkeBQ38W5NyXvEth4rUdu0LSxo1iJYIF9RGnjwsgqTbp7Hma2OfMKcZvti5C0aZMPcx2QIuJXFEmGYbjl13ToRrhwp9D8HWenOA6NfUzsV7kqKyBL4gdS"  
},  
{  
'T',  
"Tkor9invyBJal7jH4ZcOuhdetp6g5WsAY0I3MqXPC1NKzUFE2R8DGLVSwfxbQm1zD57CjauGRqpwnFcEOLliQgH39IvVdAeokhBTS02ZMNYtPsxUrKXyf64mWb8J"  
},  
{  
'U',  
"m6V4nulF71Segfbt08GIT2P3ZRxpN5EqHYXJdLOQhAayKcCswoWjvUrz9iMDBkZhw1YG8OJ9yCX4SuQgzl5BTfR3v2qUna7rAVFjHde0IKNkcE6boWmtsxMDLPpi"  
}  
};  
private static readonly string? Mantra = Environment.GetEnvironmentVariable("FLAG") ?? "flag{fake}";  
private static readonly string Welcome = "\n Welcome to \n ~ the ~ \n \uD83D\uDC86✨ REGenerating EXperience ✨\uD83D\uDC86 \n\n Let your sore body rest and \n allow these soothing brain- \n teasers to tingle your neurons! \n";  
private static readonly string Promising = "\nPromising. Let's continue.\n";  
private static readonly string SeeYouLater = "\n\n You don't seem ready for our \n experience yet, and that's okay. \n We'll be happy to welcome you back \n once you're fully relaxed. \n\n Good luck on your journey! \n\n \uD83E\uDE75 \n";  
private static readonly string Goodbye = "\n You have proven your\n ability to relax\n and take full control\n of your senses.\n\n You are now ready to face\n the world with\n a clear mind.\n\n Please take this mantra\n with you on your\n journey ahead:\n";_

private static void Main(string[] args)  
{  
Console.WriteLine(Program.Welcome);  
for (int index = 0; index < 42; ++index)  
{  
if (Program.Tingle())  
{  
Console.WriteLine(Program.Promising);  
}  
else  
{  
Console.WriteLine(Program.SeeYouLater);  
return;  
}  
}  
Console.WriteLine();  
Console.WriteLine(Program.Goodbye);  
Console.WriteLine();  
Console.WriteLine(Program.Mantra);  
Console.WriteLine();  
}

private static bool Tingle()  
{  
string str = Program.WeaveWords(EternalSourceOfWisdom.Generate()) ?? throw new Exception("Impossible, this cannot be!");  
Console.WriteLine("Please rephrase this verse in your own words:");  
Console.WriteLine(str);  
Console.WriteLine("Your version:");  
string input = Console.ReadLine();  
return input != null && Program.WeaveWords(input) == str;  
}

private static string? WeaveWords(string input)  
{  
Match m = Program.RuneAlchemist.Match(input);  
if (!m.Success)  
return (string) null;  
Queue<char> charQueue = new Queue<char>(Program.GrimoireOfTongues.Keys.Select(k => new  
{  
k = k,  
g = m.Groups[k.ToString()]  
}).SelectMany(  
_param1 => _param1.g.Captures.Cast<Capture>(), (_param1, c) => new  
{  
\u003C\u003Eh__TransparentIdentifier0 = _param1,  
c = c  
}  
).OrderBy(_param1 => _param1.c.Index).Select(_param1 => _param1.\u003C\u003Eh__TransparentIdentifier0.k));  
StringBuilder stringBuilder = new StringBuilder();  
foreach (Capture capture in m.Groups["F"].Captures)  
{  
char key = charQueue.Dequeue();  
stringBuilder.Append(Program.GrimoireOfTongues[key][Program.GrimoireOfTongues[key].IndexOf(capture.Value) + 62]);  
}  
return stringBuilder.ToString();  
}  
}  
}  
```

Let's have a look at the `Main` function first: The program sends us a welcome message,  
then prompts us with 42 challenges and finally sends us the flag, if we answer correctly.  
The challenges themselves are handled in `Tingle` that uses the server-only problem generator `EternalSourceOfWisdom` and expects an input from us,  
that produces the same result when passed to `WeaveWords`.  
If that fails the challenge kindly bids us farewell.

Challenge interaction with wrong response

So, what does `WeaveWords` do?  
First, the function matches the huge regular expression at the top of the program.  
Then it uses LINQ expressions to get the occurrences of the groups `G,C,A,T,U` sorted by their capture position.  
For example, take the simple regex input `accl` (we will look at the regex in more detail [later](#one-regex-to-fool-them-all))  
that produces the following matches of the above groups:

Group matches for accl

These matches would then produce the following queue order for `charQueue`: `['G','G','G','U']`.  
Finally, the function loops over the captures of the group `F` and translates the captured letter using the keys in `charQueue`.  
Each of those keys corresponds to a string of 124 characters in the dictionary `GrimoireOfTongues`.  
These contain the alphabet `[a-zA-Z0-9]` (62 chars long) in different orders in the front and back part and  
are used as a translation table by finding the index of the input letter in the first block and translating that index to te second block.  
Thankfully, we can easily do the opposite for a given key and translate from the second block back to the first.

So, what we have to do is build an input string for the regular expression such that the first capture of `F` translates  
to the first letter of the challenge prompt when using the key of the group at position `0-0` for translation and so on.  
Now, to do that we will have to look at a large regular expression.  
But bare with me, I will try to keep it simple and understandable.

## One regex to fool them all

So, what does this 833 characters long beauty and beast of a regular expression do?  
It turns out it is a version of a [2D maze solver](https://kobikobi.wordpress.com/2013/07/06/solving-mazes-using-regular-expressions/) regex.  
Of course, I didn't know that at the time but I was able to decipher the movement behavior.  
Below, I did something you should usually never do to a regex: I formatted it a bit to show its structure and added a few comments to explain important parts.  
I won't go into detail about regular expression mechanics here though as the article above covers that part really well.  
Instead, let me give you a broad overview of how it works.

```regex  
(?=  
(?<Pos>.*?  
(?<Step>[7DGHLPSTYbltu]) # Start symbols: first matched  
)  
)  
\A(?:  
(?:  
(?<End>)  
(?<=\A(?=\k<Pos>(?<=[369MRUXafgnpx])).*) # End symbols: last matched  
|  
(?<Right>)  
(?<=\A(?=\k<Pos>(?<Step>[1258CFVWcrvw369MRUXafgnpx])(?<=(?<Pos>\A.*))).*)  
|  
(?<Left>)  
(?<=\A(?=\k<Pos>(?<=(?<Step>[1258CFVWcrvw369MRUXafgnpx])(?<=(?<Pos>\A.*)).)).*)  
|  
(?<Down>)  
(?<=  
\A(?=\k<Pos>  
(?>  
(?<=(?<=[4AEJNZdikmsz])(?<X>[^4AEJNZdikmsz])*[^4AEJNZdikmsz]) # Count indentation with X after first wall  
[^4AEJNZdikmsz]*  
[4AEJNZdikmsz]  
(?<-X>[^4AEJNZdikmsz])* # Remove indentation after next wall with balancing group  
(?(X)(?!))  
)  
(?<Step>[1258CFVWcrvw369MRUXafgnpx])  
(?<=(?<Pos>\A.*))  
)  
.*  
)  
|  
(?<Up>)  
(?<=  
\A(?=\k<Pos>  
(?<=  
(?=  
(?>(?<-X>[^4AEJNZdikmsz])*(?(X)(?!))) # Remove indentation before second wall with balancing group  
(?<Step>[1258CFVWcrvw369MRUXafgnpx])  
(?s:(?<=(?<Pos>\A.*)))  
)  
(?>  
(?<=[4AEJNZdikmsz])  
[^4AEJNZdikmsz]*  
[4AEJNZdikmsz]  
(?<=[4AEJNZdikmsz])  
(?<X>[^4AEJNZdikmsz])* # Count indentation with X after second wall  
[^4AEJNZdikmsz]  
)  
)  
)  
.*  
)  
)  
. # Consume one character each round

# Uniqueness checks  
(?<=\A(?=(?<Temp>(?<NewPos>\k<Pos>))(?<-Pos>)).*)  
(?<=\A(?:(?<=\A(?=(?<Temp>\k<Pos>)(?)(?<-Pos>)).*).)*.)  
(?<=\A(?:(?<=\A(?=\k<Temp>(?<=(?<Pos>\A.*))(?<-Temp>)).*).)*)  
)+?  
(?(End)|(?!)) # Ensure End match with negative lookahead  
```

The regular expression starts with a `Step` match of start symbols. There are three other character classes used for the remaining steps and the pattern itself:

| Description | Characters |  
| ----------- | --------------------------- |  
| Start | `7DGHLPSTYbltu` |  
| Path | `1258CFVWcrvw369MRUXafgnpx` |  
| End | `369MRUXafgnpx` |  
| Wall | `4AEJNZdikmsz` |

After the first `Step` match, the regex contains a group that is matched multiple times and consumes a character every time,  
both incrementing the index of later matches and limiting evaluation.  
Inside, there are five different operations or moves that are matched and, after consuming the next character,  
the regex does some uniqueness checks to avoid loops.  
The moves are as follows, in order of priority:

\- **End:** Consume end character at position  
\- **Right:** Move position to right (adds letter to Pos)  
\- **Left:** Move position to left (consumes letter from Pos)  
\- **Down:** Move to next line (respects x position)  
\- **Up:** Move to previous line (respects x position)

As `End` has the highest priority and Path symbols are a superset of End symbols, path finding stops immediately when encountering an End symbol. As such, only the rest of the symbols are used on the path itself.

To represent a 2D maze as a 1D string we need to use the Wall symbols as separators. The moves `Up` and `Down` are implemented as jumps that count the offset to the next Wall symbol to the left of the current position.

Finally, the regular expression checks whether a path to the end was found  
by ensuring the `End` group was matched.  
I hope this overview is enough to give you something to work with.  
I will talk a tiny bit more about how I got to this point and about an interesting feature I stumbled upon while building a solution.  
If you like, feel free to skip ahead to the [next step](#building-a-valid-solution) to see how the solver works.

### Analyzing the regular expression

While analyzing the regular expression, I tested a lot of assumptions manually, looked at different regex documentation and took notes of interesting examples. A few useful docs are:

\- [.NET docs](https://learn.microsoft.com/en-us/dotnet/standard/base-types/regular-expressions) (official docs, I did not use them much)  
\- [Mozilla Regular expression syntax cheat sheet](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Guide/Regular_expressions/Cheatsheet)  
\- [regular-expressions.info Regex Reference](https://www.regular-expressions.info/) (detailed, especially nice for stuff like [balancing groups](https://www.regular-expressions.info/refrecurse.html))

I like testing with [regex101](https://regex101.com/): The editor supports multiple flavors (including .NET) and provides a lot of useful intel on the regex structure and matches. To use it, we have to set the flavor and set the `multi line` and `single line` options, as the program does.

Initially, I concentrated on finding examples for all five moves (I called them ops). The first three are easy, but for the last two I copied part of the regex and looked at that in isolation. I will provide some minimal examples for these operations:

\- `SX`: Move right, CU  
\- `SccX`: Move right, CCCU  
\- `XS`: Move left, GU  
\- `XccS`: Move left, GGGU  
\- `XcScX`: Priority example, CCU  
\- `NSNX`: Jump/move down, TU  
\- `NXNS`: Jump/move up, AU

The final breakthrough was when I thought about offsets in jumps using the `X` capture and balancing groups. Since they use negative character classes for that, we can pad jumps with any other character:

\- `N__SN__cN__X`: Two jumps/moves down, at x-index 2  
\- `N__XN__S`: Jump/move up, at x-index 2

To get a better feeling of that, add newlines before the `N` to get a two-dimensional maze string. With this knowledge I started [building the final solver](#building-a-valid-solution) (or rather completing a previous attempt, but rewriting the important part). When running against the remote, I found an interesting problem though.

### A buggy feature: Uniqueness matching

When I thought I had a working solve I encountered an error for the following prompt:

```  
b'Please rephrase this verse in your own words:\n'  
b'qtj0DL0iIykYh\n'  
b'Your version:\n'  
[DEBUG] Sent 0x17 bytes:  
b'NCF6N2NWNCNV8FN VNSwr\n'  
```

Funny enough, the result worked fine when replacing the first `C` with `w`,  
in theory just another Path symbol.  
But somehow, my generated solution did not work as is.  
That shouldn't happen, or so I thought, but quickly ignored it when I found that a bunch of spaces before the first line fixed that.  
If you're not to keen to look at regex specifics, you can skip the code itself.  
I summarized what it does below.

What happens here stems from the way uniqueness checks are implemented:

```regex  
(?<=\A  
(?= # Move last Pos to Temp and NewPos  
(?<Temp>  
(?<NewPos>\k<Pos>)  
)  
(?<-Pos>)  
)  
.*  
)  
(?<=\A  
(?:  
(?<=\A  
(?= # For all Pos on stack:  
(?<Temp>\k<Pos>) # Push to Temp stack  
(?) # Compare NewPos with suffix check  
(?<-Pos>) # Pop Pos  
)  
.*  
)  
.  
)*  
.  
)  
(?<=\A  
(?:  
(?<=\A # Restore Pos stack from Temp  
(?=\k<Temp>  
(?<=  
(?<Pos>\A.*)  
)  
(?<-Temp>)  
)  
.*  
)  
.  
)*  
)  
```

Regular expressions in .NET are implement via stacks for groups and balancing groups can pop from that stack.  
The uniqueness check uses that to copy the last `Pos` match to `NewPos`,  
copy the whole `Pos` stack to `Temp` and later restore from there  
and meanwhile compare `NewPos` to `Pos` with a negative lookbehind, effectively a negative suffix comparison.  
Thus, when the path passes the upper left corner and encounters something that is a suffix of a previous `Pos` value, such as `NC` is for `NCF6N2NWNC`, then we fail.

This is expected behavior as the original regex author wrapped the regex in walls anyway.  
But we have to make sure to add something unique before the first line to effectively make a real comparison out of the suffix check.

## Building a valid solution

To build a solution, we must first do a reverse lookup to match the output characters to those we need to input for the `F` match (`Step`).  
We don't know which group to use but we know the symbol character classes.  
Starting with the first output letter, we can try all move keys and only one results in a valid start symbol.  
That gives us the first move as well. Then we can do the same for the next output character  
and the respective character class and reconstruct moves and input characters step by step.

Now, we don't know the dimensions of the final maze.  
As such, I used dictionaries for lines and characters in lines to build a sparse table, possibly with negative indices.  
Then, I normalized those indices, filled empty spaces with spaces (yeah, well..)  
and prepended walls to each line.  
But see for yourself, I built a small visualization of how the maze generation of the solver works:

Visualization of building maze from program

As I said [above](#a-buggy-feature-uniqueness-matching), we need to add a unique first line before that,  
for example another wall (there are no empty lines in our generated maze).

## Final solution

Putting all those thoughts together in one script, I produced the following solution:

```python  
import string  
from dataclasses import dataclass  
import pwn

# I left the names I used during the CTF in comments, when I renamed things for readability

ALPHABET = string.ascii_letters + string.digits  
ALPHABET_LEN = len(ALPHABET)

# GrimoireOfTongues mapping tables  
GOT = {  
"G": "CV9UQG0RAh8wcfuqBsXNt2WPExOKe5dmY4oJLZ6vFjga1ry7lD3MSnkHIbizpToUY3eE5CP2LRFQdqZ6svTBSin0lbHKkVMOtzJ7r8D4w1WcGN9jpAIuamXxfhyg",  
"C": "6q5PAC82RnbigxuLhkmHoIXptvdaBSswYf4EOFyJ7KZDMe3GVjlUrTzcW1N90QWxNPRke3pTrE5JA4HngO0KwZQXDubqItLdV1iYG82omcasMfC6vS9Byhz7UjlF",  
"A": "6DCzPVlAkeBQ38W5NyXvEth4rUdu0LSxo1iJYIF9RGnjwsgqTbp7Hma2OfMKcZvti5C0aZMPcx2QIuJXFEmGYbjl13ToRrhwp9D8HWenOA6NfUzsV7kqKyBL4gdS",  
"T": "Tkor9invyBJal7jH4ZcOuhdetp6g5WsAY0I3MqXPC1NKzUFE2R8DGLVSwfxbQm1zD57CjauGRqpwnFcEOLliQgH39IvVdAeokhBTS02ZMNYtPsxUrKXyf64mWb8J",  
"U": "m6V4nulF71Segfbt08GIT2P3ZRxpN5EqHYXJdLOQhAayKcCswoWjvUrz9iMDBkZhw1YG8OJ9yCX4SuQgzl5BTfR3v2qUna7rAVFjHde0IKNkcE6boWmtsxMDLPpi",  
}

# Moves and pattern letters  
START = set("lLuY7DGbtSHTP")  
END = set("Ma6xXUfg3Rpn9")  
VALID = set("X2aM6wg3RpfcxCFvrV95WnU81")  
NON_END = VALID.difference(END)  
WALL = "N" # mzZJiN4dEAsk; JUMP  
MOVES = ["G", "C", "A", "T"] # OPS

PADDING = 64

# Mapping and reverse mapping for a given group/move key  
def GOT_map(key: str, char: str) -> str:  
first_idx = GOT[key].index(char)  
return GOT[key][first_idx + ALPHABET_LEN]

def GOT_reverse(key: str, char: str) -> str:  
second_idx = GOT[key][ALPHABET_LEN:].index(char)  
return GOT[key][second_idx]

# Functions to restore moves  
def start(expected: str):  
out = []  
for op in MOVES:  
prev = GOT_reverse(op, expected)  
if prev in START:  
out.append(op)

assert len(out) == 1  
return out[0], GOT_reverse(out[0], expected)

def next_op(expected: str):  
out = []  
for op in MOVES:  
prev = GOT_reverse(op, expected)  
if prev in NON_END:  
out.append(op)

assert len(out) == 1  
return out[0], GOT_reverse(out[0], expected)

def end(expected: str):  
out = []  
for op in MOVES:  
prev = GOT_reverse(op, expected)  
if prev in END:  
out.append(op)

assert len(out) == 1  
return out[0], GOT_reverse(out[0], expected)

@dataclass  
class ProgramUnit:  
cursor_value: str  
next_op: str

@dataclass  
class Block:  
values: dict[int, str]

def build_block(block: Block, offset_left: int):  
cell_count = max(block.values.keys()) + offset_left + 1  
cells = [" "] * cell_count

for idx, value in block.values.items():  
cells[idx + offset_left] = value  
pass

return "".join(cells)

def restore_program(challenge: str) -> list[ProgramUnit]:  
end_mark = GOT_reverse("U", challenge[-1])

prog: list[ProgramUnit] = []  
op, value = start(challenge[0])  
assert value in START, value  
prog.append(ProgramUnit(value, op))

for out in challenge[1:-1]:  
op, value = next_op(out)  
prog.append(ProgramUnit(value, op))  
pass

prog.append(ProgramUnit(end_mark, "U"))  
return prog

def generate_blocks(program: list[ProgramUnit]):  
blocks: dict[int, Block] = {}  
block_index = 0  
indentation = 0  
for unit in program:  
if block_index not in blocks:  
blocks[block_index] = Block(values={})

# Set value at cursor in current block  
blocks[block_index].values[indentation] = unit.cursor_value

# Handle ops  
match unit.next_op:  
case "U": # END  
# Nothing to do here  
pass  
case "C": # MOVE RIGHT  
indentation += 1  
pass  
case "G": # MOVE LEFT  
indentation -= 1  
pass  
case "T": # JMP RIGHT  
block_index += 1  
pass  
case "A": # JMP LEFT  
block_index -= 1  
pass  
case _:  
raise Exception(f"Not implemented:", unit)

min_indentation = 0  
for block in blocks.values():  
min_indentation = min(min_indentation, min(block.values.keys()))

offset_left = -min_indentation

return blocks, offset_left

def solve_challenge(challenge: str):  
program = restore_program(challenge)

blocks, offset_left = generate_blocks(program)

# I used " "*PADDING, but this is cleaner  
program_out = WALL * 2 + WALL.join(  
[build_block(b, offset_left) for _, b in sorted(blocks.items())]  
)  
return program_out

if __name__ == "__main__":  
with pwn.remote("regex.flu.xxx", 1337) as conn:  
for round in range(42):  
conn.recvuntil(b"Please rephrase this verse in your own words:\n")  
challenge = conn.recvline(keepends=False).decode()  
conn.sendlineafter(b"Your version:\n", solve_challenge(challenge).encode())  
conn.interactive()

```

I renamed a few constants for better readability in the context of a 2D maze solver.  
Also, I extracted the functions `restore_program` and `generate_blocks` and moved the connection code to a main function  
for use with my Manim scene script (see the archive with scripts and resources above).

## Final words

I do like creative challenges like these that build interesting logic and patterns in unconventional ways.  
However, I can understand why the challenge got only one solve as it's a lot of work to grasp what that regex does and its size is daunting.  
Hopefully, I could convey a bit of the fun I had while solving it.  
And of course, getting a first blood for it after that work is nice and the 500 points helped us out too.

Regex challenge first blood announcement

I'd like to thank [pspaul](https://blog.pspaul.de/) and the whole [FluxFingers team](https://fluxfingers.net/) for organizing the CTF.  
The challenges were very interesting and had a good level of difficulty as well.  
That does take a lot of work and I appreciate it.
