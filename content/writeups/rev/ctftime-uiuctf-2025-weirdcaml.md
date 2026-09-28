---
title: "weirdcaml - UIUCTF 2025"
category: "rev"
subcategory: "symbolic-execution"
type: "writeup"
tags: ["ocaml", "rev", "z3", "weirdcaml", "symbolic-execution", "uiuctf", "uiuctf-2025", "2025", "ctf-writeup"]
summary: "Compile this OCaml file with ocamlc main.ml."
source:
  name: "CTFtime writeup #40515"
  url: "https://ctftime.org/writeup/40515"
original_source: "https://overllama.me/posts/Weird-Caml/"
ctf:
  name: "UIUCTF 2025"
  year: 2025
  challenge: "weirdcaml"
---

## Metadata

- **CTF:** UIUCTF 2025
- **Task:** weirdcaml
- **Author team:** BYU Cyberia
- **CTFtime tags:** ocaml, rev
- **CTFtime:** <https://ctftime.org/writeup/40515>
- **Original writeup:** <https://overllama.me/posts/Weird-Caml/>

---
## WeirdCaml

Compile this OCaml file with ocamlc [main.ml](http://main.ml). The flag will be printed to stderr!

You'll need to wrap the flag in uiuctf{} when you submit.

author: n8

Files:  
\- [main.ml](http://main.ml) (see linked url for file)

### Solve

Honestly, the challenge description made it look easy. My computer is a little high powered, so I thought "maybe it'll just work and the challenge is knowing how to compile ocaml?" Not the case. I ran the compiler 3 times, and each time the system killed it after 15 minutes or so. On to the next idea.

The challenge stated that it would print the flag to stderr, so I needed to find what would actually be printed. I started with some static reverse engineering before I got smart. The program starts with these type declarations:

```ocaml  
type b_true  
type b_false  
type 'a val_t =  
| T : b_true val_t  
| F : b_false val_t  
```

It has two just open-ended types that values can then be assigned to. Then, it has a `val_t` type that is effectively a boolean, returning solid eventual values with names T and F. Next, the program jumps into further type definitions... like 1400 of them matching this form.

```ocaml  
type ('a, 'b, 'c, 'd) p1_t =  
| P1_1 : b_true val_t -> ('a, b_true, 'c, 'd) p1_t  
| P1_2 : b_true val_t -> ('a, 'b, b_true, 'd) p1_t  
| P1_3 : b_true val_t -> ('a, 'b, 'c, b_true) p1_t  
| P1_4 : b_true val_t -> (b_false, 'b, 'c, 'd) p1_t  
type ('a, 'b, 'c, 'd) p2_t =  
| P2_1 : b_true val_t -> ('a, b_true, 'c, 'd) p2_t  
| P2_2 : b_true val_t -> (b_false, 'b, 'c, 'd) p2_t  
| P2_3 : b_true val_t -> ('a, 'b, b_false, 'd) p2_t  
| P2_4 : b_false val_t -> ('a, 'b, 'c, b_false) p2_t  
```

Had to do some learning of OCaml for this, but each of these types takes 4 arguments and returns a named `val_t`. Not really sure how that tied in at this point, I just continued forward. After 1435 of those types, we finally get to the meat of the challenge, which is a type called Puzzle. This type starts out with a number of `val_t` variables, then utilizes each of the other types to create a complex system of type calls into a tuple type (the `*` is the separator between tuple elements, which is really strange coming from writing C all day, but I got used to it).

```ocaml  
type puzzle =  
Puzzle :  
'flag_000 val_t *   
'flag_001 val_t *   
'flag_002 val_t *   
'flag_003 val_t *   
'flag_004 val_t *   
'flag_005 val_t *   
'flag_006 val_t *   
'flag_007 val_t *   
'flag_008 val_t *   
'flag_009 val_t *   
...  
'flag_102 val_t *   
'flag_103 val_t *   
'a val_t *   
'b val_t *   
'c val_t *   
'd val_t *   
...  
'x val_t *   
'y val_t *   
'z val_t *   
'a1 val_t *   
'a2 val_t *   
'a3 val_t *   
...  
'a145 val_t *   
'a146 val_t *   
'a147 val_t *   
('a, 'flag_016, 'flag_038, 'flag_040) p1_t *  
('a, 'flag_016, 'flag_038, 'flag_040) p2_t *  
('a, 'flag_016, 'flag_038, 'flag_040) p3_t *  
...  
('a56, 'a57, 'flag_087, 'flag_091) p1433_t *  
('a56, 'a57, 'flag_087, 'flag_091) p1434_t *  
('a57) p1435_t  
-> puzzle  
```

FINALLY we get the actual part that seems like it would generate an error. The last three lines of the program are:

```ocaml  
let check (f: puzzle) = function  
| Puzzle _ -> .  
| _ -> ()  
```

This creates a function called check, which takes a puzzle object. This uses a really interesting feature of OCaml GADT's (Generalized Algebraic Data Types) called a [Refutation Case](<https://ocaml.org/manual/5.2/gadts-tutorial.html#s:gadt-refutation-cases>), basically meaning that if the compiler sees that `.`, it will help prove *for* you that the case cannot, in fact be reached. To acquaint myself with what the stderr of this program might look like, I just copied the start of the puzzle type and the final `let` into a file called `[test.ml](http://test.ml)` and compiled it with `ocamlc [test.ml](http://test.ml)`.

Here's that program (the dots, again, helping abbreviate the actual type object):  
```ocaml  
type b_true  
type b_false  
type 'a val_t =  
| T : b_true val_t  
| F : b_false val_t

type ('a, 'b, 'c, 'd) p1_t =  
| P1_1 : b_true val_t -> ('a, b_true, 'c, 'd) p1_t  
| P1_2 : b_true val_t -> ('a, 'b, b_true, 'd) p1_t  
| P1_3 : b_true val_t -> ('a, 'b, 'c, b_true) p1_t  
| P1_4 : b_true val_t -> (b_false, 'b, 'c, 'd) p1_t  
type ('a, 'b, 'c, 'd) p2_t =  
| P2_1 : b_true val_t -> ('a, b_true, 'c, 'd) p2_t  
| P2_2 : b_true val_t -> (b_false, 'b, 'c, 'd) p2_t  
| P2_3 : b_true val_t -> ('a, 'b, b_false, 'd) p2_t  
| P2_4 : b_false val_t -> ('a, 'b, 'c, b_false) p2_t  
type ('a, 'b, 'c, 'd) p3_t =  
| P3_1 : b_true val_t -> ('a, 'b, b_true, 'd) p3_t  
| P3_2 : b_false val_t -> (b_false, 'b, 'c, 'd) p3_t  
| P3_3 : b_true val_t -> ('a, b_false, 'c, 'd) p3_t  
| P3_4 : b_true val_t -> ('a, 'b, 'c, b_false) p3_t  
type ('a, 'b, 'c, 'd) p4_t =  
| P4_1 : b_true val_t -> ('a, 'b, 'c, b_true) p4_t  
| P4_2 : b_false val_t -> (b_false, 'b, 'c, 'd) p4_t  
| P4_3 : b_false val_t -> ('a, b_false, 'c, 'd) p4_t  
| P4_4 : b_false val_t -> ('a, 'b, b_false, 'd) p4_t  
type ('a, 'b, 'c, 'd) p5_t =  
| P5_1 : b_true val_t -> (b_true, 'b, 'c, 'd) p5_t  
| P5_2 : b_true val_t -> ('a, b_false, 'c, 'd) p5_t  
| P5_3 : b_true val_t -> ('a, 'b, b_false, 'd) p5_t  
| P5_4 : b_true val_t -> ('a, 'b, 'c, b_false) p5_t  
type ('a, 'b, 'c, 'd) p6_t =  
| P6_1 : b_false val_t -> (b_true, 'b, 'c, 'd) p6_t  
| P6_2 : b_false val_t -> ('a, 'b, b_true, 'd) p6_t  
| P6_3 : b_false val_t -> ('a, 'b, 'c, b_true) p6_t  
| P6_4 : b_true val_t -> ('a, b_false, 'c, 'd) p6_t

type puzzle =  
Puzzle :  
'flag_000 val_t *   
'flag_001 val_t *   
'flag_002 val_t *   
'flag_003 val_t *   
'flag_004 val_t *   
'flag_005 val_t *   
...  
'flag_095 val_t *   
'flag_096 val_t *   
'flag_097 val_t *   
'flag_098 val_t *   
'flag_099 val_t *   
'flag_100 val_t *   
'flag_101 val_t *   
'flag_102 val_t *   
'flag_103 val_t *   
'a val_t *   
'b val_t *   
'c val_t *   
...  
'u val_t *   
'v val_t *   
'w val_t *   
'x val_t *   
'y val_t *   
'z val_t *   
'a1 val_t *   
'a2 val_t *   
'a3 val_t *   
'a4 val_t *   
'a5 val_t *   
'a6 val_t *   
'a7 val_t *   
'a8 val_t *   
'a9 val_t *   
...  
'a144 val_t *   
'a145 val_t *   
'a146 val_t *   
'a147 val_t *   
('a, 'flag_016, 'flag_038, 'flag_040) p1_t *  
('a, 'flag_016, 'flag_038, 'flag_040) p2_t *  
('a, 'flag_016, 'flag_038, 'flag_040) p3_t *  
('a, 'flag_016, 'flag_038, 'flag_040) p4_t *  
('a, 'flag_016, 'flag_038, 'flag_040) p5_t *  
('a, 'flag_016, 'flag_038, 'flag_040) p6_t  
-> puzzle

let check (f: puzzle) = function  
| Puzzle _ -> .  
| _ -> ()  
```

And its output:  
```sh  
❯ ocamlc [test.ml](http://test.ml)   
File "[test.ml](http://test.ml)", line 329, characters 4-12:  
329 | | Puzzle _ -> .  
^^^^^^^^  
Error: This match case could not be refuted.  
Here is an example of a value that would reach it:  
Puzzle  
(T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T,  
T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T,  
T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T,  
T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T,  
T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T,  
T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T,  
T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T,  
T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T,  
T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T,  
T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T,  
T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T,  
T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T,  
T, T, P1_1 _, P2_1 _, P3_1 _, P4_1 _, P5_1 _, P6_1 _)  
```

We can see the refutation case in action! The compiler prints out the conditions under which the program will successfully allow a Puzzle object at that point of the code base. So, it seems like the stdout would print a number of T and F values based on the set of variables that will allow a successful run through. And since each type supports only a limited number of cases for its arguments, that constrains it enough to where it would only allow through one case (likely). Honestly, the realization that the output was related to binary should have been obvious, but that was ChatGPT's idea. But now to my actual solve. 

I figured that rather than generating the conditions by hand, I would do that through Python and regex, and then pass the final state into the z3 engine so that I could get a working output. I figured this out piece by piece, so I'll explain it as such. First, I created the right number of boolean values for all of the combined variables (though since flag only went to `flag_103`, I would just cut it eventually. The total number of variables was just necessary for the right amount of eventual constraint).

```python  
from z3 import *  
import re  
from Crypto.Util.number import long_to_bytes

solver = Solver()

PROGRAM = ''

with open('[main.ml](http://main.ml)', 'r') as f:  
ocaml_source = f.read()

# regex to find all of the variables from the main Puzzle object  
vars = re.findall(r"'([a-zA-Z0-9_]+) val_t \\*", ocaml_source)  
bool_inits = [(f"{v} = Bool('{v}')", v) for v in vars] # gathers all the bools from the main Puzzle type

PROGRAM += '\n'.join([i[0] for i in bool_inits])  
variable_names = [v[1] for v in bool_inits]  
PROGRAM += '\n\n'  
```

That program object was initialized to be the actual z3 program used to house the conditions and logic. This uses regex to find all of the variable names, and create Bool objects in z3 to work with later on. I also had to make a `variable_names` object to work with later to print the flag. These first cases look like this (for reference, since my code is awful):

```python  
flag_000 = Bool('flag_000')  
flag_001 = Bool('flag_001')  
flag_002 = Bool('flag_002')  
flag_003 = Bool('flag_003')  
flag_004 = Bool('flag_004')  
flag_005 = Bool('flag_005')  
```

Next, I needed to parse all of the types. Since we had each of the types set up early and then used later in the program, making these into functions would be the easiest way to work everything together. This meant taking a type like this:

```ocaml  
type ('a, 'b, 'c, 'd) p1_t =  
| P1_1 : b_true val_t -> ('a, b_true, 'c, 'd) p1_t  
| P1_2 : b_true val_t -> ('a, 'b, b_true, 'd) p1_t  
| P1_3 : b_true val_t -> ('a, 'b, 'c, b_true) p1_t  
| P1_4 : b_true val_t -> (b_false, 'b, 'c, 'd) p1_t  
```  
And turning it into a Python function (using z3) like this:  
```python  
def p1_t(a, b, c, d):  
return Or(  
b == True,  
c == True,  
d == True,  
a == False,  
)  
```

All this does is actually translate each of those possible options into a constraint on whatever variables are passed into the function. This means that when we get to the Puzzle, we can just call the `p1_t` with the constraint names and add the condition to the solver. Here's the regex and parsing that adds all of those into the final Python script. REMINDER I did not just know how to do this lol. I grabbed a set of those types from ocaml, and tweaked the regex and parsing until it looked like I wanted before I moved on to the next step. This is important to me; it's a process.

```python  
type_blocks = re.findall(  
r"type\s*\\(\s*([^)]+)\s*\\)\s*(\w+)\s*=", ocaml_source)

for params, typename in type_blocks:  
params_list = [p.strip().lstrip("'") for p in params.split(',')]

function_definition = f"def {typename}({', '.join(params_list)}):\n return Or(\n"

type_cons = re.findall(fr"-> \\(([^)]+)\\)\s+{typename}", ocaml_source)  
for t in type_cons:  
parts = [p.strip() for p in t.split(",")]  
indices = [f" {params_list[i]} == {val.lstrip('b_').capitalize()},\n" for i, val in enumerate(parts) if val in ("b_true", "b_false")]  
for x in indices:  
function_definition += x  
function_definition += ' )\n\n'  
PROGRAM += function_definition  
```

Finally, we can parse the Puzzle object, taking each condition and actually passing in the associated variables. This means that for each line like this:

```ocaml  
('a, 'flag_016, 'flag_038, 'flag_040) p1_t *  
```  
We turn it into a call to our previously-defined Python function like this:  
```python  
solver.add(p1_t(a, flag_016, flag_038, flag_040))  
```

Since the earlier function returns an `Or()`, we need to actually feed the return into the function to make it work. Here's the regex and code for that part:  
```python  
matches = re.findall(r" \\(\s*([^)]+)\s*\\)\s*(\w+)_t", ocaml_source)

for params_str, typename in matches:  
params = [p.strip().lstrip("'") for p in params_str.split(",")]  
call_str = f"solver.add({typename}_t({', '.join(params)}))\n"  
PROGRAM += call_str  
```

Finally, the program was ready to go. First of all, even though I love just `exec`ing whatever in my Python instance, I did print it to make sure everything looked like I wanted it to:  
```python  
with open('[model.py](http://model.py)', 'w') as f2:  
f2.write(PROGRAM)   
```

I was able to catch a couple of future bugs with this and verify that just everything looked like valid z3 code. THEN I ran the `exec`. Since I wanted to use the pieces later, I injected those parts back into `globals()`. Then we could just print the flag??

```python  
exec(PROGRAM, globals())

# hoping and praying  
if solver.check() == sat:  
model = solver.model()

flag = ''  
for name in variable_names:  
var = globals()[name] # Get the actual Bool object  
value = model.eval(var) # Get its value in the model  
flag += "1" if value else "0"  
print(long_to_bytes(int(flag[:104],2)))

else:  
print("unsat")  
```

I printed the pieces of the model first, and verified that the flag came out like I wanted; aka I printed all the T's and F's first, then manually changed that list into binary, then into an int, and then into a string with `long_to_bytes`. Once I saw that it was the flag, I got super hype, then added that final touch of automatic conversion into the final script!

```sh  
❯ python [solve.py](http://solve.py)   
b'sat_on_a_caml'  
```

You can find my full solve script on the linked writeup: <https://overllama.me/posts/Weird-Caml/>

Flag: `uiuctf{sat_on_a_caml}`
