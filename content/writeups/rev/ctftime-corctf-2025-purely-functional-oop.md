---
title: "purely-functional-oop - corCTF 2025"
category: "rev"
subcategory: "pow"
type: "writeup"
tags: ["rev", "object-oriented", "spreadsheets", "google-sheets", "functional-programming", "xor", "proof-of-work", "pow", "corctf", "corctf-2025", "2025", "ctf-writeup"]
summary: "This challenge is the culmination of my adventures with Google Sheets functional programming."
source:
  name: "CTFtime writeup #40478"
  url: "https://ctftime.org/writeup/40478"
original_source: "https://cor.team/posts/corctf-2025-purely-functional-oop/"
ctf:
  name: "corCTF 2025"
  year: 2025
  challenge: "purely-functional-oop"
---

## Metadata

- **CTF:** corCTF 2025
- **Task:** purely-functional-oop
- **Author team:** Crusaders of Rust
- **CTFtime tags:** object-oriented, spreadsheets, google-sheets, functional-programming
- **CTFtime:** <https://ctftime.org/writeup/40478>
- **Original writeup:** <https://cor.team/posts/corctf-2025-purely-functional-oop/>

---
#### corCTF 2025 - purely-functional-oop

[rev](https://cor.team/tags/rev)

  * **Author** : maxster
  * **Date** : Sep 18, 2025


# corCTF 2025 - purely-functional-oop

This challenge is the culmination of my adventures with Google Sheets functional programming. In [part one](https://max.xz.ax/blog/spreadsheet-functional-programming/), I implemented church numerals and arithmetic using only pure lambda abstractions and applications, and in [part two](https://max.xz.ax/blog/spreadsheet-object-oriented-programming/), I outlined a framework upon which smalltalk-style object-oriented message passing could be implemented. For corCTF 2025, I decided to implement those ideas into an actual product, compiling a custom object-oriented language into an executable Google Sheets formula.

Players were provided the source code for the compiler and were given access to a server running the same code, bound to the real flag. In order to solve this challenge, players had find a vulnerability in the compiler and submit code in the object-oriented language that, when compiled and executed, would reveal the flag.

I thought this challenge was really cool and allowed players to experiment with compilers in a new context without getting too deep into advanced concepts. In this blog, I will talk about the design of this compiler as well as the intended solution for this ctf challenge.

## The Language

![the snippet shown in the challenge teaser tweet](https://cor.team/img/purely-functional-oop/teaser.png)

From the teaser, we get a basic demonstration of the features in the language. This is a pure object-oriented language, users can declare classes with constructors that assign instance fields, as well as methods. All values in the language are objects, even the built-in integer and string literals (which are wrapped with methods).

The code would then be automatically compiled into a google sheets formula, which would be executed in a cell.

![the compiled code is run in a google sheets cell.](https://cor.team/img/purely-functional-oop/teaser_execution.png)

In the service itself, we see that our submitted code is also linked with another class declaration, which gives users a chance to obtain the flag:

```
     1"""
     2class Challenge {
     3    constructor() {
     4        let this.n = 3;
     5        let this.flag = """ + f'"{FLAG}"' + """;
     6    }
     7
     8    fn verifySolution(a, b, c) {
     9        let nonzeroInput = nonzero(a).and(nonzero(b)).and(nonzero(c));
    10        let integerInput = isInteger(a).and(isInteger(b)).and(isInteger(c));
    11        let satisfiesTheorem = pow(a, this.n).plus(pow(b, this.n)).equals(pow(c, this.n));
    12        
    13        let accepted = nonzeroInput.and(integerInput).and(satisfiesTheorem);
    14        return accepted ? this.flag : "Solution rejected";
    15    }
    16}
    17"""
```

This code requires users to enter three nonzero integers that can satisfy [Fermat’s Last Theorem](https://en.wikipedia.org/wiki/Fermat%27s_Last_Theorem) for n=3. Unfortunately, it has already been proven that no solutions exist for this mathematical problem — in order to get the flag, solvers would need to hack the compiler to trick the program.

## The Compiler

 _This compiler was hastily written, so the exact terminologies used in the internal documentation may be inaccurate._

In order to compile code, the program uses python’s [lark](https://github.com/lark-parser/lark) library to parse the language’s grammar, and then uses a recursive algorithm to generate the formula substitutions for each node in the parse tree. The grammar defines four types of statements: class definitions, function definitions, constructor definitions, and instructions (class assignment, assignment, and return statements). Functions could be defined either statically (outside of any class), or as an instance method (inside of a class). For simplicity, nested classes were not allowed in the language.

The recursive algorithm would generate the Google Sheets formula substitution, resolving each subtree until finished. For example, a method call would boil down to this expression:

```
    1args = ", ".join(parse_expression(arg, scope, outer_name) for arg in argument_list.children)
    2if not args:
    3    return f"{callee}(\"{method_name}\")" # no curried arguments
    4else:
    5    return f"{callee}(\"{method_name}\")({args})"
```

_In hindsight, it would’ve made more sense to make parameterless lambdas for no-argument methods. I didn’t know that existed at the time._

Otherwise, assignments and declarations would resolve into a string and expression pair that could be combined inside of a Google Sheets `LET` expression.

```
    1elif statement_type == "assignment":
    2    variable_name = statement.children[0]
    3    ensure_valid_name(variable_name)
    4    rhs = parse_expression(statement.children[1], scope, outer_name)
    5    return (f"{variable_name}, {rhs},\n", False)
```

Things start to get a little complicated when we declare classes. We want both `this` and the original class to be available inside method calls, but in lambda calculus, explicit recursion isn’t possible. In order to implement this, I wrote this monstronsity of a template to handle double recursion:

```
     1# template for a class definition
     2compiled_result = f"""
     3class_{class_name}, LAMBDA(_constructor, LAMBDA(this,
     4    {constructor_opening}
     5        LAMBDA(_message,
     6            {message_handler}
     7        )
     8    {constructor_closing}
     9)),
    10bootstrap_new_{class_name}, LAMBDA(_f, 
    11    LAMBDA({constructor_args_comma} 
    12        class_{class_name}(
    13            LAMBDA({constructor_args_comma} 
    14                (LAMBDA(_message, _f(_f)({constructor_args})(_message)))
    15            )
    16        ) (LAMBDA(_message, 
    17            _f(_f)({constructor_args})(_message)
    18        )) ({constructor_args})
    19    )
    20),
    21new_{class_name}, (bootstrap_new_{class_name}) (bootstrap_new_{class_name}),
    22"""
```

_A similar, simpler recursive template was used to enable static function call recursion. For brevity, I won’t show it here._

All primitives are wrapped in objects with predefined methods for functionality. Internally, they are accessed using the `_rawVal` method:

```
     1make_builtin_bootstrap, LAMBDA(f, LAMBDA(raw,
     2    LAMBDA(_message,
     3        IF(_message_match("_rawVal")(_message),
     4            raw,
     5        IF(_message_match("plus")(_message),
     6            LAMBDA(rhs, f(f)(raw + rhs("_rawVal"))),
     7        IF(_message_match("minus")(_message),
     8            LAMBDA(rhs, f(f)(raw - rhs("_rawVal"))),
     9        IF(_message_match("times")(_message),
    10            LAMBDA(rhs, f(f)(raw * rhs("_rawVal"))),
    11        IF(_message_match("divide")(_message),
    12            LAMBDA(rhs, f(f)(raw / rhs("_rawVal"))),
    13        IF(_message_match("equals")(_message),
    14            LAMBDA(rhs, f(f)(raw = rhs("_rawVal"))), 
    15        IF(_message_match("notEquals")(_message),
    16            LAMBDA(rhs, f(f)(raw <> rhs("_rawVal"))), 
    17        IF(_message_match("and")(_message),
    18            LAMBDA(rhs, f(f)(AND(raw, rhs("_rawVal")))),
    19        IF(_message_match("or")(_message),
    20            LAMBDA(rhs, f(f)(OR(raw, rhs("_rawVal")))),
    21        IF(_message_match("xor")(_message),
    22            LAMBDA(rhs, f(f)(XOR(raw, rhs("_rawVal")))),
    23        IF(_message_match("lessThan")(_message),
    24            LAMBDA(rhs, f(f)(raw < rhs("_rawVal"))),
    25        IF(_message_match("lessThanOrEquals")(_message),
    26            LAMBDA(rhs, f(f)(raw <= rhs("_rawVal"))),
    27        IF(_message_match("greaterThan")(_message),
    28            LAMBDA(rhs, f(f)(raw > rhs("_rawVal"))),
    29        IF(_message_match("greaterThanOrEquals")(_message),
    30            LAMBDA(rhs, f(f)(raw <= rhs("_rawVal"))),
    31        IF(_message_match("negate")(_message),
    32            f(f)(NOT(raw)),
    33        IF(_message_match("factorial")(_message),
    34            f(f)(FACT(raw)),
    35        IF(_message_match("log")(_message),
    36            f(f)(LOG(raw)),
    37        IF(_message_match("concat")(_message),
    38            LAMBDA(rhs, f(f)(CONCAT(raw, rhs("_rawVal")))),
    39        _raise_error_internal() 
    40        ))))))))))))))))))
    41    )
    42)),
    43
    44make_builtin, (make_builtin_bootstrap) (make_builtin_bootstrap),
```

Being derived from a functional programming language, everything here is immutable and pure. This means that repeated method calls on an object must always return the same value. Since there is no mathematical solution to the constraints, what inputs can we pass to the challenge to get the flag?

## The Exploit

The compiler has a set of reserved keywords in order to prevent names from overlapping with other tokens used in the system. These are the keywords:

```
    1RESERVED_KEYWORDS = { 
    2    "class", "fn", "constructor", "let", "return",
    3    "new", "this", "true", "false", "_f", "_message",
    4    "_constructor", "_message_match", "_raise_error_internal"
    5}
```

Since there is no runtime type checking in this programming langauge, numbers behave just like any other object — There is actually nothing preventing us from writing custom number objects that define all those same methods. Notice that the `_rawVal` method isn’t a reserved keyword, so we can call and implement these methods on any system. My intended solution abuses this mechanic by creating a special boolean value that will always return the same truth value, no matter what logical methods are called from it. This code yields the flag, `corctf{p0lym0rpHic_fr33k_1n_th3_sh33ts}`

```
     1class TrapBoolean {
     2    constructor(inner) {
     3        let this.inner = inner;
     4    }
     5
     6    fn _rawVal() {
     7        return this.inner._rawVal();
     8    }
     9
    10    fn and(other) {
    11        return this;
    12    }
    13}
    14
    15class TrapNumber {
    16    constructor(inner) {
    17        let this.inner = inner;
    18    }
    19
    20    fn _rawVal() {
    21        return this.inner._rawVal();
    22    }
    23
    24    fn notEquals(other) {
    25        return new TrapBoolean(true);
    26    }
    27}
    28
    29let chall = new Challenge();
    30return chall.verifySolution(new TrapNumber(0), 0, 0);
```

## The CTF

Unfortunately, this challenge had unintended solutions which took advantage of Google Sheets’ type confusion, with the one-line exploit `return new Challenge().verifySolution("0", "0", "0");`. As my friend Drakon accurately pointed out, “this is why we need a strongly typed spreadsheet.” At least some teams found the intended solution! I’d like to shout out the team Squid Proxy Lovers for taking the time to write up [their analysis and solution](https://spl.team/blog/cor-ctf-rev-write-ups-262bcc8ed7ef80b1beb1fe81ada9b7b6/#purely-functional-oop), which actually took advantage of the language and compiler features.

## The Conclusion

Despite compiling to a platform with a completely different programming paradigm, the intended solution for this challenge does not involve any mechanics specific to Google Sheets. `purely-functional-oop` serves as a warning against the dangers of duck typing and polymorphism.

I loved playing with this new concept and exploring the relationship between functional and object-oriented programming. Even though there was a cheese to the challenge, creating a compiler for this challenge and playing with Google Sheets formula technology was a lot of fun. Although there is very little practical usage in bringing object-oriented programming into spreadsheets, I found it interesting nonetheless. Who knows, maybe some tinkerer in the future will develop this concept into a proper toolchain.

Code copied!
