---
title: "pycjail returns - ångstromCTF 2024"
category: "rev"
type: "writeup"
tags: ["rev", "pycjail", "returns", "ngstromctf", "ngstromctf-2024", "2024", "ctf-writeup"]
summary: "I gave a talk on “Python specialized bytecode” on Pykonik #70 where I also made a walkthrough over the “pycjail returns” challenge from ångstrom CTF 2024."
source:
  name: "CTFtime writeup #39205"
  url: "https://ctftime.org/writeup/39205"
original_source: "https://disconnect3d.pl/2024/06/20/python-specialized-bytecode/"
ctf:
  name: "ångstromCTF 2024"
  year: 2024
  challenge: "pycjail returns"
---

## Metadata

- **CTF:** ångstromCTF 2024
- **Task:** pycjail returns
- **Author team:** justCatTheFish
- **CTFtime:** <https://ctftime.org/writeup/39205>
- **Original writeup:** <https://disconnect3d.pl/2024/06/20/python-specialized-bytecode/>

---
I gave a talk on “Python specialized bytecode” on Pykonik #70 where I also made a walkthrough over the “pycjail returns” challenge from ångstrom CTF 2024. The [video can be found here](https://www.youtube.com/watch?v=RlNM5n5C_wg&t=5034s) and its [slides here](https://docs.google.com/presentation/d/13ZiJPzQrNVC5azJPlryfrPtHulCvohts0rZJFepTmis).

In this blog post, I am going to do a TL;DR of the idea of specialized bytecode in Python. For details on “Python jails” or “pycjail returns” challenge solution, check out the talk linked above :).

## Python specialized bytecode

Apart from going over a capture the flag cybersecurity competition challenge, the main point of the talk is that there is an ongoing effort to make CPython faster and a huge part of it is detailed in [PEP-659](https://peps.python.org/pep-0659/). Some of it is already implemented in Python 3.11 and 3.12. The gist of it is that they added “specialized bytecode” and some tracing for how functions are used. Now, when a function is “hot”, aka: it is used lots of times, its bytecode will be optimized with “specialized bytecode” instructions.

This can be seen below:

```
    In [1]: import dis  # import module for disassembling Python bytecode
    
    In [2]: def add(x, y):
       ...:     return x + y
       ...:
    
    In [3]: dis.dis(add, adaptive=True, show_caches=True)
      1           0 RESUME                   0
    
      2           2 LOAD_FAST__LOAD_FAST     0 (x)
                  4 LOAD_FAST                1 (y)
                  6 BINARY_OP                0 (+)
                  8 CACHE                    0 (counter: 17)
                 10 RETURN_VALUE
```

When we first disassemble this function, one of its opcode was already optimized from `LOAD_FAST` to `LOAD_FAST__LOAD_FAST`. This is a “superoperator” or “superopcode” which works faster than executing two `LOAD_FAST` operations. The other `LOAD_FAST` instruction needs to be kept there since `LOAD_FAST__LOAD_FAST` figures out the second load argument from it (the name of variable to fetch, which is `y`; this can be seen [here in the CPython code](https://github.com/python/cpython/blob/3.12/Python/generated_cases.c.h#L140-L149)).

Now, lets see what will happen when we execute the `add` function with int arguments lots of times:

```
    In [4]: for i in range(1000): add(i, i)
    
    In [5]: dis.dis(add, adaptive=True, show_caches=True)
      1           0 RESUME                   0
    
      2           2 LOAD_FAST__LOAD_FAST     0 (x)
                  4 LOAD_FAST                1 (y)
                  6 BINARY_OP_ADD_INT        0 (+)
                  8 CACHE                    0 (counter: 832)
                 10 RETURN_VALUE
```

The `BINARY_OP` instruction was replaced with `BINARY_OP_ADD_INT` which adds two integers faster. Of course the instruction still checks for argument types and if they aren’t integers, a deoptimized opcode is executed (which dispatches the execution based on argument types). This can actually be seen in [CPython’s C implementation for this opcode](https://github.com/python/cpython/blob/3.12/Python/generated_cases.c.h#L537-L538):

```
            TARGET(BINARY_OP_ADD_INT) {
                PyObject *right = stack_pointer[-1];
                PyObject *left = stack_pointer[-2];
                PyObject *sum;
                #line 385 "Python/bytecodes.c"
                // HERE we deoptimize the opcode if both args 
                // are not integers (CPython's PyLong type)
                DEOPT_IF(!PyLong_CheckExact(left), BINARY_OP);
                DEOPT_IF(Py_TYPE(right) != Py_TYPE(left), BINARY_OP);
                // (...)
```

Now, what will happen if we now execute the same function with string arguments many times?

```
    In [6]: for i in range(1000): add("Hello", " world")
    
    In [7]: dis.dis(add, adaptive=True, show_caches=True)
      1           0 RESUME                   0
    
      2           2 LOAD_FAST__LOAD_FAST     0 (x)
                  4 LOAD_FAST                1 (y)
                  6 BINARY_OP_ADD_UNICODE     0 (+)
                  8 CACHE                    0 (counter: 832)
                 10 RETURN_VALUE
```

As we can see, the function got optimized for a case when both arguments are unicode strings and so `BINARY_OP_ADD_UNICODE` is used.

## Want to learn more?

If you want to learn more about all of this, I recommend you going through the talk as well as reading the [Python 3.11 release’s “What’s new” section](https://docs.python.org/3.11/whatsnew/3.11.html#pep-659-specializing-adaptive-interpreter) which also describes all the speed ups achieved with this approach.
