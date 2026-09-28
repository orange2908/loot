---
title: "wasmup - Nullcon Goa HackIM 2025 CTF"
category: "misc"
type: "writeup"
tags: ["misc", "scanf", "wasmup", "nullcon-goa-hackim-2025-ctf", "2025", "ctf-writeup"]
summary: "void unnamedfunction16(void)"
source:
  name: "CTFtime writeup #39900"
  url: "https://ctftime.org/writeup/39900"
ctf:
  name: "Nullcon Goa HackIM 2025 CTF"
  year: 2025
  challenge: "wasmup"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2025 CTF
- **Task:** wasmup
- **Author team:** thehackerscrew
- **CTFtime:** <https://ctftime.org/writeup/39900>

---
the decompilation is:

```  
void unnamed_function_16(void)

{  
int iVar1;  
uint *local_70 [4];  
undefined4 *local_60 [4];  
undefined4 local_50 [4];  
undefined *local_40 [2];  
undefined4 local_38;  
uint local_34;  
undefined local_30 [24];  
undefined4 local_18;  
undefined2 local_14;  
undefined7 local_10;  
undefined4 uStack_9;  
undefined4 local_4;

local_4 = 0;  
local_10 = s_func____p_ram_000004d4._0_7_;  
uStack_9 = s_func____p_ram_000004d4._7_4_;  
local_14 = uRam000004d2;  
local_18 = uRam000004ce;  
local_34 = 1;  
local_38 = 2;  
unnamed_function_13();  
while( true ) {  
local_50[0] = (**(code **)((ulonglong)local_34 * 4))(local_30);  
unnamed_function_83(&local_18,local_50);  
local_30[0] = 0;  
local_40[0] = local_30;  
unnamed_function_85(0x48a,local_40); // scanf("%s", buf)  
iVar1 = unnamed_function_43(uRam00000c20);  
if (((iVar1 != 0) || (iVar1 = unnamed_function_44(uRam00000c20), iVar1 != 0)) ||  
(iVar1 = unnamed_function_117(local_30,1099), iVar1 == 0)) break;  
unnamed_function_70();  
iVar1 = unnamed_function_117(local_30,s_debug_ram_00000469);// if (strstr(buf, "debug")){ printf("func: %p", )}  
if (iVar1 == 0) {  
local_70[0] = &local_34;  
unnamed_function_83(&local_10,local_70);  
local_60[0] = &local_38;  
unnamed_function_83(&local_10,local_60);  
}  
}  
unnamed_function_30(0);  
do {  
halt_trap();  
} while( true );  
}

```

we can see there is a bof on

```  
local_40  
```

with this bof, we can overwrite the

```  
local_10  
```

variable, which will be passed to printf when

```  
debug  
```

is called.  
this can give us fsb.

then, with the fsb, we can overwrite the first param given from

```  
debug  
```

, to

```  
2  
```

, so that the :

```  
local_50[0] = (**(code **)((ulonglong)local_34 * 4))(local_30);  
```

call will jump to the print flag function
