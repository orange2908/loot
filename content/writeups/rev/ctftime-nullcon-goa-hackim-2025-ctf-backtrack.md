---
title: "backtrack - Nullcon Goa HackIM 2025 CTF"
category: "rev"
subcategory: "static-analysis"
type: "writeup"
tags: ["rev", "reverse", "engineering", "ghidra", "memcpy", "backtrack", "static-analysis", "nullcon-goa-hackim-2025-ctf", "2025", "ctf-writeup"]
summary: "This was a pretty fun malware challenge from nullcon goa, although I did spend alot of time going through random rabbit holes in the program (but I guess I now know more about how malware might load D"
source:
  name: "CTFtime writeup #39853"
  url: "https://ctftime.org/writeup/39853"
original_source: "https://nikzu.dev/writeups/backtrack/"
ctf:
  name: "Nullcon Goa HackIM 2025 CTF"
  year: 2025
  challenge: "backtrack"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2025 CTF
- **Task:** backtrack
- **Author team:** Qu4cks
- **CTFtime tags:** reverse, engineering
- **CTFtime:** <https://ctftime.org/writeup/39853>
- **Original writeup:** <https://nikzu.dev/writeups/backtrack/>

---
Table of Contents

Table of Contents

This was a pretty fun malware challenge from nullcon goa, although I did spend alot of time going through random rabbit holes in the program (but I guess I now know more about how malware might load DLLs).

## Chal Description

#

While Working I found an interesting Sample in the wild.  
The Sample seems to load other executables but idk how? can you find that out?  
WARNING: THIS IS AN ACTUAL MALWARE, DO NOT EXECUTE IT (the challenge is meant to be solved statically)  
ALSO I OVERWROTE A PART OF THE ENTRY TO MAKE THE SAMPLE NOT EXECUTBLE (just to be extra safe ;) )  
Files can be found in the zip:

  * b8ad5cbf8c8a3129582161226e79b6c4b67c8b868592d1618252451c8c2146c8 is the sample
  * input_file is the data they used to get the keylogger
  * keylogger.bin is the result after the input_file is given to the sample
  * data.bin is the challenge file


To solve this task reverse what’s in data.bin and look at the output (example: input_file -> keylogger, data.bin -> ???)

Files: [`files.zip`](https://nikzu.dev/writeups/backtrack/files.zip)

## Solution

#

The zip contains the 4 files mentioned in the description. The sample `b8ad5cbf8c8a...`, is malware that loads payloads. The idea is that it turns files like `input_file` into a _PE_ such as `keylogger.bin`, which it then launches. Based on the description, the flag should be in the transformed `data.bin`. Looking at the hex of the two untransformed files (and based on the size of the `keylogger.bin`), we can see that they are compressed, and that `data.bin` should turn into a JPEG.![input_file](https://nikzu.dev/writeups/backtrack/input_file_hex.png)![data.bin](https://nikzu.dev/writeups/backtrack/data_hex.png)

With this determined, we can finally start to look at the decompiled code from `b8ad5cbf8c8a...` in ghidra.

The main function looks like this (after some analysis, some of the names for things are also dumb):

```
    int main(void)
    {
      bool bVar1;
      char cVar2;
      undefined uVar3;
      undefined2 show_window;
      int iVar4;
      int *piVar5;
      undefined4 uVar6;
      int unaff_ESI;
      void *exception_list;
      code *some_scramble_func_;
      uint idk_what_this_s;
      undefined4 local_8;
      
      local_8 = 0xfffffffe;
      some_scramble_func_ = lots_of_unwinding;
      exception_list = ExceptionList;
      idk_what_this_s = something_notimportant ^ 0x405bb0;
      ExceptionList = &exception_list;
      cVar2 = init_start(1);
      if (cVar2 == '\0') {
        handle_exceptions(7);
      }
      else {
        bVar1 = false;
        local_8 = 0;
        uVar3 = FUN_00402eb0();
        if (DAT_00407068 != 1) {
          if (DAT_00407068 == 0) {
            DAT_00407068 = 1;
                        /* get args to somewhere idk where though */
            iVar4 = call_main_table(&another_table,&DAT_00405118);
            if (iVar4 != 0) {
              ExceptionList = exception_list;
              return 0xff;
            }
            _initterm(&PTR_00405100,&DAT_00405108);
            DAT_00407068 = 2;
          }
          else {
            bVar1 = true;
          }
          ___scrt_release_startup_lock(uVar3);
          piVar5 = (int *)FUN_00403110();
          if (*piVar5 != 0) {
            cVar2 = check_entrypoint(piVar5);
            if (cVar2 != '\0') {
              (*(code *)*piVar5)(0,2,0);
            }
          }
          show_window = FUN_004032b0();
          uVar6 = FUN_00403780();
          unaff_ESI = init_all(0x400000,0,uVar6,show_window);  // The function where things happen
          cVar2 = FUN_00403300();
          if (cVar2 != '\0') {
            if (!bVar1) {
              _cexit();
            }
            free_all(1,0);
            ExceptionList = exception_list;
            return unaff_ESI;
          }
          goto LAB_00402c9a;
        }
      }
      handle_exceptions(7);
    LAB_00402c9a:
                        /* WARNING: Subroutine does not return */
      exit(unaff_ESI);
    }
```

It looks like there’s alot here, but all of the transformations actually happen in the function `init_all`). The rest is used to initialize some headers for the _PE_ in the program’s memory space.

Taking a look at that function, we can see it’s just a wrapper around another function call (my naming _convention_ (I don’t have a naming convention) is confusing)

```
    undefined4 init_all(void)
    {
      int iVar1;
      
      iVar1 = init();
      if (iVar1 == 0) {
         try_reinit();
         start_stuff(0);
      }
      return 0;
    }
```

The init function loads `SHWAPI.dll`

```
    {
      LoadLibraryA(local_50);
      builtin_memcpy(local_30 + 0xc,"SHLWAPI.dll",0xc);
      hModule = LoadLibraryA(local_30 + 0xc);
      builtin_memcpy(local_30,"SHGetValueA",0xc);
      shgetvaluea?? = (SHGetValueA *)GetProcAddress(hModule,local_30);
    }
```

The try_reinit function seems to just delay the program a little.

```
      DVar1 = GetTickCount();
      uVar5_45000 = 45000;
      uVar4_360000 = 360000;
      do {
         GetLocalTime(&local_28);
         uVar3 = (uint)local_28.wSecond;
         DVar2 = GetTickCount();
         if ((45000 < DVar2 - DVar1) && (uVar3 == t_second)) break;
         DVar2 = GetTickCount();
      } while (DVar2 - DVar1 < 0x57e41);
```

### Loading

#

The function `start_stuff` is where the program actually loads the exe.

```
    void start_stuff(void)
    {
      uint uStack_60;
      DWORD local_50 [2];
      HANDLE thread_handle;
      LPTHREAD_START_ROUTINE dllmain_addr;
      undefined4 some_size;
      IMAGE_DOS_HEADER *registryval;
      Context *context;
      char DllMain [28];
      uint local_18;
      undefined *local_14;
      void *local_10;
      undefined *puStack_c;
      undefined4 local_8;
      
      puStack_c = &LAB_004041c0;
      local_10 = ExceptionList;
      uStack_60 = something_notimportant ^ (uint)&stack0xfffffffc;
      local_14 = (undefined *)&uStack_60;
      ExceptionList = &local_10;
      local_8 = 0;
      some_size = 0;
      local_18 = uStack_60;
      registryval = (IMAGE_DOS_HEADER *)hkey_loader_or_something(&some_size);
      context = copy_file_wrapper(registryval,some_size);
      DllMain[0] = '\0';
      DllMain[1] = '\0';
       ...
      DllMain[0x1b] = '\0';
      strcat(DllMain,"Dll");
      strcat(DllMain,"Ma");
      strcat(DllMain,"in");
      dllmain_addr = (LPTHREAD_START_ROUTINE)find_dllmain(context,DllMain);
      thread_handle = (HANDLE)0x0;
      dllmain_addr = (LPTHREAD_START_ROUTINE)find_dllmain(context,DllMain);
      thread_handle = CreateThread((LPSECURITY_ATTRIBUTES)0x0,0,dllmain_addr,(LPVOID)0x0,0,local_50);
      WaitForSingleObject(thread_handle,0xffffffff);
      exit_free_fn();
      return;
    }
```

I did end up figuring out the structs of these values while trying to understand how it works. The malware loads some input from the Windows Registry (hkey_loader), which it interprets as a _PE_ header, `copy_file_wrapper` copies the loaded data, into program memory. The next part finds `DllMain` in the loaded program and runs it in a other thread.

Knowing all this, the data would have to be transformed when it first gets loaded, which would be in `hkey_loader_or_something`.

This function looks like this:

```
    void hkey_loader_or_something(size_t *param_1)
    {
      LSTATUS LVar1;
      DWORD local_48;
      void *dest;
      size_t length;
      DWORD local_3c;
      astruct_1 *src;
      size_t size_in;
      char buf_a [22];
      void *local_10;
      undefined *puStack_c;
      undefined4 local_8;
      
      puStack_c = &LAB_004041f0;
      local_10 = ExceptionList;
      ExceptionList = &local_10;
      local_8 = 0;
      length = 0;
      size_in = 0;
      local_48 = 3;
      local_3c = 4;
      builtin_strncpy(buf_a,"Software\\Realtek Inc.",0x16);
      LVar1 = (*shgetvaluea??)((HKEY)0x80000001,buf_a,"CS",&local_48,&size_in,&local_3c);
      if (LVar1 == 0) {
         src = (astruct_1 *)malloc(size_in);
         local_3c = size_in;
         LVar1 = (*shgetvaluea??)((HKEY)0x80000001,buf_a,"CH",&local_48,src,&local_3c);
         if (LVar1 == 0) {
           length = size_in << 1;
           dest = malloc(length);
           if (dest != (void *)0x0) {
              copy(src,size_in,dest,&length);
              *param_1 = length;
              if (src != (astruct_1 *)0x0) {
                operator_delete[](src);
                src = (astruct_1 *)0x0;
              }
              FUN_004014c1();
              return;
           }
           dest = (void *)0x0;
         }
      }
      ExceptionList = local_10;
      init_DAT_00407298_first();
      return;
    }
```

It would look for **Software\Realtek Inc.** in the registry, and load the two keys **CS** and **HS**. The first one is the size of the data, and the second is the data itself. The program then allocates **2x** the size of the data into a buffer that will store the transformed data.

### Transformation

#

The function `copy` is where the transformations happen. src_buf is where the loaded untransformed data is.

```
    struct astruct_1 {
        undefined4* ptr;
        byte data;
    };
    char * __cdecl copy(astruct_1 *src_buf,int size_in,byte *dest_buf?,int *length)
    {
      byte *next;
      byte *local_20;
      int local_1c;
      int local_14;
      uint base;
      byte *tmp_ptr;
      byte *src_buf_ptr;
      byte c1;
      byte c2;
      
      local_14 = 0;
      src_buf_ptr = &src_buf->data;
      tmp_ptr = dest_buf?;
      if (src_buf->ptr == '\x01') {
         sometypeacopy(&src_buf->data,dest_buf?,size_in + -4);
         *length = size_in + -4;
      }
      else {
         while (src_buf_ptr != (byte *)(&src_buf->ptr + size_in)) {
           if (local_14 == 0) {
              base = (uint)*(ushort *)src_buf_ptr;
              src_buf_ptr = src_buf_ptr + 2;
              local_14 = 0x10;
           }
           if ((base & 1) == 0) {
              *tmp_ptr = *src_buf_ptr;
              tmp_ptr = tmp_ptr + 1;
              src_buf_ptr = src_buf_ptr + 1;
           }
           else {
              c1 = *src_buf_ptr;
              c2 = *src_buf_ptr;
              next = src_buf_ptr + 1;
              src_buf_ptr = src_buf_ptr + 2;
              local_20 = tmp_ptr + -((uint)*next + (c1 & 0xf0) * 0x10);
              local_1c = (c2 & 0xf) + 1;
              while (local_1c != 0) {
                *tmp_ptr = *local_20;
                tmp_ptr = tmp_ptr + 1;
                local_20 = local_20 + 1;
                local_1c = local_1c + -1;
              }
           }
           base = base >> 1;
           local_14 = local_14 + -1;
         }
         *length = (int)tmp_ptr - (int)dest_buf?;
      }
      return (char *)length;
    }
```

### Flag

#

This algorithm seems to just be some kind of decompression, which I reimplemented in python.

```
    f = open("data.bin", 'rb')
    f.read(4)
    data = f.read()
    data_size = len(data)
    length = data_size << 1
    out_buf = [0 for _ in range(length)]
    i, block, base, tmp = 0, 0, 0, 0
    while i != data_size:
        if block == 0:
            base = int.from_bytes(data[i:i+2][::-1])
            i += 2
            block = 0x10
        if (base & 1) == 0:
            out_buf[tmp] = data[i]
            tmp += 1
            i += 1
        else:
            c = data[i]
            next = data[i + 1]
            i += 2
            x1 = tmp - (next + (c & 0xf0) * 0x10)
            x2 = (c & 0xf) + 1
            while x2 != 0:
                out_buf[tmp] = out_buf[x1]
                tmp += 1
                x1 += 1
                x2 -= 1
        base = base >> 1
        block -= 1
    length = tmp
    out_buf = bytes(out_buf[:length])
    with open("output_file.bin", 'wb') as f:
        f.write(out_buf)
```

Running this on `data.bin` gives us this jpeg.![Flag image](https://nikzu.dev/writeups/backtrack/output_file.jpeg)

This also works for the other input file (to get the keylogger).

Flag: `ENO{M4lw4r3_3Nj0y3R5_Wh00P!}`

Solution script: [`backtrack.py`](https://nikzu.dev/writeups/backtrack/backtrack.py)

[ ](https://www.linkedin.com/shareArticle?mini=true&url=https://nikzu.dev/writeups/backtrack/&title=rev/backtrack%20-%20Nullcon%20HackIM%20CTF%20Goa%202025 "Share on LinkedIn")[ ](https://twitter.com/intent/tweet/?url=https://nikzu.dev/writeups/backtrack/&text=rev/backtrack%20-%20Nullcon%20HackIM%20CTF%20Goa%202025 "Tweet on Twitter")[ ](https://reddit.com/submit/?url=https://nikzu.dev/writeups/backtrack/&resubmit=true&title=rev/backtrack%20-%20Nullcon%20HackIM%20CTF%20Goa%202025 "Submit to Reddit")[ ](https://pinterest.com/pin/create/bookmarklet/?url=https://nikzu.dev/writeups/backtrack/&description=rev/backtrack%20-%20Nullcon%20HackIM%20CTF%20Goa%202025 "Pin on Pinterest")[ ](https://www.facebook.com/sharer/sharer.php?u=https://nikzu.dev/writeups/backtrack/&quote=rev/backtrack%20-%20Nullcon%20HackIM%20CTF%20Goa%202025 "Share on Facebook")[ ](https://nikzu.dev/cdn-cgi/l/email-protection#f0cf929f9489cd9884848083cadfdf9e999b8a85de949586df8782998495858083df9291939b848291939bdfd6919d80cb8385929a959384cd829586df9291939b848291939bd5c2c0ddd5c2c0be859c9c939f9ed5c2c0b891939bb9bdd5c2c0b3a4b6d5c2c0b79f91d5c2c0c2c0c2c5 "Send via email")[ ](https://api.whatsapp.com/send?text=https://nikzu.dev/writeups/backtrack/&resubmit=true&title=rev/backtrack%20-%20Nullcon%20HackIM%20CTF%20Goa%202025 "Share via WhatsApp")[](https://t.me/share/url?url=https://nikzu.dev/writeups/backtrack/&resubmit=true&title=rev/backtrack%20-%20Nullcon%20HackIM%20CTF%20Goa%202025 "Share via Telegram")
