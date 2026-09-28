---
title: "Go Sweep - m0leCon CTF 2025 Teaser"
category: "rev"
subcategory: "static-analysis"
type: "writeup"
tags: ["rev", "gef", "ghidra", "golang", "lsb", "sweep", "static-analysis", "m0lecon-ctf-2025-teaser", "2025", "ctf-writeup"]
summary: "We are given a binary called GoSweep:"
source:
  name: "CTFtime writeup #39468"
  url: "https://ctftime.org/writeup/39468"
original_source: "https://7rocky.github.io/en/ctf/other/m0lecon-ctf/go-sweep/"
ctf:
  name: "m0leCon CTF 2025 Teaser"
  year: 2025
  challenge: "Go Sweep"
---

## Metadata

- **CTF:** m0leCon CTF 2025 Teaser
- **Task:** Go Sweep
- **Author team:** thehackerscrew
- **CTFtime:** <https://ctftime.org/writeup/39468>
- **Original writeup:** <https://7rocky.github.io/en/ctf/other/m0lecon-ctf/go-sweep/>

---
We are given a binary called `GoSweep`:

`

```
    $ file GoSweep
    GoSweep: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, Go BuildID=E8AKvGNouZccNMS4QzKx/gv5u3Bl0aF1q0beXnu2L/ZgB_HzVs3SKcdMITee5O/W5Hg19NTpamr0Is20WCh, stripped
```

`

The binary runs a web server to play minesweeper. We have a nice UI on the remote URL:

![Go Sweep 1](https://7rocky.github.io/images/other/m0leCon%20CTF/Go-Sweep-1.webp)

It is a stripped binary compiled from Go, so it will be a bit hard to reverse-engineer. It is worth mentioning that this challenge was categorized as Reversing/Web, although I think it fits better in the Reversing side.

## Reverse engineering

The purpose of the challenge is quite obvious, we need to win the minesweeper game in time. Instead of trying to win the game using a minesweeper solver, it is better to find out how the board is generated and determine the mines’ positions.

This time, I am using IDA because Ghidra was awful with Go. For instance, IDA was able to detect Go functions:

![Go Sweep 2](https://7rocky.github.io/images/other/m0leCon%20CTF/Go-Sweep-2.webp)

### Board generation

Let’s start by analyzing how the minesweeper boards are generated. There are actually two functions, `main_initBoard` and `main_initLargeBoard`. We will start with the first one:

`

```
    // main.initBoard
    __int64 __golang main_initBoard(int64 a1, int a2, int a3, unsigned __int64 a4, int a5, int a6, int a7, int a8, int a9)
    {
      // ...
    
      slice = runtime_makeslice((unsigned int)&RTYPE__slice_structs_Cell, 20, 20, a4, a5, a6, a7, a8, a9);
      for ( i = 0LL; i < 20; i = v16 + 1 )
      {
        v38 = i;
        v15 = runtime_makeslice((unsigned int)&RTYPE_structs_Cell, 20, 20, a4, a5, v10, v11, v12, (_DWORD)v13);
        v16 = v38;
        if ( v38 >= 20 )
          runtime_panicIndex(v38);
        a5 = slice;
        a4 = 3 * v38;
        *(_QWORD *)(slice + 8 * a4 + 8) = 20LL;
        *(_QWORD *)(slice + 8 * a4 + 16) = 20LL;
        if ( dword_93B840 )
        {
          v15 = runtime_gcWriteBarrier2(v15);
          *v13 = v15;
          v10 = *(_QWORD *)(slice + 24 * v38);
          v13[1] = v10;
        }
        *(_QWORD *)(slice + 24 * v38) = v15;
      }
      p_rand_rngSource = (rand_rngSource *)runtime_newobject(&RTYPE_rand_rngSource);
      math_rand__ptr_rngSource_Seed(p_rand_rngSource, a1);
      for ( j = 0xE839DD11LL; ; j = v23 )
      {
        v20 = j;
        v21 = 16 * (*(_QWORD *)off_8CFC80 & j);
        v22 = *(RTYPE **)((char *)off_8CFC80 + v21 + 8);
        if ( v22 == &RTYPE__ptr_rand_rngSource )
          break;
        v23 = v20 + 1;
        if ( !v22 )
        {
          v24 = runtime_typeAssert(
                  (unsigned int)&off_8CFC80,
                  (unsigned int)&RTYPE__ptr_rand_rngSource,
                  (_DWORD)off_8CFC80,
                  a4,
                  v21,
                  v23,
                  0,
                  v17,
                  v18);
          goto LABEL_13;
        }
      }
      v24 = *(_QWORD *)((char *)off_8CFC80 + v21 + 16);
    LABEL_13:
      v41 = v9;
      v40[0] = off_734748;
      v40[1] = p_rand_rngSource;
      v40[2] = v24;
      v40[3] = p_rand_rngSource;
      numMines = 0LL;
      while ( numMines < 150 )
      {
        tmpNumMines = numMines;
        a = math_rand__ptr_Rand_Intn(v40, 20LL);
        b = math_rand__ptr_Rand_Intn(v40, 20LL);
        if ( a >= 20 )
          runtime_panicIndex(a);
        if ( b >= *(_QWORD *)(slice + 24 * a + 8) )
          runtime_panicIndex(b);
        bomb = (_BYTE *)(*(_QWORD *)(slice + 24 * a) + 24 * b + 1);
        if ( *bomb )
        {
          numMines = tmpNumMines;
        }
        else
        {
          *bomb = 1;
          for ( k = -1LL; k <= 1; ++k )
          {
            for ( m = -1LL; m <= 1; ++m )
            {
              v31 = k + a;
              v32 = m + b;
              if ( k + a < 20 && v32 < 20 )
              {
                if ( v31 >= 20 )
                  runtime_panicIndex(k + a);
                v33 = 3 * v31;
                v34 = *(_QWORD *)(slice + 8 * v33 + 8);
                v35 = *(_QWORD *)(slice + 8 * v33);
                if ( v34 <= v32 )
                  runtime_panicIndex(m + b);
                ++*(_QWORD *)(v35 + 24 * v32 + 8);
              }
            }
          }
          numMines = tmpNumMines + 1;
        }
      }
      return slice;
    }
```

`

As you can see, although IDA deals correctly with Go, the decompilation is very ugly and difficult to read.

The board definition seems clear, it’s just a 20x20 slice:

`

```
      slice = runtime_makeslice((unsigned int)&RTYPE__slice_structs_Cell, 20, 20, a4, a5, a6, a7, a8, a9);
      for ( i = 0LL; i < 20; i = v16 + 1 )
      {
        v38 = i;
        v15 = runtime_makeslice((unsigned int)&RTYPE_structs_Cell, 20, 20, a4, a5, v10, v11, v12, (_DWORD)v13);
        v16 = v38;
        if ( v38 >= 20 )
          runtime_panicIndex(v38);
        a5 = slice;
        a4 = 3 * v38;
        *(_QWORD *)(slice + 8 * a4 + 8) = 20LL;
        *(_QWORD *)(slice + 8 * a4 + 16) = 20LL;
        if ( dword_93B840 )
        {
          v15 = runtime_gcWriteBarrier2(v15);
          *v13 = v15;
          v10 = *(_QWORD *)(slice + 24 * v38);
          v13[1] = v10;
        }
        *(_QWORD *)(slice + 24 * v38) = v15;
      }
```

`

As can be seen, I set a variable name to `slice` to improve the reverse-engineering process. Still, some points are still not clear. For instance, why there are some `24` out there? It’s a strange offset.

These strange things come again when the board is being filled with bombs:

`

```
      numMines = 0LL;
      while ( numMines < 150 )
      {
        tmpNumMines = numMines;
        a = math_rand__ptr_Rand_Intn(v40, 20LL);
        b = math_rand__ptr_Rand_Intn(v40, 20LL);
        if ( a >= 20 )
          runtime_panicIndex(a);
        if ( b >= *(_QWORD *)(slice + 24 * a + 8) )
          runtime_panicIndex(b);
        bomb = (_BYTE *)(*(_QWORD *)(slice + 24 * a) + 24 * b + 1);
        if ( *bomb )
        {
          numMines = tmpNumMines;
        }
        else
        {
          *bomb = 1;
          for ( k = -1LL; k <= 1; ++k )
          {
            for ( m = -1LL; m <= 1; ++m )
            {
              v31 = k + a;
              v32 = m + b;
              if ( k + a < 20 && v32 < 20 )
              {
                if ( v31 >= 20 )
                  runtime_panicIndex(k + a);
                v33 = 3 * v31;
                v34 = *(_QWORD *)(slice + 8 * v33 + 8);
                v35 = *(_QWORD *)(slice + 8 * v33);
                if ( v34 <= v32 )
                  runtime_panicIndex(m + b);
                ++*(_QWORD *)(v35 + 24 * v32 + 8);
              }
            }
          }
          numMines = tmpNumMines + 1;
        }
      }
      return slice;
```

`

This part took me a while to fully understand it. It is obvious that `a` and `b` are two random numbers between `0` and `19`, which represent row and column where to place a bomb. These numbers are generated using `math/rand`, initialized with a seed.

Also, we see a `while` loop until `numMines` equals `150`, so it’s clear that the 20x20 board will have 150 bombs.

We can also notice that if `bomb` is already a `1`, the program does not increase `numMines` and continues to the next loop iteration. After that, we see two nested `for` loops, both from `-1` to `1`. These `for` loops are meant to increase the amount of adjacent mines on the adjacent cells:

`

```
          for ( k = -1LL; k <= 1; ++k )
          {
            for ( m = -1LL; m <= 1; ++m )
            {
              v31 = k + a;
              v32 = m + b;
              if ( k + a < 20 && v32 < 20 )
              {
                if ( v31 >= 20 )
                  runtime_panicIndex(k + a);
                v33 = 3 * v31;
                v34 = *(_QWORD *)(slice + 8 * v33 + 8);
                v35 = *(_QWORD *)(slice + 8 * v33);
                if ( v34 <= v32 )
                  runtime_panicIndex(m + b);
                ++*(_QWORD *)(v35 + 24 * v32 + 8);
              }
            }
          }
```

`

However, the following code snippets look weird, due to the offsets of `1`, `8` and `24`:

`

```
        bomb = (_BYTE *)(*(_QWORD *)(slice + 24 * a) + 24 * b + 1);
```

`

`

```
                ++*(_QWORD *)(v35 + 24 * v32 + 8);
```

`

The key to understand this part lies in a function called `type__eq_mines_struct_Cell`:

`

```
    // type:.eq.mines/struct.Cell
    bool __golang type__eq_mines_struct_Cell(__int64 a1, __int64 a2)
    {
      return *(_BYTE *)a2 == *(_BYTE *)a1
          && *(_BYTE *)(a2 + 1) == *(_BYTE *)(a1 + 1)
          && *(_QWORD *)(a2 + 8) == *(_QWORD *)(a1 + 8)
          && *(_BYTE *)(a2 + 16) == *(_BYTE *)(a1 + 16);
    }
```

`

With this, we can guess that each cell is implemented as a `struct` with 4 types (1 byte, 1 byte, 8 byte, 1 byte). This makes sense if we take a look at the generated board in GDB. We can set a breakpoint at `main_initBoard` (`0x643f20`) and hit `finish`:

`

```
    $ gdb -q GoSweep
    Reading symbols from GoSweep...
    (No debugging symbols found in GoSweep)
    gef> break *0x643f20
    Breakpoint 1 at 0x643f20
    gef> run
    Starting program: /root/GoSweep/GoSweep
    [Thread debugging using libthread_db enabled]
    Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
    [New Thread 0x7fffb12d6640 (LWP 4141107)]
    [New Thread 0x7fffb0ad5640 (LWP 4141108)]
    [New Thread 0x7fffabfff640 (LWP 4141116)]
    [New Thread 0x7fffab7fe640 (LWP 4141119)]
    [New Thread 0x7fffaaffd640 (LWP 4141132)]
    2024/09/14 19:18:21 Server started on :8080
    
    Thread 1 "GoSweep" hit Breakpoint 1, 0x0000000000643f20 in ?? ()
```

`

Now, we make a request to the server for a new board (`curl 127.0.0.1:8080/new`) and the program will hit the breakpoint:

`

```
    gef> finish
    Run till exit from #0  0x0000000000643f20 in ?? ()
    0x000000000064478c in ?? ()
```

`

Here we can see the slice of slices:

`

```
    gef> x/10gx $rax
    0xc0001cc000:   0x000000c0001ce000      0x0000000000000014
    0xc0001cc010:   0x0000000000000014      0x000000c0001ce1e0
    0xc0001cc020:   0x0000000000000014      0x0000000000000014
    0xc0001cc030:   0x000000c0001ce3c0      0x0000000000000014
    0xc0001cc040:   0x0000000000000014      0x000000c0001ce5a0
```

`

It makes sense because in Go, a slice is formed by a pointer to the elements (`ptr`), an integer that represents the length of the slice (`len`), and another integer that represents the capacity of the slice (`cap`). Both integer fields are `0x14`, or `20` in decimal format, which is correct. More information about Go slices internals at [go.dev](https://go.dev/blog/slices-intro).

If we examine the first `ptr` we get the array of `Cell` structures:

`

```
    gef> x/30gx 0x000000c0001ce000
    0xc0001ce000:   0x0000000000000100      0x0000000000000004
    0xc0001ce010:   0x0000000000000000      0x0000000000000100
    0xc0001ce020:   0x0000000000000005      0x0000000000000000
    0xc0001ce030:   0x0000000000000100      0x0000000000000003
    0xc0001ce040:   0x0000000000000000      0x0000000000000000
    0xc0001ce050:   0x0000000000000001      0x0000000000000000
    0xc0001ce060:   0x0000000000000000      0x0000000000000000
    0xc0001ce070:   0x0000000000000000      0x0000000000000000
    0xc0001ce080:   0x0000000000000001      0x0000000000000000
    0xc0001ce090:   0x0000000000000000      0x0000000000000001
    0xc0001ce0a0:   0x0000000000000000      0x0000000000000000
    0xc0001ce0b0:   0x0000000000000002      0x0000000000000000
    0xc0001ce0c0:   0x0000000000000100      0x0000000000000002
    0xc0001ce0d0:   0x0000000000000000      0x0000000000000000
    0xc0001ce0e0:   0x0000000000000003      0x0000000000000000
```

`

For instance, this is one single `Cell` (`0x18` bytes, which is `24` in decimal format):

`

```
    gef> x/3gx 0x000000c0001ce000
    0xc0001ce000:   0x0000000000000100      0x0000000000000004
    0xc0001ce010:   0x0000000000000000
```

`

And it means that the cell contains a bomb and there are 4 adjacent bombs. The rest of the fields are still unknown.

However, if we take a look at the web requests, we can guess the other two fields (`revealed` and `flagged`):

![Go Sweep 3](https://7rocky.github.io/images/other/m0leCon%20CTF/Go-Sweep-3.webp)

So, the only remaining part of the board generation is to determine the seed. But the server shows the seed!

![Go Sweep 4](https://7rocky.github.io/images/other/m0leCon%20CTF/Go-Sweep-4.webp)

## Solution

With all this, we can implement a function in Go to generate the same board given this seed:

`

```
    func initBoard(seed int64, size, mines int) [][]Cell {
            r := rand.New(rand.NewSource(seed))
            board := make([][]Cell, size)
            numMines := 0
    
            for i := range size {
                    board[i] = make([]Cell, size)
            }
    
            for numMines < mines {
                    a := r.Intn(size)
                    b := r.Intn(size)
    
                    if !board[a][b].Bomb {
                            board[a][b].Bomb = true
    
                            for k := -1; k <= 1; k++ {
                                    for m := -1; m <= 1; m++ {
                                            if k+a < size && m+b < size && k+a >= 0 && m+b >= 0 {
                                                    board[k+a][m+b].Adjacent++
                                            }
                                    }
                            }
    
                            numMines++
                    }
            }
    
            return board
    }
```

`

Where `Cell` is the following `struct`:

`

```
    type Cell struct {
            Revealed bool `json:"revealed"`
            Bomb     bool `json:"bomb"`
            Adjacent int  `json:"adjacent"`
            Flagged  bool `json:"flagged"`
    }
```

`

Once I checked with GDB that the above code generated the same board, I implemented a way to win the game using web requests:

`

```
    func reveal(gameId string, c, r int) *RevealCells {
            guard <- struct{}{}
    
            res, err := http.PostForm(fmt.Sprintf("%s/reveal?gameID=%s&col=%d&row=%d", URL, gameId, c, r), nil)
    
            if err != nil {
                    panic(err)
            }
    
            body, err := io.ReadAll(res.Body)
    
            if err != nil {
                    panic(err)
            }
    
            defer res.Body.Close()
    
            var data *RevealCells
    
            if err := json.Unmarshal(body, &data); err != nil {
                    panic(err)
            }
    
            <-guard
            return data
    }
    
    func solve(url string, size, mines int) {
            res, err := http.Get(url)
    
            if err != nil {
                    panic(err)
            }
    
            body, err := io.ReadAll(res.Body)
    
            if err != nil {
                    panic(err)
            }
    
            defer res.Body.Close()
    
            var data *Board
    
            if err := json.Unmarshal(body, &data); err != nil {
                    panic(err)
            }
    
            board := initBoard(data.Seed, size, mines)
    
            for r := range size {
                    for c := range size {
                            go func() {
                                    wg.Add(1)
                                    defer wg.Done()
    
                                    if !board[r][c].Bomb {
                                            data := reveal(data.GameId, c, r)
    
                                            if data.Message != "" {
                                                    fmt.Println(data.Message)
                                            }
                                    }
                            }()
                    }
            }
    
            wg.Wait()
    }
```

`

It is important to use threads in order to win the game in time. Once we solve the game, we are not given the flag, but some nanoseconds:

`

```
    $ go run solve.go
    Good job! Take some nanos: 1726246281186930269
```

`

It’s worth mentioning that it is always the same number.

### Large board

If we take a look at `main_revealCellHandler`:

`

```
          v130 = v46[7];
          if ( *(_QWORD *)(v130 + 32) )
          {
            time_stopTimer(v130 + 8, (_DWORD)v49, v48, v128, v50, (_DWORD)v42, (_DWORD)v43, (_DWORD)v44, v45, v331);
            v367 = v9;
            v136 = runtime_convT64(qword_93B3B0, (_DWORD)v49, v131, v128, v50, v132, v133, v134, v135);
            *(_QWORD *)&v367 = &RTYPE_int;
            *((_QWORD *)&v367 + 1) = v136;
            *((_QWORD *)&v147 + 1) = 1LL;
            v352 = fmt_Sprintf(
                     (unsigned int)"Good job! Take some nanos: %d",
                     29,
                     (unsigned int)&v367,
                     1,
                     1,
                     v137,
                     v138,
                     v139,
                     v140,
                     v331,
                     v332,
                     v333,
                     v334);
            v341 = 29LL;
            // ...
            *v152 = v157;
            if ( v357[3] == 50LL )
            {
              if ( v357[4] == 50LL )
              {
                File = os_ReadFile(
                         (unsigned int)"flag.txt",
                         8,
                         (_DWORD)v357,
                         v147,
                         1,
                         v153,
                         v154,
                         v155,
                         (_DWORD)v156,
                         v331,
                         v332);
          *((_BYTE *)v46 + 40) = 1;
                if ( (_QWORD)v147 )
                {
                  v346 = 8LL;
                  v360 = File;
                  v367 = v9;
                  *(_QWORD *)&v147 = *(_QWORD *)(v147 + 8);
                  v367 = v147;
                  LODWORD(v147) = 1;
                  DWORD2(v147) = 1;
                  log_Fatalf(
                    (unsigned int)"Unable to read flag: %v",
                    23,
                    (unsigned int)&v367,
                    1,
                    1,
                    v161,
                    v162,
                    v163,
                    v164,
                    v331,
                    v332,
                    v333,
                    v334,
                    v335);
                  LODWORD(File) = v360;
                }
                v367 = v9;
                v165 = File;
                v166 = runtime_slicebytetostring(0, File, 8, v147, DWORD2(v147), v161, v162, v163, v164, v331, v332, v333);
                v172 = runtime_convTstring(v166, v165, v167, v147, DWORD2(v147), v168, v169, v170, v171, v331);
                *(_QWORD *)&v367 = &RTYPE_string;
                *((_QWORD *)&v367 + 1) = v172;
                v158 = 36LL;
                LODWORD(v147) = 1;
                *((_QWORD *)&v147 + 1) = 1LL;
                v159 = fmt_Sprintf(
                         (unsigned int)"Congratulations! Take some chars: %s[...]",
                         36,
                         (unsigned int)&v367,
                         1,
                         1,
                         v173,
                         v174,
                         v175,
                         v176,
                         v331,
                         v332,
                         v333,
                         v334);
              }
```

`

We see that there are two different responses when we win the game (the nanoseconds and the flag). Looking at other functions, there are some of them related to a “large” board. Actually, `main_initLargeBoard` is the same as `main_initBoard` but with a 50x50 board and 2000 bombs.

The problem is that the `/new` endpoint only works for the 20x20 board. The 50x50 board is hidden. We can see how it is generated in `main_main` when the server starts:

`

```
    // main.main
    void __fastcall main_main()
    {
      // ...
    
      p_http_fileHandler = (http_fileHandler *)runtime_newobject(&RTYPE_http_fileHandler);
      p_http_fileHandler->root.tab = off_7336A0;
      p_http_fileHandler->root.data = &off_732060;
      v3 = p_http_fileHandler;
      net_http_Handle((unsigned int)&unk_6B93F8, 1, (unsigned int)off_7336C0, (_DWORD)p_http_fileHandler, v0, v4, v5, v6);
      Seed = mines_randomizer_CreateSeed(qword_93B3B0, 1LL, v7, (__int64)v3, v0, v8, v9, v10, v11);
      Endpoint = mines_randomizer_CreateEndpoint(Seed, 1, v13, (int)v3, v0, v14, v15, v16, v17);
      v72[0] = (__int64)&RTYPE_string;
      v72[1] = runtime_convTstring(Endpoint, 1, v19, (_DWORD)v3, v0, v20, v21, v22, v23, v54);
      v28 = fmt_Sprintf((unsigned int)&unk_6B949E, 3, (unsigned int)v72, 1, 1, v24, v25, v26, v27, v55, v62, v64, v66);
      net_http_HandleFunc(v28, 3, (unsigned int)off_6E8A80, 1, 1, v29, v30, v31, v32, v56);
    
      // ...
    }
```

`

The relevant part here is that the `Endpoint` is generated from a `Seed`, which is returned from a function called `mines_randomizer_CreateSeed`. This function is hard to reverse-engineer. On the other hand, we can see that `mines_randomizer_CreateEndpoint` is just a MD5 hash of the `Seed` in text format:

`

```
    // mines/randomizer.CreateEndpoint
    __int64 __golang mines_randomizer_CreateEndpoint(
            int a1,
            int a2,
            int a3,
            int a4,
            int a5,
            int a6,
            int a7,
            int a8,
            int a9)
    {
      // ...
    
      v53[0] = &RTYPE_int64;
      v53[1] = runtime_convT64(a1, a2, a3, a4, a5, a6, a7, a8, a9);
      v9 = 1;
      v10 = 1;
      v15 = fmt_Sprintf(
              (unsigned int)"%d80; ./h2%wTe]:%T\r\n\">OK2500",
              2,
              (unsigned int)v53,
              1,
              1,
              v11,
              v12,
              v13,
              v14,
              v39,
              v43,
              v45,
              v49);
      v20 = runtime_stringtoslicebyte((unsigned int)&v52, v15, 2, 1, 1, v16, v17, v18, v19, v40, v44, v46);
      crypto_md5_Sum(v20, v15, v21, 1, 1, v22, v23, v24, v25, v41, v47, v50);
      v51 = v42;
      slice = runtime_makeslice((unsigned int)&RTYPE_uint8, 32, 32, 1, 1, v26, v27, v28, v29);
      i = 0LL;
      j = 0LL;
      while ( i < 16 )
      {
        v37 = *((_BYTE *)&v51 + i);
        v31 = "0123456789abcdef";
        if ( j >= 0x20 )
          runtime_panicIndex(j);
        *(_BYTE *)(slice + j) = a0123456789abcd[v37 >> 4];
        v10 = j + 1;
        v9 = (unsigned __int8)a0123456789abcd[v37 & 0xF];
        if ( j + 1 >= 0x20 )
          runtime_panicIndex(j + 1);
        *(_BYTE *)(j + slice + 1) = v9;
        ++i;
        j += 2LL;
      }
      return runtime_slicebytetostring(0, slice, 32, v9, v10, (_DWORD)v31, v32, v33, v34, v42, *((__int64 *)&v42 + 1), v48);
    }
```

`

One feature of Go is that strings are not null-terminated. Instead, a string always appears together with its length. That’s why the following instruction is the equivalent to `fmt.Sprintf("%d", v53)`:

`

```
      v15 = fmt_Sprintf(
              (unsigned int)"%d80; ./h2%wTe]:%T\r\n\">OK2500",
              2,
              (unsigned int)v53,
              1,
              1,
              v11,
              v12,
              v13,
              v14,
              v39,
              v43,
              v45,
              v49);
```

`

When I was testing, I took the hidden endpoint from GDB by setting breakpoints at `mines_randomizer_CreateEndpoint` (`0x53c280`) and `mines_randomizer_CreateSeed` (`0x53c3a0`). Then, I realized that calling the hidden endpoint was actually the same as calling `/new`. I mean, we are given a seed to generate the 50x50 board. Once we generate and win the game, the server will return the flag.

The only thing left was to determine what was the input to `mines_randomizer_CreateSeed`. This had to be something fixed, because the hidden endpoint is defined when the server starts, and it is not supposed to be restarted by the user.

After a lot of tests, I found out that the input to `mines_randomizer_CreateSeed` was the current time in nanoseconds. In fact, the number returned from the first board is the time when the server was started (it was about 10 minutes before the CTF started, so it was good).

So, we have everything; well, almost. Instead of reverse-engineering `mines_randomizer_CreateSeed`, we can use GDB to modify the input to `mines_randomizer_CreateSeed` and get the expected result. Then, we compute the MD5 hash and we will have the hidden endpoint:

`

```
    $ gdb -q GoSweep
    Reading symbols from GoSweep...
    (No debugging symbols found in GoSweep)
    gef> break *0x53c3a0
    Breakpoint 1 at 0x53c3a0
    gef> run
    Starting program: /root/GoSweep/GoSweep
    [Thread debugging using libthread_db enabled]
    Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
    [New Thread 0x7fffb12d6640 (LWP 4155745)]
    [New Thread 0x7fffb0ad5640 (LWP 4155761)]
    [New Thread 0x7fffabfff640 (LWP 4155763)]
    [New Thread 0x7fffab7fe640 (LWP 4155764)]
    [New Thread 0x7fffaaffd640 (LWP 4155773)]
    
    Thread 1 "GoSweep" hit Breakpoint 1, 0x000000000053c3a0 in ?? ()
```

`

`

```
    gef> set $rax = (long) 1726246281186930269
    gef> finish
    Run till exit from #0  0x000000000053c3a0 in ?? ()
    0x0000000000647e1b in ?? ()
```

`

`

```
    gef> p/d $rax
    $1 = 60357764246024467
    gef> quit
    
    $ python3 -q
    >>> from hashlib import md5
    >>> md5(b'60357764246024467').hexdigest()
    '48f99e62219f9bfd9fd437b75e0d46f9'
```

`

At this point, we can reuse the functions from the script and simply add these functions to solve the challenge:

`

```
    const URL = "https://gosweep.challs.m0lecon.it"
    
    func main() {
            solve(fmt.Sprintf("%s/new", URL), 20, 150)
            solve(fmt.Sprintf("%s/48f99e62219f9bfd9fd437b75e0d46f9", URL), 50, 2000)
    }
```

`

## Flag

If we run the script, we will get the flag:

`

```
    $ go run solve.go
    Good job! Take some nanos: 1726246281186930269
    Congratulations! Take some chars: ptm{wh0_n33ds_luck_wh3n_y0u_h4v3_r3v3rs3?}
```

`

The full script can be found in here: [`solve.go`](https://github.com/7Rocky/CTF-scripts/tree/main/m0leCon%20CTF/Go%20Sweep/solve.go).
