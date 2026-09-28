---
title: "Third Times the Charm - UMassCTF 2024"
category: "crypto"
subcategory: "rsa"
type: "writeup"
tags: ["crypto", "rsa", "discrete-log", "chinese-remainder", "proof-of-work", "low-exponent", "umassctf", "umassctf-2024", "2024", "ctf-writeup"]
summary: "This page houses writeups for the four challenges I authored or co-authored for UMassCTF 2024:"
source:
  name: "CTFtime writeup #39070"
  url: "https://ctftime.org/writeup/39070"
original_source: "https://bburns.xyz/blog/umassctf2024.html#third-times-the-charm"
ctf:
  name: "UMassCTF 2024"
  year: 2024
  challenge: "Third Times the Charm"
---

## Metadata

- **CTF:** UMassCTF 2024
- **Task:** Third Times the Charm
- **Author team:** SavedByTheShell
- **CTFtime:** <https://ctftime.org/writeup/39070>
- **Original writeup:** <https://bburns.xyz/blog/umassctf2024.html#third-times-the-charm>

---
## [Benjamin A. Burns](https://bburns.xyz/)

# UMassCTF 2024 writeups

* * *

> Author writeups for UMassCTF 2024

* * *

This page houses writeups for the four challenges I authored or co-authored for [UMassCTF 2024](https://ctftime.org/event/2287/):

Challenge| Category| Level  
---|---|---  
Third Times the Charm| Crypto| Beginner  
100 Degrees| Crypto/Misc.| Beginner  
Krusty Katering| Misc.| Beginner  
Primitive Reversing| Rev| Medium  
  
With the exception of Primitive Reversing, my challenges were all written with beginners in mind. Third Times the Charm and 100 Degrees were intended to be for beginner Crypto players, Krusty Katering was an introduction to scripting with `nc` (netcat), and Primitive Reversing was a fun side project to cook up while TAing for our [Formal Language Theory course](https://people.cs.umass.edu/~barring/cs501/) here at UMass.

Hope that you enjoyed the CTF!

### Third Times the Charm

This challenge was intended to be a gentle introduction to the Crypto category. UMassCTF traditionally only offers rather advanced Crypto challenges, so we wanted to write a nice beginner challenge.

#### Challenge Description

![Third Times the Charm CTFd
photo](https://bburns.xyz/images/umassctf2024/third-times-the-charm.png)

#### Exploring the challenge

`main.py` contains the following

```
    from Crypto.Util.number import getPrime
     
    with open("flag.txt",'rb') as f:
        FLAG = f.read().decode()
        f.close()
     
     
    def encrypt(plaintext, mod):
        plaintext_int = int.from_bytes(plaintext.encode(), 'big')
        return pow(plaintext_int, 3, mod)
     
     
    while True:
        p = [getPrime(128) for _ in range(6)]
        if len(p) == len(set(p)):
            break
     
    N1, N2, N3 = p[0] * p[1], p[2] * p[3], p[4] * p[5]
    m1, m2, m3 = encrypt(FLAG, N1), encrypt(FLAG, N2), encrypt(FLAG, N3)
     
    pairs = [(m1, N1), (m2, N2), (m3, N3)]
    for i, pair in enumerate(pairs):
        print(f'm{i+1}: {pair[0]}\nN{i+1}: {pair[1]}\n')
```

Letâs start by looking at our encryption scheme. Given a string and a modulus N, the encryption scheme converts the string to an integer, cubes that integer, and returns that valuemodN. This alone seems ok: weâre encrypting the message via [RSA](https://en.wikipedia.org/wiki/RSA_\(cryptosystem\)), with public exponent e=3 and modulus N.

Our `main.py` script generates six pairwise-distinct 128-bit primes, which are then used to construct 3 coprime [RSA](https://en.wikipedia.org/wiki/RSA_\(cryptosystem\)) moduli N1â, N2â, and N3â. Then, we use the aforementioned encryption routine with each of the moduli to obtain three messages m1â, m2â, and m3â. Finally, we pair up the messages with their respective moduli, and print them.

It is known that solving [discrete log problem](https://en.wikipedia.org/wiki/Discrete_logarithm) is, in general, hard. Given any one of the messages m1â, we could extract the `FLAG` by solving the discrete log problem. However, this does not leverage any specific property of the challenge. In particular, it doesnât directly leverage that we are cubing, and that we are provided exactly three, coprime RSA moduli.

Instead, we observe that the value x we are searching for must solve the following system of congruences:

m1ââ¡x3modN1m2ââ¡x3modN2m3ââ¡x3modN3

Since we are guaranteed that the moduli N1â, N2â, and N3â are coprime, it is natural to apply [Chinese Remainder Theorem](https://en.wikipedia.org/wiki/Chinese_remainder_theorem) to solve this system of congruences for x3mod(N1ââN2ââN3â).

Observe that, if our message x is larger (as an integer) than any of our RSA moduli, decrypting m1â will return xmodN1â, not x. Therefore, we assume (for now) that our primes were selected to be large enough that x is smaller than all three moduli, and so it can be easily decrypted.

Let k denote the number of bits needed to write x as an integer. Observe that the product of an m bit number and an n bit number is at most an m+n bit number. This implies three key facts:

  1. each moduli is the product of two 128 bit primes, meaning they are 256 bit numbers.
  2. x3 is the product of three k bit numbers, and is therefore a 3k bit number.
  3. N1ââN2ââN3â is the product of three 256 bit numbers, and is therefore a 768 bit number.


Since we are assuming the message x is shorter than all the moduli, k<256, which implies 3k<256â3=768. By above, x3 (3k bits) is smaller than N1ââN2ââN3â (768 bits), so x3modN1ââN2ââN3 is equal to x3, since x3 is not big enough to âwrap aroundâ modN1ââN2ââN3â. Therefore, we do not have to solve the discrete log problem to acquire x from x3mod(N1ââN2ââN3â), as we can just take a regular cube root.

#### Crafting our exploit

Our exploit is as follows:

  1. Read the 6 numbers in from nc
  2. Apply a Chinese Remainder Theorem solve to obtain x3mod(N1ââN2ââN3â)
  3. Take the normal cube root of x3 to get x
  4. Convert x back to a string


Implementing this logic, we get

```
    from sympy.ntheory.modular import solve_congruence
    from sympy import cbrt
    import socket
     
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("127.0.0.1", 3333))
    data = [int(x.split(b' ')[1]) for x in s.recv(4096).split(b'\n') if x != b'']
     
    example_pairs = [(x, y) for x, y in zip(data[::2], data[1::2])]
     
    # Apply the Chinese Remainder Theorem
    M, _ = solve_congruence(*example_pairs)
    # Compute the cube root of M (doesn't require any modular arithmetic)
    plaintext_int = int(cbrt(M))
    # Convert the integer back to bytes (assuming it's properly padded/formatted)
    FLAG = plaintext_int.to_bytes((plaintext_int.bit_length() + 7) // 8, 'big').decode()
     
    print(f'Recovered FLAG: {FLAG}'
```

which we can then run to obtain our flag.

```
    UMASS{sunz1_su@nj1ng}
```

#### Takeaways

Hardness guarantees for modular arithmetic encryption schemes, such as RSA, often rely on the assumption that solving discrete log problem is difficult. While the message x needs to be smaller than the modulus N for us to decrypt, we need the encrypted message m to be larger than N so that m âwraps aroundâ mod N, and requires solving discrete log problem to directly obtain. However, in this case, we are given the same message encrypted with three different moduli, which allows us to exploit this length assumption to obtain the flag.

### 100 Degrees

The goal of this challenge was to be an introduction to Lagrange interpolation accessible to non-crypto players. I initially intended to write an [SSS](https://en.wikipedia.org/wiki/Shamir%27s_secret_sharing) challenge to piggyback off of this, but didnât get to it.

#### Challenge Description

![100 Degrees CTFd photo](https://bburns.xyz/images/umassctf2024/100-degrees.png)

#### Exploring the challenge

`journal.txt` contains the following content:

```
    p = 137
     
    DAY(0) = 81
    DAY(1) = 67
    ... # 98 additional lines
    DAY(100) = 22
     
    ----------------------------------------
     
    DAY(101) = ???
    DAY(102) = ???
    ... # 29 additional lines
    DAY(132) = ???
```

We see that the `journal.txt` file contains three sets of information: a prime number p=137, 101 days with known values, and 32 days with unknown values. From the description, we are told there is some âLagrangeâ guy who can help us out. The challenge name, 100 Degrees, and the fact that we are given 101 points, is the key piece of information. Any set of d+1 points with unique x coordinates lie on a unique degree d polynomial, which we can obtain via [Lagrange interpolation](https://en.wikipedia.org/wiki/Lagrange_polynomial).

If we apply Lagrange interpolationmod137, all of our 32 outputs will be numbers, not characters. However, a fair guess for us to make is that, since 137 is so close to 128, we should convert these decimal numbers to ASCII.

#### Crafting our exploit

Our exploit is as follows:

  1. Read in the prime from the first line
  2. Read in the 101 known values
  3. Apply Lagrange interpolation to acquire the 100 degree polynomial DAY(x) through these points
  4. Compute DAY(101) through DAY(132)
  5. Convert the outputs from decimal to ASCII, and print


First, we implement our Lagrange interpolation subroutine:

```
    from typing import List
     
     
    class Polynomial:
        def __init__(self, coefficients: List[int], p: int):
            self.coefficients = coefficients
            self.p = p
     
        def __add__(self, other: 'Polynomial'):
            assert self.p == other.p, "Polynomials are over different base fields"
     
            result = [0] * max(len(self.coefficients), len(other.coefficients))
            for i in range(len(self.coefficients)):
                result[i] = (result[i] + self.coefficients[i]) % self.p
            for i in range(len(other.coefficients)):
                result[i] = (result[i] + other.coefficients[i]) % self.p
            return Polynomial(result, self.p)
     
        def __mul__(self, other: 'Polynomial'):
            assert self.p == other.p, "Polynomials are over different base fields"
            result = [0] * (len(self.coefficients) + len(other.coefficients) - 1)
            for i, a in enumerate(self.coefficients):
                for j, b in enumerate(other.coefficients):
                    result[i + j] = (result[i + j] + a * b) % self.p
            return Polynomial(result, self.p)
     
        def __neg__(self):
            return Polynomial([-x for x in self.coefficients], self.p)
     
        def __sub__(self, other: 'Polynomial'):
            assert self.p == other.p, "Polynomials are over different base fields"
     
            return self + (-other)
     
        def __str__(self):
            return f'{self.coefficients} (mod {self.p})'
     
        def __call__(self, *args, **kwargs):
            x_to_i = 1
            y = self.coefficients[0]
            for a_i in self.coefficients[1:]:
                x_to_i = (x_to_i * args[0]) % self.p
                y += (a_i * x_to_i) % self.p
            return y % self.p
     
        def scalar_multiply(self, scalar: int):
            return Polynomial([(a_i * scalar) % self.p for a_i in self.coefficients], self.p)
     
        def degree(self):
            d = len(self.coefficients)
            while d > 0:
                d -= 1
                if self.coefficients[d]:
                    break
            return d
     
     
    def lagrange_interpolation(points, p):
        def lagrange_basis(k):
            # Constructs the k-th Lagrange basis polynomial
            basis = Polynomial([1], p)
            for j, (x_j, _) in enumerate(points):
                if j != k:
                    basis = basis * Polynomial([-x_j, 1], p)
                    denominator = (points[k][0] - x_j) % p
                    inv_denominator = pow(denominator, -1, p)  # Modular inverse
                    basis = basis.scalar_multiply(inv_denominator)
            return basis
     
        # Initialization of the interpolation polynomial
        interpolation_poly = Polynomial([0], p)
     
        # Constructing the interpolation polynomial
        for i, (_, y_i) in enumerate(points):
            # basis_poly = lagrange_basis(k).scalar_multiply(y_k)
            # term = basis_poly
            interpolation_poly = interpolation_poly + lagrange_basis(i).scalar_multiply(y_i)
     
        return interpolation_poly
```

Using our subroutine, we can now write our solve script

```
    from modpoly import lagrange_interpolation
     
    with open('journal.txt', 'r') as f:
        p = int(f.readline().split('p = ')[1])
     
        f.readline()  # Dump the empty line
     
        given_points = []
     
        for i in range(101):  # Read in the 101 points
            line = f.readline().strip()
            # Extract the value, and convert to integers
            # We know the x values will just count up so no need to extract them
            value = int(line.split('= ')[1])
            # Append the tuple to the list
            given_points.append((i, value))
     
    # Compute the polynomial
    DAY = lagrange_interpolation(given_points, p)
     
    x_vals = [i for i in range(101, 133)]
    y_vals = [DAY(x) for x in x_vals]
    flag = "".join([chr(y) for y in y_vals])
     
    print(flag)
```

which we can then run to obtain our flag.

```
    UMASS{1nt3rpr3t_n0r_1nt3rp0l@t3}
```

#### Takeaways

As mentioned previously, Lagrange interpolation is an important subroutine for cryptographic schemes such as [Shamirâs Secret Sharing](https://en.wikipedia.org/wiki/Shamir%27s_secret_sharing). It also provides a constructive proof that, for any d+1 points with unique x coordinates, there exists a degree d polynomial that passes through them, which is a good number-theoretic fact to know.

### Krusty Katering

Lots of CTF challenges involve talking to a remote connection via nc. This challenge was meant to give practice on how to talk to a nc via a script, as itâs intractable to respond to all 5000 jobs by hand.

#### Challenge Description

![100 Degrees CTFd
photo](https://bburns.xyz/images/umassctf2024/krusty-katering.png)

#### Exploring the challenge

Connecting to the given address repeats the above description, and shows the first job:

```
    Day 1. Time to beat: 10h41m10s
     
    Order #1: SpongeBob's Sundae
    âââ Price: $12
    âââ Estimated time to cook: 6m10s
     
     
    Which cook should handle this job? [1-10]
```

Responding with a number 1 through 10 then shows the next job. We can reply 1 repeatedly to verify the day serves 1000 jobs. We are then printed back the time it took our kitchen to finish all the jobs.

This is a classic online algorithms problem, commonly called the âonline job scheduling problemâ. Just using greedy algorithms (giving each job to the cook with the smallest queue) is sufficient. We only care about the estimated times to cook, so we can just throw the rest of the information away.

#### Crafting our solution

Our algorithm is as follows:

  1. Initialize 10 integers representing the current length of each cookâs queue.
  2. Iterate through the 1000 jobs, at each step adding the job to the cook with the shortest queue.
  3. Repeat until we make it to the end of the week.


Implementing our logic gives the following solve script

```
    from numpy import argmin
    from pwn import remote
     
    def parse_first_line(line):
        line = line.split(': ')[1]
        hours_str, remaining = line.split('h')
        minutes_str, remaining = remaining.split('m')
        seconds_str = remaining.split('s')[0]
     
        return int(hours_str) * 3600 + int(minutes_str) * 60 + int(seconds_str)
     
    def parse_time_line(line):
        line = line.split(': ')[1]
        if 'm' in line and 's' not in line:
            return int(line.split('m')[0]) * 60
        if 's' in line and 'm' not in line:
            return int(line.split('s')[0])
        num_min, remaining = line.split('m')
        return int(num_min) * 60 + int(remaining.split('s')[0])
     
    p = remote('krusty-katering.ctf.umasscybersec.org', 1337)
     
    for _ in range(5):
        # Throwaway lines before the day starts
        line = ''
        while not line.startswith('Day'):
            line = p.recvline().decode()
            print(line)
     
        # Read in time to beat from first line
        time_to_beat = parse_first_line(line)
     
        queue_times = [0] * 10
        
        for job_num in range(1000):
            while not line.startswith('âââ'):
                line = p.recvline().decode()
            job_time = parse_time_line(line)
     
            # Assign job to cook
            cook = argmin(queue_times)
            queue_times[cook] += job_time
     
            while not line.startswith('Which'):
                line = p.recvline().decode()
     
            # Send cook number  
            p.sendline((str(cook+1)).encode())
     
            # Print out current queue state
            print(f'Job: {job_num:<3}', end=' | ')
            print(f'Total time: {min(queue_times):<5}', end=' | ')
            print('Queue times:', end=' ')
            for time in queue_times:
                print(f'{time:<5}', end=' ')
            print()
     
    print(p.recv().decode())
```

which we can run to survive the week:

```
    You're hired, one could say that you're no UMASS{subst@nd@rd_c00k}
```

### Primitive Reversing

This is the fun challenge. People throw around the phrase [Turing complete](https://en.wikipedia.org/wiki/Turing_completeness) to say a programming language or application (i.e., [Excel with LAMBDA](https://www.microsoft.com/en-us/research/blog/lambda-the-ultimatae-excel-worksheet-function/)) is a sufficiently powerful programming language, in other words that itâs as powerful as a [Turing machine](https://en.wikipedia.org/wiki/Turing_machine). This challenge, and its sequel [Primitive Reversing 2](https://www.overleaf.com/project/662492450409f6351e0cdaf0), put that to the test.

#### Challenge Description

![Primitive Reversing CTFd
photo](https://bburns.xyz/images/umassctf2024/primitive-reversing.png)

#### Exploring the challenge

primitive-reversing.zip contains three files: an output file,

```
    [48, 48, 48, 49, 49, 48, 48, 49, 48, 49, 48, 49, 49, 48, 48, 49, 49, 49, 48, 48, 48, 48, 48, 48, 48, 49, 48, 49, 49, 48, 48, 48, 48, 49, 48, 49, 49, 48, 48, 48, 48, 48, 48, 49, 49, 48, 48, 48, 48, 48, 48, 49, 49, 48, 48, 49, 48, 49, 48, 48, 49, 49, 49, 48, 49, 49, 48, 49, 49, 49, 48, 48, 48, 48, 48, 49, 49, 48, 48, 49, 49, 49, 48, 48, 49, 49, 48, 48, 48, 49, 48, 48, 49, 48, 49, 49, 49, 48, 48, 49, 49, 48, 48, 48, 48, 49, 48, 48, 49, 49, 49, 48, 48, 49, 48, 48, 49, 49, 49, 49, 48, 48, 48, 49, 49, 48, 48, 48, 48, 49, 48, 48, 49, 49, 48, 49, 49, 48, 48, 49, 49, 48, 48, 48, 48, 49, 48, 49, 49, 48, 48, 48, 49, 48, 48, 49, 49, 48, 48, 48, 48, 49, 48, 49, 49, 49, 48, 48, 49, 49, 48, 49, 48, 49, 49, 49, 49, 49, 48, 49, 49, 49, 48, 49, 49, 48, 48, 49, 49, 48, 48, 48, 48, 49, 48, 49, 49, 49, 48, 49, 48, 49, 48, 48, 49, 49, 49, 48, 48, 49, 48, 48, 49, 49, 48, 48, 48, 49, 48, 49, 48, 49, 49, 49, 49, 49, 48, 48, 49, 48, 48, 48, 49, 48, 48, 49, 49, 48, 48, 49, 49, 49, 48, 49, 48, 49, 49, 49, 49, 49, 48, 48, 49, 49, 48, 48]
```

a Turing machine starter class,

```
    blank = 0
    ACCEPT = "#ACCEPT"
    REJECT = "REJECT"
    R = 1
    L = -1
    START = "#START"
     
    class State:
        def __init__(self):
            self.cursor = 0
            self.tape = []
            self.current_state = START
     
     
    class TuringMachine:
        def __init__(self):
            self.transitions = {}
     
        def run_machine(self, state: State):
            while True:
                if state.cursor == -1 or state.current_state == REJECT:
                    return REJECT
                if state.current_state == ACCEPT:
                    return ACCEPT
                if state.cursor >= len(state.tape):
                    state.tape += [blank] * 1000
                if (state.current_state, state.tape[state.cursor]) not in self.transitions:
                    return REJECT
     
                write, direction, next_state = self.transitions[(state.current_state, state.tape[state.cursor])]
                state.tape[state.cursor] = write
                state.current_state = next_state
                state.cursor += direction
     
        def add_transition(self, current, read, write, direction, next_state):
            self.transitions[(current, read)] = (write, direction, next_state)
     
     
    # put the input to the TM here
    INPUT = b""
    tm = TuringMachine()
     
    # load the TM in after this with tm.add_transition
    flag_state = State()
    flag_state.tape = [x for x in INPUT]
     
    tm.run_machine(flag_state)
    print(flag_state.tape)
```

and the state table of a Turing machine.

```
    State #234    253  253  R State #234   
    State #580    108  108  R State #580   
    State #258    125  125  R State #258   
    State #746    225  225  R State #746   
    State #144    193  193  R State #144   
    State #325    199  199  R State #325   
    State #202    137  137  R State #202 
    ... # 68k additional lines
    State #568    159  159  R State #568   
    State #120    0    48   R State #121   
    State #606    62   62   R State #606
```

The Turing machineâs state table is far too large to parse by hand. However, just peaking through the file, there are a few patterns:

  1. The overwhelming majority of the transitions go from an ASCII value to itself, stay in the same state, and move right.
  2. When any of the ASCII right-moving states sees a blank cell, it âswitches modesâ, and starts writing a binary string to the end of the tape.
  3. The output we are provided only has 48s and 49s, but our Turing machine supports all ASCII characters.


From this, we can guess that a subroutine the Turing machine implements is to convert an ASCII string to binary. The moving-right-until-blank pattern suggests that the machine does so by reading an ASCII character, reading all the way right until you see blank tape, writing that ASCII character in binary, returning left, and repeating.

From here, there are three main approaches, either brute force the Turing machine with ASCII inputs, attempt to backsolve the Turing machine by backtracking through the computation graph, or attempt to further analyze the machineâs state space to infer what it is doing. I take the third approach, but want to point something out about brute forcing.

The first approach is tractable, but requires us to implement a simulator for the machine. Furthermore, it is of upmost importance that we do our brute force intelligently, namely that we only try inputs that start with `UMASS{` and end with `}`.

In fact, the second step that the Turing machine takes is to read in the first 48 bytes, and check that they match the binary encoding of `UMASS{`, and read in the last 8 bytes to check that they match `}`. If we fail at any point of this process, we are sent to one of 56 different junk states. If we BFS from any of these states, we see that there is no path to the ACCEPT state. In fact, we discover that we landed in a torus graph, constructed from 13 disjoint 17-cycles, which carriage returns whenever it sees a blank, reads right until it sees a blank, writes, carriage returns, and so on.

```
    cr_length = 13
    num_subgraphs = 17
    subgraph_size = cr_length
    graph_size = num_subgraphs * subgraph_size
     
    # Carriage return states
    for i in range(cr_length):
        tm.add_transition(f'carriage return {i}', zero, zero, L, f'carriage return {i + 1}')
        tm.add_transition(f'carriage return {i}', one, one, L, f'carriage return {i + 1}')
    # When you finish carriage returning, go back to somewhere in the junk graph
    tm.add_transition(f'carriage return {cr_length}', zero, one, R, f'reject 0')
    tm.add_transition(f'carriage return {cr_length}', one, zero, R, f'reject {int(cr_length / 2)}')
     
    # Obfuscation graph
    # Make subgraphs, each of which is a cycle on alternating characters
    for i in range(num_subgraphs):
        for j in range(subgraph_size):
            k = i * subgraph_size + j
            cycle_successor = i * subgraph_size + ((j + 1) % subgraph_size)
            graph_successor = ((i + 1) % num_subgraphs) * subgraph_size + j
            tm.add_transition(f'reject {k}', ord(str(j % 2)), ord(str((j + 1) % 2)), R, f'reject {cycle_successor}')
            tm.add_transition(f'reject {k}', ord(str((j + 1) % 2)), ord(str(j % 2)), R, f'reject {graph_successor}')
    # Make graph states put down their parity and carriage return when they see a blank
    for i in range(graph_size):
        tm.add_transition(f'reject {i}', blank, ord(str(i % 2)), L, 'carriage return 0')
```

Primitive Reversing 1 was designed to be a lesson on brute forcing: if you know your input has certain structure, utilize that to your advantage. Once we filter out the ASCII conversion and junk graph states, the resulting function is relatively simple: states which swap pairs of bits and rotate the string. We just need to filter out noise

#### Recovering the flag

By our above analysis, we know that the Turing machine

  1. Converts the input string from ASCII to binary
  2. Checks that the binary string follows the `UMASS{...}` format, and deletes these characters
  3. Iterates through the remainder of the flag and swaps consecutive bits
  4. Left rotates the resulting string


Therefore, to recover the flag, we take the provided output, right rotate, swap consecutive bits, and convert to binary. Adding back the `UMASS{}` format, we obtain the flag

```
    UMASS{k0lm0g0r0v_w0uld_b3_d1s@pp01nt3d}
```
