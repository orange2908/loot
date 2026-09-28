---
title: "[Cripto] Shiro Hero - L3akCTF 2025"
category: "crypto"
subcategory: "aes"
type: "writeup"
tags: ["crypto", "aes", "ecc", "ecdsa", "cbc", "prng", "z3", "l3akctf", "l3akctf-2025", "2025", "ctf-writeup"]
summary: "En este reto, tenemos el siguiente archivo."
source:
  name: "CTFtime writeup #40523"
  url: "https://ctftime.org/writeup/40523"
original_source: "https://k3sero.github.io/posts/Shiro-Hero-L3AK2025/"
ctf:
  name: "L3akCTF 2025"
  year: 2025
  challenge: "[Cripto] Shiro Hero"
---

## Metadata

- **CTF:** L3akCTF 2025
- **Task:** [Cripto] Shiro Hero
- **Author team:** Caliphal Hounds
- **CTFtime:** <https://ctftime.org/writeup/40523>
- **Original writeup:** <https://k3sero.github.io/posts/Shiro-Hero-L3AK2025/>

---
Shiro Hero - L3AK2025 __

Contenido __

Shiro Hero - L3AK2025

__

Autor del reto: `supasuge`

Dificultad: Media

## Enunciado __

“None”

##  Archivos __

En este reto, tenemos el siguiente archivo.

  * `chall.py`: Contiene el script principal de cifrado.
  * `ecc.py`: Contiene el script principal de la curva elíptica utilizada.
  * `prng.py`: Contiene el script creador del PRNG.
  * `output.txt`: Contiene la salida del script principal.


Archivos utilizados en mi [repositorio de Github](https://github.com/k3sero/Blog_Content/tree/main/Competiciones_Internacionales_Writeups/2025/L3AKCTF2025/Cripto/Shiro%20Hero).

## Analizando el reto __

En este reto, tenemos tres componentes principales:

  1. **PRNG personalizado (`xorshiro256`)**
  2. **Firmas ECDSA sobre la curva`secp256k1`**
  3. **Encriptación AES con clave derivada del secreto ECDSA**


Si abrimos el archivo `chall.py` encontramos lo siguiente.

____

`

```
    1
    2
    3
    4
    5
    6
    7
    8
    9
    10
    11
    12
    13
    14
    15
    16
    17
    18
    19
    20
    21
    22
    23
    24
    25
    26
    27
    28
    29
    30
    31
    32
```

| 

```
     from secrets import randbits
    from prng import xorshiro256
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
    from ecc import ECDSA
    from Crypto.Util.number import bytes_to_long, long_to_bytes
    import hashlib
    flag = open("flag.txt", "rb").read()
    state = [randbits(64) for _ in range(4)]
    prng = xorshiro256(state)
    leaks = [prng.next_raw() for _ in range(4)]
    print(f"PRNG leaks: {[hex(x) for x in leaks]}")
    Apriv, Apub = ECDSA.gen_keypair()
    print(f"public_key = {Apub}")
    msg = b"My favorite number is 0x69. I'm a hero in your mother's bedroom, I'm a hero in your father's eyes. What am I?"
    H = bytes_to_long(msg)
    sig = ECDSA.ecdsa_sign(H, Apriv, prng)                  
    print(f"Message = {msg}")
    print(f"Hash = {H}")
    print(f"r, s = {sig}")
    key = hashlib.sha256(long_to_bytes(Apriv)).digest()
    iv = randbits(128).to_bytes(16, "big")
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = iv.hex() + cipher.encrypt(pad(flag, 16)).hex()
    print(f"ciphertext = {ciphertext}")
    with open("output.txt", "w") as f:
        f.write(f"PRNG leaks: {[hex(x) for x in leaks]}\n")
        f.write(f"public_key = {Apub}\n")
        f.write(f"Message = {msg}\n")
        f.write(f"Hash = {H}\n")
        f.write(f"r, s = {sig}\n")
        f.write(f"ciphertext = {ciphertext}\n")
```  
  
---|---  
`

  1. Se genera el estado inicial de 256 bits para el PRNG.
  2. Se crea una instancia del PRNG `xorshiro256`.
  3. Se generan 4 valores crudos del PRNG (no temperados) y se filtran.
  4. Se genera un par de claves ECDSA (`Apriv`, `Apub`).
  5. Se firma un mensaje usando ECDSA, con una `k` generada del PRNG. Esta `k` debe ser secreta, pero el PRNG que la genera ha sido filtrado parcialmente.
  6. Se deriva una clave AES a partir de la clave privada ECDSA, y se cifra la flag.


Si abrimos el archivo `ecc.py` encontramos lo siguiente.

____

`

```
    1
    2
    3
    4
    5
    6
    7
    8
    9
    10
    11
    12
    13
    14
    15
    16
    17
    18
    19
    20
    21
    22
    23
    24
    25
    26
    27
    28
    29
    30
    31
    32
    33
    34
    35
    36
    37
    38
    39
    40
    41
    42
    43
    44
    45
    46
    47
    48
    49
    50
    51
    52
    53
    54
    55
    56
    57
    58
    59
    60
    61
    62
    63
    64
    65
    66
    67
    68
    69
    70
    71
    72
    73
    74
    75
    76
    77
    78
    79
    80
    81
    82
    83
    84
    85
    86
```

| 

```
     #!/usr/bin/env python3
    import random
    from hashlib import sha3_256, sha256
    from Crypto.Util.number import bytes_to_long, inverse
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import unpad, pad
    from prng import xorshiro256, MASK64     
    import hashlib
    import os
    
    class ECDSA:
        """ECDSA implementation for secp256k1 curve"""
        # parameters
        p  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
        a  = 0
        b  = 7
        Gx = 55066263022277343669578718895168534326250603453777594175500187360389116729240
        Gy = 32670510020758816978083085130507043184471273380659243275938904335757337482424
        n  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        G  = (Gx, Gy)
    
        @staticmethod   
        def digest(msg: bytes) -> int:
            """Hash a message and return as integer"""
            return bytes_to_long(sha256(msg).digest())
    
        @staticmethod
        def point_add(P, Q):
            """Add two points on the elliptic curve"""
            if P == (None, None): 
                return Q
            if Q == (None, None): 
                return P
            (x1, y1), (x2, y2) = P, Q
            if x1 == x2 and (y1 + y2) % ECDSA.p == 0: return (None, None)
            if P == Q:
                l = (3 * x1 * x1) * inverse(2 * y1, ECDSA.p) % ECDSA.p
            else:
                l = (y2 - y1) * inverse(x2 - x1, ECDSA.p) % ECDSA.p
            x3 = (l * l - x1 - x2) % ECDSA.p
            y3 = (l * (x1 - x3) - y1) % ECDSA.p
            return (x3, y3)
    
        @staticmethod
        def scalar_mult(k, P):
            R = (None, None)
            while k:
                if k & 1: R = ECDSA.point_add(R, P)
                P = ECDSA.point_add(P, P)
                k >>= 1
            return R
    
        @staticmethod
        def gen_keypair():
            d = random.randint(1, ECDSA.n - 1)         
            Q = ECDSA.scalar_mult(d, ECDSA.G)          
            return d, Q                                 
    
        @staticmethod
        def ecdsa_sign(h: int, d: int, prng: xorshiro256):
            while True:
                k = prng() % ECDSA.n
                if not k:
                    continue
                x, _ = ECDSA.scalar_mult(k, ECDSA.G)
                if x is None:  
                    continue
                r = x % ECDSA.n
                if not r:
                    continue
                s = (inverse(k, ECDSA.n) * (h + r * d)) % ECDSA.n
                if s:
                    return r, s
    
        @staticmethod
        def ecdsa_verify(h, Q, sig):
            r, s = sig
            if not (1 <= r < ECDSA.n and 1 <= s < ECDSA.n):
                return False
            w  = inverse(s, ECDSA.n)
            u1 = (h * w) % ECDSA.n
            u2 = (r * w) % ECDSA.n
            x, _ = ECDSA.point_add(ECDSA.scalar_mult(u1, ECDSA.G), ECDSA.scalar_mult(u2, Q))
            if x is None:  
                return False
            return (x % ECDSA.n) == r
```  
  
---|---  
`

  1. Se genera la clave privada `d ∈ [1, n-1]`
  2. Calcula la clave pública `Q = d·G`
  3. Firma un mensaje `h` usando:


  * `k = prng() % n` ← vulnerable porque prng es determinista y parcialmente filtrado
  * `r = (k·G).x % n`
  * `s = k⁻¹(h + r·d) % n`


  1. Devuelve `(r, s)`


Si abrimos el archivo `prng.py` encontramos lo siguiente.

____

`

```
    1
    2
    3
    4
    5
    6
    7
    8
    9
    10
    11
    12
    13
    14
    15
    16
    17
    18
    19
    20
    21
    22
    23
    24
    25
    26
    27
    28
    29
    30
    31
    32
    33
    34
    35
    36
    37
    38
    39
    40
    41
```

| 

```
     #!/usr/bin/python3
    from Crypto.Util.number import bytes_to_long, inverse
    MASK64 = (1 << 64) - 1                    
    
    def _rotl(x: int, k: int) -> int:
        return ((x << k) | (x >> (64 - k))) & MASK64
    
    class xorshiro256:
        
        def __init__(self, seed):
            if len(seed) != 4:
                raise ValueError("seed must have four 64-bit words")
            self.s = [w & MASK64 for w in seed]
    
    
        @staticmethod
        def _temper(s1: int) -> int:
            return (_rotl((s1 * 5) & MASK64, 7) * 9) & MASK64
    
    
        def next_raw(self) -> int:
            s0, s1, s2, s3 = self.s
            t = (s1 << 17) & MASK64
    
            s2 ^= s0
            s3 ^= s1
            s1 ^= s2
            s0 ^= s3            
            s2 ^= t
            s3  = _rotl(s3, 45)
    
            self.s = [s0, s1, s2, s3]
            return s1          
        
        def randrange(self, start, stop, inclusive=False):
            if inclusive:
                return start + self.next_raw() % (stop - start + 1)
            return start + self.next_raw() % (stop - start)
    
        def __call__(self) -> int:
            return self._temper(self.next_raw())
```  
  
---|---  
`

Este PRNG es una versión específica de xorshiro256**, donde:

  * Internamente usa un estado de 4 enteros de 64 bits.
  * `next_raw()` devuelve `s1` (sin temperar)
  * `__call__()` aplica un `temper` a `s1`, siguiendo la fórmula de xorshiro:


____

`

```
    1
```

| 

```
     _rotl((s1 * 5) & MASK64, 7) * 9
```  
  
---|---  
`

## Solución __

El objetivo principal del reto es**recuperar la clave privada ECDSA (Apriv)** a partir de las **fugas del PRNG** , para así poder derivar la clave AES y desencriptar la flag.

En este caso, la clave está en las fugas del PRNG, ya que nos dan 4 valores **sin temperar** (`next_raw()`), lo cual es importante porque permite **reconstruir el estado interno** del PRNG `xorshiro256` (si tienes suficientes valores).

Una vez que tenemos el estado interno, podemos predecir el `k` usado en la firma ECDSA y finalmente con `k`, `r`, `s`, y `h`, puedes recuperar la clave privada `Apriv` mediante: \\(d = \frac{s \cdot k - h}{r} \mod n\\)

El script completo que integra los pasos necesarios para desencriptar la flag es el siguiente.

____

`

```
    1
    2
    3
    4
    5
    6
    7
    8
    9
    10
    11
    12
    13
    14
    15
    16
    17
    18
    19
    20
    21
    22
    23
    24
    25
    26
    27
    28
    29
    30
    31
    32
    33
    34
    35
    36
    37
    38
    39
    40
    41
    42
    43
    44
    45
    46
    47
    48
    49
    50
    51
    52
    53
    54
    55
    56
    57
    58
    59
    60
    61
    62
    63
    64
    65
    66
    67
    68
    69
    70
    71
    72
    73
    74
    75
    76
    77
    78
    79
    80
    81
    82
    83
    84
    85
    86
    87
    88
    89
    90
    91
    92
    93
    94
    95
    96
    97
    98
    99
    100
    101
```

| 

```
     import z3
    from Crypto.Util.number import long_to_bytes
    from hashlib import sha256
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import unpad
    
    # Parámetros de la curva
    n_ecdsa = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    MASK64 = (1 << 64) - 1
    
    # Leaks del PRNG
    leaks = [
        0x785a1cb672480875,
        0x91c1748fec1dd008,
        0x5c52ec3a5931f942,
        0xac4a414750cd93d7
    ]
    
    # Datos de la firma
    H = 9529442011748664341738996529750340456157809966093480864347661556347262857832209689182090159309916943522134394915152900655982067042469766622239675961581701969877932734729317939525310618663767439074719450934795911313281256406574646718593855471365539861693353445695
    r_sig = 54809455810753652852551513610089439557885757561953942958061085530360106094036
    s_sig = 42603888460883531054964904523904896098962762092412438324944171394799397690539
    
    ciphertext_hex = "404e9a7bbdac8d3912d881914ab2bdb924d85338fbd1a6d62a88d793b4b9438400489766e8e9fb157c961075ad4421fc"
    
    def _rotl(x, k):
        return ((x << k) | (x >> (64 - k))) & MASK64
    
    # Función de temperado
    def temper(s1):
        x = (s1 * 5) & MASK64
        x = _rotl(x, 7)
        x = (x * 9) & MASK64
        return x
    
    # Función de actualización del estado en Z3
    def next_state_z3(state):
        s0, s1, s2, s3 = state
        t = s1 << 17
        s2_t = s2 ^ s0
        s3_t = s3 ^ s1
        s1_t = s1 ^ s2_t
        s0_t = s0 ^ s3_t
        s2_t = s2_t ^ t
        s3_t = z3.RotateLeft(s3_t, 45)
        return [s0_t, s1_t, s2_t, s3_t]
    
    # Resolver con Z3 para el estado inicial
    s0, s1, s2, s3 = z3.BitVecs('s0 s1 s2 s3', 64)
    solver = z3.Solver()
    state = [s0, s1, s2, s3]
    
    for i in range(4):
        solver.add(state[1] == leaks[i])
        state = next_state_z3(state)
    
    if solver.check() != z3.sat:
        print("No solution found")
        exit(1)
    
    model = solver.model()
    s0_val = model[s0].as_long()
    s1_val = model[s1].as_long()
    s2_val = model[s2].as_long()
    s3_val = model[s3].as_long()
    print("Estado inicial recuperado:")
    
    # Función de actualización del estado en Python
    def next_state_py(state):
        s0, s1, s2, s3 = state
        t = (s1 << 17) & MASK64
        s2 ^= s0
        s3 ^= s1
        s1 ^= s2
        s0 ^= s3
        s2 ^= t
        s3 = _rotl(s3, 45)
        return [s0, s1, s2, s3]
    
    # Simular 4 actualizaciones
    state = [s0_val, s1_val, s2_val, s3_val]
    for _ in range(4):
        state = next_state_py(state)
    
    # Obtener nonce k utilizado
    k_raw = state[1]
    k = temper(k_raw)
    print(f"Nonce k: {k}")
    
    # Calcular clave privada d
    H_mod = H % n_ecdsa
    d = ((s_sig * k - H_mod) * pow(r_sig, -1, n_ecdsa)) % n_ecdsa
    print(f"Clave privada d: {d}")
    
    # Derivar clave AES y descifrar
    key = sha256(long_to_bytes(d)).digest()
    iv = bytes.fromhex(ciphertext_hex[:32])
    ct = bytes.fromhex(ciphertext_hex[32:])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    flag = unpad(cipher.decrypt(ct), 16)
    print(f"[+] Flag: {flag.decode()}")
```  
  
---|---  
`

## Flag __

`L3AK{u_4r3_th3_sh1r0_h3r0!}`

__[Writeups Competiciones Internacionales](https://k3sero.github.io/categories/writeups-competiciones-internacionales/), [Criptografía](https://k3sero.github.io/categories/criptograf%C3%ADa/)

__[Cripto](https://k3sero.github.io/tags/cripto/) [Cripto - PRNGs](https://k3sero.github.io/tags/cripto-prngs/) [Otros - Writeups](https://k3sero.github.io/tags/otros-writeups/) [Dificultad - Media](https://k3sero.github.io/tags/dificultad-media/) [L3AKCTF](https://k3sero.github.io/tags/l3akctf/)

Esta entrada está licenciada bajo [ CC BY 4.0 ](https://creativecommons.org/licenses/by/4.0/) por el autor.

Compartir [ __](https://twitter.com/intent/tweet?text=Shiro%20Hero%20-%20L3AK2025%20-%20Kesero&url=https%3A%2F%2Fk3sero.github.io%2Fposts%2FShiro-Hero-L3AK2025%2F "Twitter") [ __](https://www.facebook.com/sharer/sharer.php?title=Shiro%20Hero%20-%20L3AK2025%20-%20Kesero&u=https%3A%2F%2Fk3sero.github.io%2Fposts%2FShiro-Hero-L3AK2025%2F "Facebook") [ __](https://t.me/share/url?url=https%3A%2F%2Fk3sero.github.io%2Fposts%2FShiro-Hero-L3AK2025%2F&text=Shiro%20Hero%20-%20L3AK2025%20-%20Kesero "Telegram") __
