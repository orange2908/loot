---
title: "curved-mvm - x3CTF 2025 (feat. mvm)"
category: "crypto"
subcategory: "ecc"
type: "writeup"
tags: ["crypto", "ecc", "ecdsa", "sage", "curved-mvm", "x3ctf-2025-feat-mvm", "2025", "ctf-writeup"]
summary: "“mvm cwypto chall for funny users.”"
source:
  name: "CTFtime writeup #40184"
  url: "https://ctftime.org/writeup/40184"
original_source: "https://k3sero.github.io/posts/Curved-mvm-x3CTF2025/"
ctf:
  name: "x3CTF 2025 (feat. mvm)"
  year: 2025
  challenge: "curved-mvm"
---

## Metadata

- **CTF:** x3CTF 2025 (feat. mvm)
- **Task:** curved-mvm
- **Author team:** Caliphal Hounds
- **CTFtime:** <https://ctftime.org/writeup/40184>
- **Original writeup:** <https://k3sero.github.io/posts/Curved-mvm-x3CTF2025/>

---
Curved MVM - x3CTF2025 __

Contenido __

Curved MVM - x3CTF2025

__

Autor del reto: `Yes`

Dificultad: Media

## Enunciado __

“mvm cwypto chall for funny users.”

##  Archivos __

En este reto, nos dan los siguientes archivos.

  * `server.py` : Contiene la lógica principal del reto.
  * `Servidor remoto` : Conexión por ncat.


Archivos utilizados en mi [repositorio de Github](https://github.com/k3sero/Blog_Content/tree/main/Competiciones_Internacionales_Writeups/2025/x3CTF2025/Cripto/curved-mvm).

## Analizando el código __

Si abrimos el archivo`server.py` podemos ver el siguiente código.

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
    102
    103
    104
    105
    106
    107
    108
    109
    110
    111
    112
    113
    114
    115
    116
    117
    118
    119
    120
    121
    122
    123
    124
    125
    126
    127
    128
    129
    130
    131
    132
    133
    134
    135
    136
    137
    138
    139
    140
    141
    142
```

| 

```
     from sage.all import *
    
    import os
    from json import dumps
    from secrets import randbits
    from Crypto.Util.number import bytes_to_long
    from hashlib import sha1
    
    FLAG = os.getenv("FLAG", "MVM{f4ke_fl4g}")
    
    # a wonderful curve
    p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
    a = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC
    b = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
    Gx = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
    Gy = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
    
    F = GF(p)
    EC = EllipticCurve(F, [a, b])
    n = EC.order()
    
    SECRET_KEY = bytes_to_long(os.urandom(69420)) % n
    G = EC([Gx, Gy])
    assert G in EC
    
    Q = SECRET_KEY * G
    
    FUNNY_CREDITS_FOR_FREE_TRIAL = 2
    
    CHALL_NAME = "Curved MVM"
    
    K_SIZE = 18
    SAMPLE_MSG = "hardcoded cuz reasons"
    REQUIRED_MSG = "mvm mvm mvm"
    
    
    def sign_msg(msg: str):
        z = bytes_to_long(sha1(msg.encode()).digest()) % n
        k = (randbits(K_SIZE) + 2) % n
        R = k * G
        r = ZZ(R.x()) % n
        s = (k.inverse_mod(n) * (z + r * SECRET_KEY)) % n
        return {"r": hex(r), "s": hex(s)}
    
    
    def sign_bogus():
        return sign_msg(SAMPLE_MSG)
    
    
    def verify_signature(r, s, msg):
        z = bytes_to_long(sha1(msg.encode()).digest()) % n
    
        if r < 1 or r >= n or s < 1 or s >= n:
            return {"error": "funny user uwu"}
    
        w = s.inverse_mod(n)
    
        u1 = (z * w) % n
        u2 = (r * w) % n
    
        P = u1 * G + u2 * Q
    
        should_r = ZZ(P.x()) % n
    
        if should_r == r:
            return {"flag": FLAG}
        else:
            # user funny
            return {"error": "invalid signature"}
    
    
    def mvm():
        r = prompt_integer("r")
        s = prompt_integer("s")
        try:
            return verify_signature(r, s, REQUIRED_MSG)
        except:
            return {"error": "funny user"}
    
    
    operations = {
        "sign": sign_bogus,
        "mvm": mvm,
    }
    
    
    def prompt_operation():
        _prompt = "/".join(operations)
        prompt = f"({_prompt}): "
    
        try:
            recv = input(prompt)
        except Exception:
            print("user too funny, complaints will be ignored\n")
    
        if recv not in operations:
            print("funny operation\n")
            return prompt_operation()
    
        return operations[recv]
    
    
    def prompt_integer(name: str):
        prompt = f"{name}: "
        try:
            recv = input(prompt)
        except:
            print("user too funny, complaints will be sent to /dev/null\n")
            return prompt_integer(name)
    
        try:
            number = int(recv, 16)
        except:
            print("user supplied number too funny, complaints will be ignored\n")
            return prompt_integer(name)
    
        if number <= 1:
            print("user supplied number funny.\n")
            return prompt_integer(name)
    
        return ZZ(number)
    
    
    funny_credits = FUNNY_CREDITS_FOR_FREE_TRIAL
    
    if __name__ == "__main__":
        print(f"Welcome to {CHALL_NAME!r}, enjoy the pain!\n")
    
        while True:
            print(
                f"You have {funny_credits} funny credit{'s' if funny_credits > 1 else ''}."
            )
            operation = prompt_operation()
            print(dumps(operation()))
            funny_credits -= 1
    
            if funny_credits == 0:
                print("ran out of funny credits, bye")
                exit()
    
            print()
```  
  
---|---  
`

Este código implementa un sistema de firma digital basado en curvas elípticas, específicamente utilizando la curva elíptica secp256r1 (P-256). Este sistema permite firmar mensajes y verificar firmas además de contar con una opción en la que si se proporciona una firma válida, el servidor nos arrojará la flag para un mensaje específico.

Podemos desglosar el código en las siguientes funcionalidades.

  1. La curva elíptica utilizada es `secp256r1`, con parámetros \\(p\\), \\(a\\), \\(b\\), \\(Gx\\), y \\(Gy\\).

  2. El punto base \\(G\\) es un punto en la curva, y $n$ es el orden del grupo generado por $G$.

  3. $SECRETKEY$ es un número aleatorio generado a partir de bytes aleatorios, y se utiliza para generar la clave pública \\(Q = SECRETKEY * G\\).

  4. La función $signmsg$ firma un mensaje utilizando el esquema de firma `ECDSA` (Elliptic Curve Digital Signature Algorithm).

  5. El valor $k$ es un nonce (número aleatorio) que se genera para cada firma.

  6. La firma consiste en dos valores $r$ y $s$, donde $r$ es la coordenada $x$ del punto \\(R = k * G\\) , y $s$ es un valor calculado a partir de $k$, el hash del mensaje $z$, y la clave secreta.

  7. La función $verify_signature$ verifica si una firma es válida para un mensaje dado. Si la firma es válida, se devuelve la bandera (flag).

  8. El programa permite al usuario realizar dos operaciones: firmar un mensaje predefinido ($sign_bogus$) y verificar una firma para un mensaje específico ($mvm$).

  9. El usuario solamente tiene 2 intentos para realizar estas operaciones.


## Solución __

La solución de este reto viene dada por el nonce $k$ y es que podemos obtener el nonce original $k$ mediante un ataque de fuerza bruta.

Esto es posible porque el valor de $k$ se genera con un tamaño de solo 18 bits \\(KSIZE = 18\\), lo que significa que hay solo \\(2^(18) = 262,144\\) valores posibles para $k$. Esto es un número manejable para un ataque de fuerza bruta.

El procedimiento que tenemos que seguir es el siguiente para elaborar un solver.

  1. Obtenemos por parte del servidor una firma $(r, s)$ válidas para el mensaje predeterminado $SAMPLEMSG$

  2. Calculamos el hash $z$ del mensaje $SAMPLEMSG$ usando `SHA-1`.

  3. Realizamos fuerza bruta de $k$ iterando sobre todos los posibles valores de $k$ (desde 0 hasta 2^18 - 1).

  4. Para cada valor de $k$, se calcula \\(R = k * G\\) y obtenemos un \\(rcandidate = ZZ(R.x()) % n\\)

  5. Si $rcandidate$ coincide con el valor $r$ de la firma, entonces hemos encontrado el valor correcto de $k$.

  6. Una vez que tenemos $k$, puedes resolver la ecuación de la firma para obtener la clave secreta $SECRETKEY$:


\\[s = k^{-1} (z + r \cdot SECRETKEY) \mod n\\]

Despejando $SECRETKEY$:

\\[SECRETKEY = (s \cdot k - z) \cdot r^{-1} \mod n\\]

  1. Por último, firmamos un mensaje en local para posteriormente enviarlo al servidor usando la función mvm, ya que la firmas realizadas de forma local son válidas.


El script resultante de todo el proceso es el siguiente.

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
```

| 

```
     from sage.all import *
    import hashlib
    
    # Función bytes_to_long (No se puede importar)
    def bytes_to_long(byte_data):
        return int.from_bytes(byte_data, byteorder='big')
    
    # Parámetros de la curva
    p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
    a = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC
    b = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
    Gx = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
    Gy = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
    
    F = GF(p)
    EC = EllipticCurve(F, [a, b])
    G = EC([Gx, Gy])
    n = EC.order()
    
    # Obtener una firma (r, s) para SAMPLE_MSG
    SAMPLE_MSG = "hardcoded cuz reasons"
    z = bytes_to_long(hashlib.sha1(SAMPLE_MSG.encode()).digest()) % n
    
    # Valores de r y s obtenidos del servidor
    r = 0x78a743145f397a221bd84e032e02349e9f1010fe3866c7f3d7b9f783e59c7d2f  
    s = 0xf7ffc9d5cb436db8cfdcf3b5e88f51c071cf13adc567ce025d0369aaf63d539  
    
    # Fuerza bruta sobre k
    found = False
    for k in range(2**18):
        R = k * G
        if R == EC(0):  # Verificar si R es el punto en el infinito
            continue  # Saltar este valor de k
        r_candidate = ZZ(R.x()) % n
        if r_candidate == r:
            print(f"Found k: {k}")
    
            # Recupera la clave secreta
            SECRET_KEY = (s * k - z) * inverse_mod(r, n) % n
            print(f"Recovered SECRET_KEY: {SECRET_KEY}")
            found = True
            break
    
    if not found:
        print("No se encontró el valor de k.")
    
    # Firmar el mensaje
    if found:
        REQUIRED_MSG = "mvm mvm mvm"
        z_required = bytes_to_long(hashlib.sha1(REQUIRED_MSG.encode()).digest()) % n
        k_required = (randint(0, 2**18 - 1) + 2) % n  
        R_required = k_required * G
    
        # Verificar si R_required es el punto en el infinito
        if R_required == EC(0):  
            print("Error: R_required es el punto en el infinito.")
        else:
            r_required = ZZ(R_required.x()) % n
            s_required = (inverse_mod(k_required, n) * (z_required + r_required * SECRET_KEY)) % n
            print(f"Firma para REQUIRED_MSG: r = {hex(r_required)}, s = {hex(s_required)}")
```  
  
---|---  
`

Como hemos mencionado anteriormente, primero necesitamos un r y un s válidas del servidor. Para ello nos conectamos al servidor y con el comando sing obtenemos las mismas.

[![Obtencion](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/x3CTF2025/Cripto/curved-mvm/img/obtain.png)](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/x3CTF2025/Cripto/curved-mvm/img/obtain.png)

Acto seguido, introducimos las firmas en los parámetros `r` y `s` correspondientes y ejecutamos el script.

[![Ejecución](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/x3CTF2025/Cripto/curved-mvm/img/execution.png)](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/x3CTF2025/Cripto/curved-mvm/img/execution.png)

Por último, introducimos las claves válidas generadas localmente para obtener la flag.

[![flag](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/x3CTF2025/Cripto/curved-mvm/img/flag.png)](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/x3CTF2025/Cripto/curved-mvm/img/flag.png)

## Flag __

`MVM{why_k_no_v3wwy_much_se3uw3????}`

__[Writeups Competiciones Internacionales](https://k3sero.github.io/categories/writeups-competiciones-internacionales/), [Criptografía](https://k3sero.github.io/categories/criptograf%C3%ADa/)

__[Cripto](https://k3sero.github.io/tags/cripto/) [Cripto - Curvas Elípticas](https://k3sero.github.io/tags/cripto-curvas-el%C3%ADpticas/) [Otros - Writeups](https://k3sero.github.io/tags/otros-writeups/) [Dificultad - Media](https://k3sero.github.io/tags/dificultad-media/) [x3CTF](https://k3sero.github.io/tags/x3ctf/)

Esta entrada está licenciada bajo [ CC BY 4.0 ](https://creativecommons.org/licenses/by/4.0/) por el autor.

Compartir [ __](https://twitter.com/intent/tweet?text=Curved%20MVM%20-%20x3CTF2025%20-%20Kesero&url=https%3A%2F%2Fk3sero.github.io%2Fposts%2FCurved-mvm-x3CTF2025%2F "Twitter") [ __](https://www.facebook.com/sharer/sharer.php?title=Curved%20MVM%20-%20x3CTF2025%20-%20Kesero&u=https%3A%2F%2Fk3sero.github.io%2Fposts%2FCurved-mvm-x3CTF2025%2F "Facebook") [ __](https://t.me/share/url?url=https%3A%2F%2Fk3sero.github.io%2Fposts%2FCurved-mvm-x3CTF2025%2F&text=Curved%20MVM%20-%20x3CTF2025%20-%20Kesero "Telegram") __
