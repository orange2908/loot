---
title: "[Cripto] Dumber - L3akCTF 2025"
category: "crypto"
subcategory: "discrete-log"
type: "writeup"
tags: ["crypto", "gcd", "sage", "discrete-log", "proof-of-work", "cripto", "dumber", "l3akctf", "l3akctf-2025", "2025", "ctf-writeup"]
summary: "“Don’t try to outsmart me buddy.”"
source:
  name: "CTFtime writeup #40521"
  url: "https://ctftime.org/writeup/40521"
original_source: "https://k3sero.github.io/posts/Dumber-L3AK2025/"
ctf:
  name: "L3akCTF 2025"
  year: 2025
  challenge: "[Cripto] Dumber"
---

## Metadata

- **CTF:** L3akCTF 2025
- **Task:** [Cripto] Dumber
- **Author team:** Caliphal Hounds
- **CTFtime:** <https://ctftime.org/writeup/40521>
- **Original writeup:** <https://k3sero.github.io/posts/Dumber-L3AK2025/>

---
Dumber - L3AK2025 __

Contenido __

Dumber - L3AK2025

__

Autor del reto: `CEA`

Dificultad: Media

## Enunciado __

“Don’t try to outsmart me buddy.”

##  Archivos __

En este reto, tenemos el siguiente archivo.

  * `chall.py`: Contiene el script principal de cifrado.
  * `output.txt`: Contiene la salida del script anterior.


Archivos utilizados en mi [repositorio de Github](https://github.com/k3sero/Blog_Content/tree/main/Competiciones_Internacionales_Writeups/2025/L3AKCTF2025/Cripto/Dumber).

## Analizando el reto __

Si abrimos el código podemos observar lo siguiente.

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
```

| 

```
     from Crypto.Util.number import  bytes_to_long, long_to_bytes
    from sage.all import *
    
    a,b,p = ?,?,?
    
    pt1="L3AK{test_"
    pt2="flag}"
    
    E = EllipticCurve(Zmod(p), [a, b])
    p,q=E.random_element(),E.random_element()
    u=bytes_to_long(pt1.encode())*p
    v=bytes_to_long(pt2.encode())*q
    
    # I will help u <3
    print(p,u,q,v)
```  
  
---|---  
`

Este código toma dos partes de un mensaje (`pt1` y `pt2`), las convierte a números grandes y los codifica como múltiplos de puntos aleatorios en una curva elíptica sobre un campo finito. Después imprime los puntos y sus múltiplos.

## Solución __

Para resolver este problema, tenemos que resolver el logaritmo discreto en la curva para recuperar la`flag`. Como podemos leer en el enunciado y en la sátira del título del reto, este código es vulnerable a un `smart attack`.

Un `smart attack` es un ataque criptanalítico que permite resolver el logaritmo discreto en curvas elípticas reducidas a característica 2 (o p pequeña) cuando ciertas condiciones especiales se cumplen. Dicho ataque explota el hecho de que si una curva elíptica tiene orden igual al primo del campo, entonces se puede levantar la curva a los números p-ádicos y resolver el logaritmo discreto de forma eficiente.

Pero para poder realizar este ataque, tenemos que reconstruir la curva elíptica utilizada. Para ello recuperaremos los parámetros de la curva `a` `b` y `p` utilizados en la creación del campo a partir de puntos dados, extrayendo los parámetros `a`, `b` y `p` mediante una deducción algebraica.

Sabemos que la forma general de una curva elíptica sobre un campo $\mathbb{F}_p$ es:

\\[y^2 = x^3 + ax + b \mod p\\]

Tenemos 4 puntos $(x_i, y_i)$ que deben satisfacer esa ecuación. Es decir, para cada punto:

\\[y_i^2 - x_i^3 - a x_i - b \equiv 0 \mod p\\]

Pero como no conocemos `a`, ni `b`, ni `p`, los eliminamos parcialmente para poder **aislar`p`**.

Por ende:

\\[\text{term}_i = y_i^2 - x_i^3 \Rightarrow \text{term}_i = a x_i + b \mod p\\]

Entonces, la diferencia entre dos términos:

\\[\text{term}_i - \text{term}_j = a(x_i - x_j) \mod p\\]

De ahí puedes deducir que:

\\[A_1 = \text{term}_1 - \text{term}_2 = a(x_1 - x_2) \mod p \\\ A_2 = \text{term}_1 - \text{term}_3 = a(x_1 - x_3) \mod p \\\ \text{etc.}\\]

Ahora tenemos que crear combinaciones lineales de estas ecuaciones para **cancelar`a`** y quedarte con expresiones que **son múltiplos de`p`**.

Posteriormente, calculamos el MCD de los candidatos para deducir `p` y para comprobar la viabilidad de dicho candidato, realizamos una factorización ligera para quedarnos con el número `p` que probablemente sea primo grande.

____

`

```
    1
    2
    3
    4
    5
```

| 

```
     for f in range(2, 1000000):
        while temp % f == 0:
            temp //= f
    
    p = temp
```  
  
---|---  
`

Una vez obtenido `p` podemos obtener lo siguiente.

\\[a = \frac{y_1^2 - y_2^2 - (x_1^3 - x_2^3)}{x_1 - x_2} \mod p\\] \\[b = y_1^2 - x_1^3 - a x_1 \mod p\\]

Y ya tenemos la curva elíptica reconstruida.

En este punto del reto, tenemos que evaluar dicha curva para ver si es vulnerable a ataques relacionados con la `singularidad`, `supersingularidad` o en curvas `anómalas`.

En este caso, podemos verificar que la curva es `anómala` por que cumple la siguiente condición:

\\[\\#E(\mathbb{F}_p) = p\Rightarrow \text{traza de Frobenius} = 1\\]

Como se cumple dicha condición, podemos aplicar el **smart attack** mencionado anteriormente.

Además, existe una isomorfía entre el grupo de puntos de la curva y $\mathbb{Z}_p$, lo que permite resolver el DLP con p-ádicos.

El script completo es el siguiente.

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
```

| 

```
     from Crypto.Util.number import bytes_to_long, long_to_bytes
    import math
    from sage.all import *
    
    x1 = 103905521866731574234430443362297034336
    y1 = 116589269353056499566212456950780999584
    x2 = 171660318017081135625337806416866746485
    y2 = 122407097490400018041253306369079974706
    x3 = 161940138185633513360673631821653803879
    y3 = 167867902631659599239485617419980253311
    x4 = 95406403280474692216804281695624776780
    y4 = 109560844064302254814641159241201048462
    
    # Verify the points of the curve.
    def verify_point(x, y, a, b, p):
        left = pow(y, 2, p)
        right = (pow(x, 3, p) + a * x + b) % p
        return left == right
    
    # Convert a field element to a p-adic number.
    def _gf_to_qq(n, qq, x):
        return ZZ(x) if n == 1 else qq(list(map(int, x.polynomial())))
    
    # Lift a point to the p-adic numbers.
    def _lift(E, p, Px, Py):
        for P in E.lift_x(Px, all=True):
            if (P.xy()[1] % p) == Py:
                return P
    
    def attack(G, P):
    
        E = G.curve()
        assert E.trace_of_frobenius() == 1, f"Curve should have trace of Frobenius = 1."
    
        F = E.base_ring()
        p = F.characteristic()
        q = F.order()
        n = F.degree()
        qq = Qq(q, names="g")
    
        # Section 6.1: case where n == 1
    
        E = EllipticCurve(qq, [_gf_to_qq(n, qq, a) + q * ZZ.random_element(1, q) for a in E.a_invariants()])
        Gx, Gy = _gf_to_qq(n, qq, G.xy()[0]), _gf_to_qq(n, qq, G.xy()[1])
        Gx, Gy = (q * _lift(E, p, Gx, Gy)).xy()
        Px, Py = _gf_to_qq(n, qq, P.xy()[0]), _gf_to_qq(n, qq, P.xy()[1])
        Px, Py = (q * _lift(E, p, Px, Py)).xy()
        l = ZZ(((Px / Py) / (Gx / Gy)) % p)
    
        if n > 1:
            # Section 6.2: case where n > 1
            G0 = p ** (n - 1) * G
            G0x, G0y = _gf_to_qq(n, qq, G0.xy()[0]), _gf_to_qq(n, qq, G0.xy()[1])
            G0x, G0y = (q * _lift(E, p, G0x, G0y)).xy()
            for i in range(1, n):
                Pi = p ** (n - i - 1) * (P - l * G)
                if Pi.is_zero():
                    continue
    
                Pix, Piy = _gf_to_qq(n, qq, Pi.xy()[0]), _gf_to_qq(n, qq, Pi.xy()[1])
                Pix, Piy = (q * _lift(E, p, Pix, Piy)).xy()
                l += p ** i * ZZ(((Pix / Piy) / (G0x / G0y)) % p)
    
        return int(l)
    
    k1 = bytes_to_long(b"L3AK{test_")  
    k2 = bytes_to_long(b"flag}")       
    
    # Compute terms for the curve equation
    term1 = y1**2 - x1**3
    term2 = y2**2 - x2**3
    term3 = y3**2 - x3**3
    term4 = y4**2 - x4**3
    
    # Differences of the terms
    A1 = term1 - term2
    A2 = term1 - term3
    A3 = term1 - term4
    A4 = term3 - term4
    
    # Differences in x-coordinates
    dx12 = x1 - x2
    dx13 = x1 - x3
    dx14 = x1 - x4
    dx34 = x3 - x4
    
    # Expressions that are multiples of p
    d1 = A1 * dx13 - A2 * dx12
    d2 = A1 * dx14 - A3 * dx12
    d3 = A1 * dx34 - A4 * dx12
    d4 = A2 * dx14 - A3 * dx13
    d5 = A2 * dx34 - A4 * dx13
    
    # Compute GCD of the absolute values
    candidate = abs(d1)
    candidate = math.gcd(candidate, abs(d2))
    candidate = math.gcd(candidate, abs(d3))
    candidate = math.gcd(candidate, abs(d4))
    candidate = math.gcd(candidate, abs(d5))
    
    temp = candidate
    for f in range(2, 1000000):
        while temp % f == 0:
            temp //= f
    
    p = temp
    
    num_a = ( (y1**2 - y2**2) - (x1**3 - x2**3) ) % p
    denom_a = (x1 - x2) % p
    inv_denom = pow(denom_a, -1, p)
    a = (num_a * inv_denom) % p
    
    b = (y1**2 - x1**3 - a * x1) % p
    
    assert verify_point(x1, y1, a, b, p)
    assert verify_point(x2, y2, a, b, p)
    assert verify_point(x3, y3, a, b, p)
    assert verify_point(x4, y4, a, b, p)
    
    print(f"p = {p}")
    print(f"a = {a}")
    print(f"b = {b}")
    
    E = EllipticCurve(GF(p), [a, b])
    
    G1 = E(x1, y1)
    P1 = E(x2, y2)
    G2 = E(x3, y3)
    P2 = E(x4, y4)
    
    f1 = attack(G1, P1)
    f2 = attack(G2, P2)
    
    print(f"[+] Flag: {long_to_bytes(f1) + long_to_bytes(f2)}")
```  
  
---|---  
`

## Flag __

`L3AK{5m4rt1_1n_Th3_h00000d!!!}`

__[Writeups Competiciones Internacionales](https://k3sero.github.io/categories/writeups-competiciones-internacionales/), [Criptografía](https://k3sero.github.io/categories/criptograf%C3%ADa/)

__[Cripto](https://k3sero.github.io/tags/cripto/) [Cripto - Curvas Elípticas](https://k3sero.github.io/tags/cripto-curvas-el%C3%ADpticas/) [Otros - Writeups](https://k3sero.github.io/tags/otros-writeups/) [Dificultad - Media](https://k3sero.github.io/tags/dificultad-media/) [L3AKCTF](https://k3sero.github.io/tags/l3akctf/)

Esta entrada está licenciada bajo [ CC BY 4.0 ](https://creativecommons.org/licenses/by/4.0/) por el autor.

Compartir [ __](https://twitter.com/intent/tweet?text=Dumber%20-%20L3AK2025%20-%20Kesero&url=https%3A%2F%2Fk3sero.github.io%2Fposts%2FDumber-L3AK2025%2F "Twitter") [ __](https://www.facebook.com/sharer/sharer.php?title=Dumber%20-%20L3AK2025%20-%20Kesero&u=https%3A%2F%2Fk3sero.github.io%2Fposts%2FDumber-L3AK2025%2F "Facebook") [ __](https://t.me/share/url?url=https%3A%2F%2Fk3sero.github.io%2Fposts%2FDumber-L3AK2025%2F&text=Dumber%20-%20L3AK2025%20-%20Kesero "Telegram") __
