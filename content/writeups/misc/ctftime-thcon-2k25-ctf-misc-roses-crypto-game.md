---
title: "[Misc] Roses Crypto Game - THCon 2K25 CTF"
category: "misc"
subcategory: "audio"
type: "writeup"
tags: ["morse", "misc", "roses", "crypto", "game", "audio", "thcon-2k25-ctf", "ctf-writeup"]
summary: "Roses Crypto Game - THCON2025"
source:
  name: "CTFtime writeup #40193"
  url: "https://ctftime.org/writeup/40193"
original_source: "https://k3sero.github.io/posts/Crypto-Roses-Game-THCON2025/"
ctf:
  name: "THCon 2K25 CTF"
  challenge: "[Misc] Roses Crypto Game"
---

## Metadata

- **CTF:** THCon 2K25 CTF
- **Task:** [Misc] Roses Crypto Game
- **Author team:** Caliphal Hounds
- **CTFtime:** <https://ctftime.org/writeup/40193>
- **Original writeup:** <https://k3sero.github.io/posts/Crypto-Roses-Game-THCON2025/>

---
Roses Crypto Game - THCON2025 __

Contenido __

Roses Crypto Game - THCON2025

__

Autor del reto: `Babson`

Dificultad: Fácil

## Enunciado __

“Congratulation on accessing our target’s computer.

He seems to have a background task that interacts with a remote host through a socket. Spawn the docker below to get access to it. Find out if we can exfiltrate information from this !

(Don’t forget to use the link you get with NeoPrivesc)

View Hint In case you forget it ^^

THC{Ne0f37CH_i5_B34u71fUL}

from : Viktor “Crypt” a.k.a. The Secret Shadow to : Gideon “Giddy” Morse a.k.a. The Jester content : Hey looser, I just finished implementing the “secure” (that’s called irony you stupid) “encryption system” (that was too) you requested. As you asked it is based on the https://en.wikipedia.org/wiki/Petals_Around_the_Rose concept (Mammoth and his betting friends will be happy ha ha). Now if you’re done asking stupid things and spending 5 hours choosing a terminal color scheme, I’ll focus on attacking, controlling and destroying THCity, potentially not in this particular order. View Hint Did you ever heard of base 3 ?”

## Archivos __

En este reto, tenemos el siguiente archivo.

  * `Instancia Netcat` : Instancia de conexión con netcat.


Archivos utilizados en mi [repositorio de Github](https://github.com/k3sero/Blog_Content/tree/main/Competiciones_Internacionales_Writeups/2025/THCON2025/misc/Roses%20Crypto%20Game/img).

## Analizando el reto __

Una vez que nos conectamos por netcat, recibimos por parte del servidor la siguiente cadena (Es aleatoria en cada iteración).

____

`

```
    1
    2
    3
    4
```

| 

```
    ┌──(kesero㉿kali)-[~]
    └─$ nc 43.216.228.210 32923
    
    332565656633463553443562123355345335124553335153533361461335554235432333433655553433535565355315145355336333333622345132555545316133135455335
```  
  
---|---  
`

## Solver __

Con esta cadena, se nos pueden ocurrir muchas posibles tentativas, pero en este reto las pistas eran muy importantes ya que sin ellas era casi imposible de resolver el reto.

Básicamente se trata de un sistema de “cifrado” basado en el juego `"Petals Around the Rose"` (Referencia del título del reto)

`"Petals Around the Rose"` es un juego de lógica donde se lanzan dados, y solo ciertos valores (3 y 5) aportan puntos. La clave está en que:

  1. El número 3 cuenta como 2 pétalos.

  2. El número 5 cuenta como 4 pétalos.

  3. Los otros números (1, 2, 4, 6) cuentan como 0 pétalos.


Una vez decodificada, obtendremos un mensaje en `base 3`, el cual tendremos que pasar a binario para posteriormente leer la flag.

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
```

| 

```
     def petals_around_the_rose_value(die_face):
        if die_face == 3:
            return 2
        elif die_face == 5:
            return 4
        else:
            return 0
    
    def to_base3_rep(petals_list):
        return [val // 2 for val in petals_list]
    
    def base3_to_int(base3_list):
        return int(''.join(map(str, base3_list)), 3)
    
    def int_to_binary_string(num):
        return bin(num)[2:]
    
    def binary_to_string(binary_string):
        characters = []
        for i in range(0, len(binary_string), 8):
            byte = binary_string[i:i+8]
            if len(byte) == 8:
                decimal_value = int(byte, 2)
                characters.append(chr(decimal_value))
        return ''.join(characters)
    
    def decode_message(dice_string):
        petals = [petals_around_the_rose_value(int(c)) for c in dice_string.strip()]
        print(f"[1] Pétalos: {petals}")
    
        base3_digits = to_base3_rep(petals)
        print(f"[2] Base 3: {''.join(map(str, base3_digits))}")
    
        base3_number = base3_to_int(base3_digits)
        print(f"[3] Número decimal: {base3_number}")
    
        binary_str = int_to_binary_string(base3_number)
    
        # ⚠️ Rellenar binario a múltiplos de 8 bits
        remainder = len(binary_str) % 8
        if remainder != 0:
            padding = 8 - remainder
            binary_str = '0' * padding + binary_str
    
        print(f"[4] Binario (padded): {binary_str} ({len(binary_str)} bits)")
    
        message = binary_to_string(binary_str)
        return message
    
    
    # Cadena original
    input_string = "332565656633463553443562123355345335124553335153533361461335554235432333433655553433535565355315145355336333333622345132555545316133135455335"
    
    # Ejecutar
    flag = decode_message(input_string)
    print(f"[5] Mensaje oculto: {flag}")
```  
  
---|---  
`

## Flag __

`THC{I_r3Ally_L1k3_7H1s_g4M3}`

__[Writeups Competiciones Internacionales](https://k3sero.github.io/categories/writeups-competiciones-internacionales/), [Miscelánea](https://k3sero.github.io/categories/miscel%C3%A1nea/)

__[Dificultad - Fácil](https://k3sero.github.io/tags/dificultad-f%C3%A1cil/) [Otros - Writeups](https://k3sero.github.io/tags/otros-writeups/) [Misc](https://k3sero.github.io/tags/misc/) [THCONCTF](https://k3sero.github.io/tags/thconctf/)

Esta entrada está licenciada bajo [ CC BY 4.0 ](https://creativecommons.org/licenses/by/4.0/) por el autor.

Compartir [ __](https://twitter.com/intent/tweet?text=Roses%20Crypto%20Game%20-%20THCON2025%20-%20Kesero&url=https%3A%2F%2Fk3sero.github.io%2Fposts%2FCrypto-Roses-Game-THCON2025%2F "Twitter") [ __](https://www.facebook.com/sharer/sharer.php?title=Roses%20Crypto%20Game%20-%20THCON2025%20-%20Kesero&u=https%3A%2F%2Fk3sero.github.io%2Fposts%2FCrypto-Roses-Game-THCON2025%2F "Facebook") [ __](https://t.me/share/url?url=https%3A%2F%2Fk3sero.github.io%2Fposts%2FCrypto-Roses-Game-THCON2025%2F&text=Roses%20Crypto%20Game%20-%20THCON2025%20-%20Kesero "Telegram") __
