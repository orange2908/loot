---
title: "Stop Drop and Roll - Cyber Apocalypse 2024: Hacker Royale"
category: "pwn"
type: "writeup"
tags: ["pwn", "stop", "drop", "roll", "cyber-apocalypse-2024-hacker-r", "cyber-apocalypse-2024-hacker-royal", "2024", "ctf-writeup"]
summary: "Stop Drop and Roll - CyberApocalypse2024"
source:
  name: "CTFtime writeup #39646"
  url: "https://ctftime.org/writeup/39646"
original_source: "https://k3sero.github.io/posts/Stop-Drop-and-Roll-CyberApocalypse2024/"
ctf:
  name: "Cyber Apocalypse 2024: Hacker Royale"
  year: 2024
  challenge: "Stop Drop and Roll"
---

## Metadata

- **CTF:** Cyber Apocalypse 2024: Hacker Royale
- **Task:** Stop Drop and Roll
- **Author team:** Caliphal Hounds
- **CTFtime:** <https://ctftime.org/writeup/39646>
- **Original writeup:** <https://k3sero.github.io/posts/Stop-Drop-and-Roll-CyberApocalypse2024/>

---
Stop Drop and Roll - CyberApocalypse2024 __

Contenido __

Stop Drop and Roll - CyberApocalypse2024

__

Autor del reto: `ir0nstone`

Dificultad: Fácil

## Enunciado __

“The Fray: The Video Game is one of the greatest hits of the last… well, we don’t remember quite how long. Our “computers” these days can’t run much more than that, and it has a tendency to get repetitive…”

##  Archivos __

En este reto, únicamente nos dan una conexión por netcat, al conectarnos encontraremos lo siguiente.

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
```

| 

```
    $ nc localhost 1337
    ===== THE FRAY: THE VIDEO GAME =====
    Welcome!
    This video game is very simple
    You are a competitor in The Fray, running the GAUNTLET
    I will give you one of three scenarios: GORGE, PHREAK or FIRE
    You have to tell me if I need to STOP, DROP or ROLL
    If I tell you there's a GORGE, you send back STOP
    If I tell you there's a PHREAK, you send back DROP
    If I tell you there's a FIRE, you send back ROLL
    Sometimes, I will send back more than one! Like this: 
    GORGE, FIRE, PHREAK
    In this case, you need to send back STOP-ROLL-DROP!
    Are you ready? (y/n) 
```  
  
---|---  
`

Archivos utilizados en mi [repositorio de Github](https://github.com/k3sero/Blog_Content/tree/main/Competiciones_Internacionales_Writeups/2024/Misc/CyberApocalypse2024/Stop_Drop_and_Roll).

## Analizando el código __

Las instrucciones son muy simples. Simplemente el programa nos dirá`GORGE`, `PHREAK` o `FIRE` y nosotros tendremos que enviar la cadena `STOP`, `DROP` or `ROLL` dependiendo de lo que nos diga el programa.

## Solución __

Lo que deberemos de hacer es programar un script el cual reciba la cadena indicada por parte del servidor y nosotros mapearemos el siguiente esquema.

  * Si el programa nos dice `GORGE` enviamos `STOP`.
  * Si el programa nos dice `PHREAK` enviamos `DROP`.
  * Si el programa nos dice `FIRE` enviamos `ROLL`.


Además, tendremos que tener en cuenta que hay ocasiones en las que nos dice las cadenas concatenadas con varios casos simultáneos y nosotros tenemos que ser capaces de interpretarlas y de generar su correspondiente salida.

El script que utilicé para resolver el ejercicio fue el siguiente.

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
```

| 

```
     from binascii import crc32
    from pwn import *
    
    def intercambiar_cadenas(cadena):
        # Decodificar la cadena de bytes y dividirla en palabras separadas
        palabras = cadena.decode().strip("b'\n").split(', ')
    
        # Crear un diccionario para mapear las palabras
        mapeo = {'FIRE': 'ROLL', 'PHREAK': 'DROP', 'GORGE': 'STOP'}
    
        # Iterar sobre cada palabra y aplicar el mapeo si es necesario
        palabras_intercambiadas = [mapeo.get(palabra, palabra) for palabra in palabras]
    
        # Unir las palabras intercambiadas de nuevo en una cadena
        cadena_intercambiada = '-'.join(palabras_intercambiadas)
    
        # Codificar la cadena intercambiada de nuevo en bytes
        cadena_intercambiada_bytes = cadena_intercambiada.encode()
    
        return cadena_intercambiada_bytes
    
    def intercambiar_cadenas2(cadena):
        # Decodificar la cadena de bytes y extraer lo que sigue después de "What do you do?"
        cadena = cadena.decode()
        indice = cadena.find("What do you do?")
        cadena = cadena[indice+len("What do you do?"):].strip()
        
        # Dividir la cadena en palabras separadas
        palabras = cadena.strip("b'\n").split(', ')
    
        # Crear un diccionario para mapear las palabras
        mapeo = {'FIRE': 'ROLL', 'PHREAK': 'DROP', 'GORGE': 'STOP'}
    
        # Iterar sobre cada palabra y aplicar el mapeo si es necesario
        palabras_intercambiadas = [mapeo.get(palabra, palabra) for palabra in palabras]
    
        # Unir las palabras intercambiadas de nuevo en una cadena
        cadena_intercambiada = '-'.join(palabras_intercambiadas)
    
        # Codificar la cadena intercambiada de nuevo en bytes
        cadena_intercambiada_bytes = cadena_intercambiada.encode()
    
        return cadena_intercambiada_bytes
     
    r = remote('94.237.61.79',  49263)
    print(r.recvuntil(b"Are you ready?"))
    r.sendline(b"y")
    print(r.recvline())
    
    string = r.recvline()
    print("La cadena leida es: ", string)
    salida = intercambiar_cadenas(string)
    print("la salida es: ", salida)
    r.sendline(salida)
    
    for i in range (0,500):
        string = r.recvline()
        print("La cadena leida es: ", string)
        salida = intercambiar_cadenas2(string)
        print("la salida es: ", salida)
        r.sendline(salida)
        print(i)
```  
  
---|---  
`

Como podemos ver, el servidor nos envia 500 cadenas las cuales nosotros tenemos que contestar de forma correcta para que nos arroje la flag.

### NOTA __

Leyendo otros writeups, he visto un script el cual realiza el mismo procedimiento pero de manera más compacta. Lo comparto a modo de curiosidad.

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
```

| 

```
     from pwn import *
    
    p = remote('127.0.0.1', 1337)
    
    p.sendlineafter(b'(y/n) ', b'y')
    p.recvline()
    
    while True:
        recv = p.recvlineS().strip()
    
        if 'GORGE' not in recv and 'PHREAK' not in recv and 'FIRE' not in recv:
            print(recv)
            break
    
        result = recv.replace(", ", "-")
        result = result.replace("GORGE", "STOP")
        result = result.replace("PHREAK", "DROP")
        result = result.replace("FIRE", "ROLL")
    
        p.sendlineafter(b'do? ', result.encode())
```  
  
---|---  
`

## Flag __

`HTB{1_wiLl_sT0p_dR0p_4nD_r0Ll_mY_w4Y_oUt!}`

__[Writeups Competiciones Internacionales](https://k3sero.github.io/categories/writeups-competiciones-internacionales/), [Miscelánea](https://k3sero.github.io/categories/miscel%C3%A1nea/)

__[Dificultad - Fácil](https://k3sero.github.io/tags/dificultad-f%C3%A1cil/) [Misc](https://k3sero.github.io/tags/misc/) [Misc - Scripts](https://k3sero.github.io/tags/misc-scripts/) [Otros - Writeups](https://k3sero.github.io/tags/otros-writeups/) [CyberApocalypseCTF](https://k3sero.github.io/tags/cyberapocalypsectf/)

Esta entrada está licenciada bajo [ CC BY 4.0 ](https://creativecommons.org/licenses/by/4.0/) por el autor.

Compartir [ __](https://twitter.com/intent/tweet?text=Stop%20Drop%20and%20Roll%20-%20CyberApocalypse2024%20-%20Kesero&url=https%3A%2F%2Fk3sero.github.io%2Fposts%2FStop-Drop-and-Roll-CyberApocalypse2024%2F "Twitter") [ __](https://www.facebook.com/sharer/sharer.php?title=Stop%20Drop%20and%20Roll%20-%20CyberApocalypse2024%20-%20Kesero&u=https%3A%2F%2Fk3sero.github.io%2Fposts%2FStop-Drop-and-Roll-CyberApocalypse2024%2F "Facebook") [ __](https://t.me/share/url?url=https%3A%2F%2Fk3sero.github.io%2Fposts%2FStop-Drop-and-Roll-CyberApocalypse2024%2F&text=Stop%20Drop%20and%20Roll%20-%20CyberApocalypse2024%20-%20Kesero "Telegram") __
