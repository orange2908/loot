---
title: "[Forensics] Lssas Crackdown - SpookyCTF 2024"
category: "forensics"
subcategory: "memory"
type: "writeup"
tags: ["process", "forensics", "windows", "ntlm", "memory-forensics", "memory", "spookyctf", "spookyctf-2024", "2024", "ctf-writeup"]
summary: "Lsass Crackdown - SpookyCTF2024"
source:
  name: "CTFtime writeup #39620"
  url: "https://ctftime.org/writeup/39620"
original_source: "https://k3sero.github.io/posts/Lsass-Crackdown-Forense-SpookyCTF2024/"
ctf:
  name: "SpookyCTF 2024"
  year: 2024
  challenge: "[Forensics] Lssas Crackdown"
---

## Metadata

- **CTF:** SpookyCTF 2024
- **Task:** [Forensics] Lssas Crackdown
- **Author team:** Caliphal Hounds
- **CTFtime tags:** process, forensics, windows, ntlm
- **CTFtime:** <https://ctftime.org/writeup/39620>
- **Original writeup:** <https://k3sero.github.io/posts/Lsass-Crackdown-Forense-SpookyCTF2024/>

---
Lsass Crackdown - SpookyCTF2024 __

Contenido __

Lsass Crackdown - SpookyCTF2024

__

Autor del reto: `Trent`

Dificultad: Fácil

## Enunciado __

Anna Circoh has intercepted a highly sensitive memory dump, but The Consortium has fortified it with advanced encryption, hiding their deepest secrets within. Participants must analyze the data and navigate through layers of defenses to find a key piece of information we are thinking its a leaked password. Dr. Tom Lei has rigged the memory with decoys and traps, so tread carefully—one wrong step could lead you down a path of misdirection.

Some AV’s may detect the attachment as malicious. This is a false positive and can be ignored

## Archivos __

En este reto nos dan el siguiente archivo.

  * `dump.DMP`: Archivo que contiene el dumpeo de un proceso en Windows.


Archivos utilizados en mi [repositorio de Github](https://github.com/k3sero/Blog_Content/tree/main/Competiciones_Internacionales_Writeups/2024/Forensics/Spookyctf2024/Lsass_Crackdown).

## Analizando el Código __

En este reto básicamente tenemos un dumpeo de memoria proveniente de un equipo en Windows, concretamente se trata de un proceso`LSASS` (Local Security Authority) el cual se encarga de gestionar la autenticación de los usuarios, creación de tokens de acceso y su almacenamiento en caché. La clave para obtener la flag es encontrar la contraseña de DR.Tom. Para ello, tendremos que navegar por dicho dumpeo de memoria y analizar el contenido.

## Solución __

En este caso voy a utilizar la herramienta[ypykatz](https://github.com/skelsec/pypykatz) la cual se encarga de descomponer dicho proceso LSASS en secciones acorde a la información que encuentra.

Para instalar la herramienta simplemente utilicé los siguientes comandos.

____

`

```
    1
    2
    3
```

| 

```
        sudo apt install python3-pypykatz
        python3 -m venv venv  
        pip3 install minidump minikerberos aiowinreg msldap winacl
```  
  
---|---  
`

Una vez tenemos la herramienta instalada, utilizando el siguiente comando nos arroja un informe detallado de toda la información de dicho proceso (Dumpeo completo en archivos)

____

`

```
    1
    2
```

| 

```
        ┌──(kesero㉿kali)-[~]
        └─$ pypykatz lsa minidump dump.DMP
```  
  
---|---  
`

Llegados a este punto, la clave para resolver el reto es filtrar de forma correcta por el hash NTLM correcto para obtener la contraseña de DR.Tom. Como tenemos un usuario que se llama igual que la corporación `Consortium` vamos a extraer el hash NTLM de dicho usuario.

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
```

| 

```
        FILE: ======== dump.DMP =======
        == LogonSession ==
        authentication_id 6471305 (62be89)
        session_id 2
        username Consortium
        domainname DESKTOP-UBFFHS2
        logon_server DESKTOP-UBFFHS2
        logon_time 2024-10-18T01:40:41.720992+00:00
        sid S-1-5-21-996221637-1914836208-3740248221-1011
        luid 6471305
                == MSV ==
                        Username: Consortium
                        Domain: DESKTOP-UBFFHS2
                        LM: NA
                        NT: f6c479f4b9904f884fede1b2d4328d98
                        SHA1: 8e0cf85ff4c266ff4ef626580cce1ff025118c6f
                        DPAPI: 8e0cf85ff4c266ff4ef626580cce1ff025118c6f
                == WDIGEST [62be89]==
                        username Consortium
                        domainname DESKTOP-UBFFHS2
                        password None
                        password (hex)
                == Kerberos ==
                        Username: Consortium
                        Domain: DESKTOP-UBFFHS2
                == WDIGEST [62be89]==
                        username Consortium
                        domainname DESKTOP-UBFFHS2
                        password None
                        password (hex)
                == DPAPI [62be89]==
                        luid 6471305
                        key_guid cd06bac7-841e-4615-afdf-735caa9878b6
                        masterkey 9447b5b0b2e2ebbec0bd1298e3e411612413f39cfbb8a6019a0bd2e14be8e45d602fdd4f96d22f977161988f0d4b6090bf992bea9abb4dc64873bfedff8ed10f
                        sha1_masterkey 1256160a5105caf7146b49f397a95efee53e4376
```  
  
---|---  
`

Una vez tenemos el hash NTLM de dicho usuario `f6c479f4b9904f884fede1b2d4328d98` podemos crackearlo de forma manual o directamente usar `crackstation` y podemos observar que dicho hash coincide con `1987evilovekoen`

[![Hash](https://github.com/k3sero/Blog_Content/blob/main/Competiciones_Internacionales_Writeups/2024/Forensics/Spookyctf2024/Lsass_Crackdown/hash.png?raw=true)](https://github.com/k3sero/Blog_Content/blob/main/Competiciones_Internacionales_Writeups/2024/Forensics/Spookyctf2024/Lsass_Crackdown/hash.png?raw=true)

## Flag __

`NICC{1987evilovekoen}`

__[Writeups Competiciones Internacionales](https://k3sero.github.io/categories/writeups-competiciones-internacionales/), [Forense](https://k3sero.github.io/categories/forense/)

__[Forense](https://k3sero.github.io/tags/forense/) [Forense - LSASS](https://k3sero.github.io/tags/forense-lsass/) [Otros - Writeups](https://k3sero.github.io/tags/otros-writeups/) [Dificultad - Fácil](https://k3sero.github.io/tags/dificultad-f%C3%A1cil/) [SpookyCTF](https://k3sero.github.io/tags/spookyctf/)

Esta entrada está licenciada bajo [ CC BY 4.0 ](https://creativecommons.org/licenses/by/4.0/) por el autor.

Compartir [ __](https://twitter.com/intent/tweet?text=Lsass%20Crackdown%20-%20SpookyCTF2024%20-%20Kesero&url=https%3A%2F%2Fk3sero.github.io%2Fposts%2FLsass-Crackdown-Forense-SpookyCTF2024%2F "Twitter") [ __](https://www.facebook.com/sharer/sharer.php?title=Lsass%20Crackdown%20-%20SpookyCTF2024%20-%20Kesero&u=https%3A%2F%2Fk3sero.github.io%2Fposts%2FLsass-Crackdown-Forense-SpookyCTF2024%2F "Facebook") [ __](https://t.me/share/url?url=https%3A%2F%2Fk3sero.github.io%2Fposts%2FLsass-Crackdown-Forense-SpookyCTF2024%2F&text=Lsass%20Crackdown%20-%20SpookyCTF2024%20-%20Kesero "Telegram") __
