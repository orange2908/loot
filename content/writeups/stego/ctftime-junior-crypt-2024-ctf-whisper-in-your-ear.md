---
title: "Whisper in your ear - Junior.Crypt.2024 CTF"
category: "stego"
type: "writeup"
tags: ["stego", "whisper", "ear", "junior-crypt-2024-ctf", "2024", "ctf-writeup"]
summary: "В этой задаче мы должны найти скрытый флаг в двух аудиофайлах sample-3sx.wav и sample-3sxyz.wav с помощью методов стеганографии."
source:
  name: "CTFtime writeup #39311"
  url: "https://ctftime.org/writeup/39311"
ctf:
  name: "Junior.Crypt.2024 CTF"
  year: 2024
  challenge: "Whisper in your ear"
---

## Metadata

- **CTF:** Junior.Crypt.2024 CTF
- **Task:** Whisper in your ear
- **Author team:** Capybaras
- **CTFtime tags:** stego
- **CTFtime:** <https://ctftime.org/writeup/39311>

---
Описание

В этой задаче мы должны найти скрытый флаг в двух аудиофайлах sample-3sx.wav и sample-3sxyz.wav с помощью методов стеганографии.

Шаги

Определяем функцию subtract_files, которая вычитает байты из одного файла из другого и сохраняет результат в новый файл.  
Вычитаем байты из файла sample-3sxyz.wav из файла sample-3sx.wav и сохраняем результат в файл result.bin.  
Анализируем файл result.bin и находим, что различия между файлами находятся только в начале файла.  
Используем "шепот в ухо" (Whisper in your ear) - метод стеганографии, который заключается в извлечении последнего бита каждого байта файла.  
Читаем файл result.bin байт за байтом и извлекаем последний бит каждого байта, если он находится на третьей позиции в байте.  
Формируем строку битов и удаляем первые 11 бит.  
Разбиваем строку битов на группы по 8 бит и преобразуем их в символы ASCII.  
Выводим полученный текст, который является флагом.  
Флаг

Флагом является grodno{find_secret_in_2st_chanell}.

Вывод

В этом задании мы использовали методы стеганографии, такие как вычитание файлов и извлечение последнего бита каждого байта, чтобы найти скрытый флаг в аудиофайлах.
