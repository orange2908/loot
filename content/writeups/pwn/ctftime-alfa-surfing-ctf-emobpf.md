---
title: "ЭМОциональное приключение (emobpf) - Alfa Surfing CTF"
category: "pwn"
type: "writeup"
tags: ["bpf", "kernel", "pwn", "emobpf", "alfa-surfing-ctf", "ctf-writeup"]
summary: "Авторский эксплойт: <https://github.com/mephi42/ctf/blob/master/2025.09.16-AlfaSurfingCTF/emobpf/solution/pwnit.c>"
source:
  name: "CTFtime writeup #40437"
  url: "https://ctftime.org/writeup/40437"
original_source: "https://github.com/mephi42/ctf/tree/master/2025.09.16-Alfa_Surfing_CTF/emobpf"
ctf:
  name: "Alfa Surfing CTF"
  challenge: "ЭМОциональное приключение (emobpf)"
---

## Metadata

- **CTF:** Alfa Surfing CTF
- **Task:** ЭМОциональное приключение (emobpf)
- **Author team:** SPbCTF
- **CTFtime tags:** bpf, kernel, pwn
- **CTFtime:** <https://ctftime.org/writeup/40437>
- **Original writeup:** <https://github.com/mephi42/ctf/tree/master/2025.09.16-Alfa_Surfing_CTF/emobpf>

---
Авторский эксплойт: [<https://github.com/mephi42/ctf/blob/master/2025.09.16-Alfa_Surfing_CTF/emobpf/solution/pwnit.c>](<https://github.com/mephi42/ctf/blob/master/2025.09.16-Alfa_Surfing_CTF/emobpf/solution/pwnit.c>)

Изначально флаг находится в initramfs, поэтому его можно найти в памяти ядра. Таким образом, для решения задания полная эксалация привилегий не нужна, достаточно найти способ читать память ядра.

Патч на ядро позволяет BPF программам читать данные, находящиеся в памяти после конца пакета. В выданном ядре eBPF недоступен, но можно создать UDP сокет и подключить к нему cBPF программу с помощью `SO_ATTACH_FILTER`. С помощью такой программы можно считывать из ядра 1 бит за пакет, наблюдая за тем, доставляется пакет или нет.

Если посылать в этот сокет пакеты размера, который редко выделяется ядром, то они будут выделяться по одному и тому же адресу. Таким образом, можно побитово считывать память, следующую за пакетом, пока не найдется флаг. Для оптимизации можно использовать тот факт, что флаг в памяти всегда выровнен на страницу.
