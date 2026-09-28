---
title: "Изменен, но не сломлен. - KubanCTF Qualifier 2024"
category: "forensics"
subcategory: "network"
type: "writeup"
tags: ["forensics", "pcap", "wireshark", "network", "kubanctf-qualifier", "kubanctf-qualifier-2024", "2024", "ctf-writeup"]
summary: "Есть pcap файл с каким то трафиком TCP"
source:
  name: "CTFtime writeup #39466"
  url: "https://ctftime.org/writeup/39466"
ctf:
  name: "KubanCTF Qualifier 2024"
  year: 2024
  challenge: "Изменен, но не сломлен."
---

## Metadata

- **CTF:** KubanCTF Qualifier 2024
- **Task:** Изменен, но не сломлен.
- **Author team:** Capybaras
- **CTFtime tags:** forensics
- **CTFtime:** <https://ctftime.org/writeup/39466>

---
Есть pcap файл с каким то трафиком TCP  
Открываем в wireshark и нажимаем экспортировать  
(скрин 1)выбираем самый большой пакет и нажимаем сохранить  
(скрин 2)  
Открываем и видим что это обычный post запрос на загрузку картинки и после хедеров идет сама картинка. Открываем HxD и удаляем все из начала до сигнатуры png %PNG и сохраняем как .png, открываем и получаем картинку с флагом. (3 скрин)Сложный не такой уж и сложный.

<https://imgur.com/JavOYhz>  
<https://imgur.com/3Y0Dmvc>  
<https://imgur.com/xzaZAyt>
