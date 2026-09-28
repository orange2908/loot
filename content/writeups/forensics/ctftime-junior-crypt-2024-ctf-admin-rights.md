---
title: "Admin rights - Junior.Crypt.2024 CTF"
category: "forensics"
type: "writeup"
tags: ["forensics", "admin", "rights", "junior-crypt-2024-ctf", "2024", "ctf-writeup"]
summary: "Задача: Поиск административной учетной записи"
source:
  name: "CTFtime writeup #39309"
  url: "https://ctftime.org/writeup/39309"
ctf:
  name: "Junior.Crypt.2024 CTF"
  year: 2024
  challenge: "Admin rights"
---

## Metadata

- **CTF:** Junior.Crypt.2024 CTF
- **Task:** Admin rights
- **Author team:** Capybaras
- **CTFtime tags:** forensics
- **CTFtime:** <https://ctftime.org/writeup/39309>

---
Задача: Поиск административной учетной записи

Нам был предоставлен файл SAM, который является файлом реестра Windows, хранящим информацию об учетных записях пользователей и хеш-паролях. Наша задача состояла в том, чтобы найти административную учетную запись.

Понимание файла SAM

Файл SAM обычно находится в C:\Windows\System32\config\SAM и заблокирован во время работы Windows, чтобы предотвратить несанкционированные изменения. Он хранит информацию об учетных записях пользователей и хеш-паролях.

Используемые инструменты

Мы пытались использовать инструменты, такие как samdump2, pwdump и [secretsdump.py](http://secretsdump.py), чтобы извлечь информацию об учетных записях пользователей из файла SAM. Однако эти инструменты не смогли извлечь информацию об административной учетной записи.

Решение: Использование chntpw

В конце концов, мы использовали инструмент chntpw, который является офлайн-редактором паролей и реестра NT. Он может сбрасывать или удалять пароли для локальных учетных записей на системах Windows и редактировать реестр Windows офлайн.

Мы установили chntpw с помощью sudo apt install chntpw, а затем использовали команду chntpw -l SAM, чтобы список пользователей в реестре.

Вывод

Вывод показал нам список пользователей, включая административную учетную запись:

Verify

Open In Editor  
Edit  
Copy code  
| RID -|---------- Username ------------| Admin? |- Lock? --|  
| 0516 | user_7565 | ADMIN | *BLANK* |  
Флаг

Флагом было grodno{user_7565}.
