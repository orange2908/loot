---
title: "Capybara Admin Portal - KubSTU CTF"
category: "web"
subcategory: "lfi"
type: "writeup"
tags: ["web", "path-traversal", "jwt", "capybara", "admin", "portal", "lfi", "kubstu-ctf", "ctf-writeup"]
summary: "Вход в CapyAdmin состоит из логина/пароля + псевдо-2FA страницы."
source:
  name: "CTFtime writeup #40756"
  url: "https://ctftime.org/writeup/40756"
ctf:
  name: "KubSTU CTF"
  challenge: "Capybara Admin Portal"
---

## Metadata

- **CTF:** KubSTU CTF
- **Task:** Capybara Admin Portal
- **Author team:** БАГодельня
- **CTFtime:** <https://ctftime.org/writeup/40756>

---
Вход в CapyAdmin состоит из логина/пароля + псевдо-2FA страницы.

На 2FA-странице в JS есть подсказка:  
\- внутренний эндпоинт: POST /admin/account/<id>  
\- используется JWT из localStorage

Брутим логин по rockyou.txt опираясь на ответы:  
\- "404 Пользователь не найден" > логина нет  
\- "401 Неверный пароль..." > логин существует  
Находим логин: angel

Далее брутим пароля для angel по rockyou.txt, пока не получим успешный вход  
Находим пароль: princess

Пара angel:princess возвращает JWT и user_id=679202372644, редирект на /2fa

Делаем запрос к своему аккаунту: POST /admin/account/679202372644  
Ответ говорит, что флаг находится в аккаунте 239716013

Обход проверки доступа через path traversal в параметре пути: POST /admin/account/679202372644../239716013  
Запрос делаем со своим же JWT и телом {"action":"fetch_secure_data"}, сервер возвращает данные аккаунта админа и флаг
