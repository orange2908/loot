---
title: "find_the_flag3 - VolgaCTF 2024 Qualifier"
category: "web"
subcategory: "websocket"
type: "writeup"
tags: ["web", "websocket", "find", "flag3", "volgactf-2024-qualifier", "2024", "ctf-writeup"]
summary: "Writeup for find_the_flag3 from VolgaCTF 2024 Qualifier."
source:
  name: "CTFtime writeup #38975"
  url: "https://ctftime.org/writeup/38975"
ctf:
  name: "VolgaCTF 2024 Qualifier"
  year: 2024
  challenge: "find_the_flag3"
---

## Metadata

- **CTF:** VolgaCTF 2024 Qualifier
- **Task:** find_the_flag3
- **Author team:** Bushwhackers
- **CTFtime tags:** web
- **CTFtime:** <https://ctftime.org/writeup/38975>

---
# Посмотрим js код на сайте. ![image](<https://github.com/aksden42/VolgaCTF2024_qualifer_find_the_flag3/blob/main/volga1.jpg?raw=true>)

# Тут интересная 11 строчка. Попробуем пойти по пути /worker11111.js, и мы увидим первую часть флага.  
## ![image](<https://raw.githubusercontent.com/aksden42/VolgaCTF2024_qualifer_find_the_flag3/main/volga2.jpg>) 

# Смотрим дальше код и находим следующий фрагмент:  
![image](<https://raw.githubusercontent.com/aksden42/VolgaCTF2024_qualifer_find_the_flag3/main/volga3.jpg>)

# Тут у нас инициализируется Web Socket соединение с backendHost и отправляется сообщение "info". Хорошо, читаем дальше, и понимаем чему равен backendHost.   
![image](<https://raw.githubusercontent.com/aksden42/VolgaCTF2024_qualifer_find_the_flag3/main/volga4.jpg>)

# backendHost = 172.105.246.165:3001. С web консоли в браузере попробуем по WebSocket подключится на этот адрес:  
![image](<https://raw.githubusercontent.com/aksden42/VolgaCTF2024_qualifer_find_the_flag3/main/volga5.jpg>)  
# Теперь отправим "info".   
![image](<https://raw.githubusercontent.com/aksden42/VolgaCTF2024_qualifer_find_the_flag3/main/volga6.jpg>)

# Нам сервер отвечает "work work work". Давайте вместе "info" отправим строку "flag".  
![image](<https://raw.githubusercontent.com/aksden42/VolgaCTF2024_qualifer_find_the_flag3/main/volga7.jpg>)

# Отлично, у нас есть вторая часть флага. Продолжим поиски. Далее рассмотрим этот кусок кода:  
![image](<https://raw.githubusercontent.com/aksden42/VolgaCTF2024_qualifer_find_the_flag3/main/volga8.jpg>)

# Тут идёт взаимодейтвие между /worker.js и /api/code/part3. Так же берётся с локального хранилища "unlockCode" который используется дальше в /api/code/part3. Давайте посмотрим на /worker.js  
![image](<https://raw.githubusercontent.com/aksden42/VolgaCTF2024_qualifer_find_the_flag3/main/volga9.jpg>)

# worker.js принимает unclockCode и далее генерируется js код (строка const code = ...). Заметим, в конце строки вставляется e.data.code, а потом вызывается eval от code. Теперь давайте посмотрим на /api/code/part3:  
![image](<https://raw.githubusercontent.com/aksden42/VolgaCTF2024_qualifer_find_the_flag3/main/volga10.jpg>)

# Этот код манипулирует positions и secretKey из worker.js. Этот код и подставляется на место e.data.code. Давайте соберём вместе эти два кода воедино.  
![image](<https://raw.githubusercontent.com/aksden42/VolgaCTF2024_qualifer_find_the_flag3/main/volga11.jpg>)

# И мы получим третий кусок флага:  
![image](<https://raw.githubusercontent.com/aksden42/VolgaCTF2024_qualifer_find_the_flag3/main/volga12.jpg>)

# Всем спасибо за внимание:)
