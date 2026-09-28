---
title: "Heritage Encryption - Urmia CTF 2024"
category: "osint"
type: "writeup"
tags: ["osint", "heritage", "encryption", "urmia-ctf", "urmia-ctf-2024", "2024", "ctf-writeup"]
summary: "HOST = 'heritage.uctf.ir'"
source:
  name: "CTFtime writeup #39447"
  url: "https://ctftime.org/writeup/39447"
ctf:
  name: "Urmia CTF 2024"
  year: 2024
  challenge: "Heritage Encryption"
---

## Metadata

- **CTF:** Urmia CTF 2024
- **Task:** Heritage Encryption
- **Author team:** Persian
- **CTFtime tags:** osint
- **CTFtime:** <https://ctftime.org/writeup/39447>

---
[osint.py](http://osint.py)

```  
import socket  
import time

HOST = '[heritage.uctf.ir](http://heritage.uctf.ir)'  
PORT = 1001

answers = [  
"Takht-e Jamshīd", # Stage 1  
"Chogha Zanbil", # Stage 2  
"Arg-e Bam", # Stage 3  
"Behistun Inscription", # Stage 4  
"Shushtar", # Stage 5  
"Qal’at-e Jargar", # Stage 6  
"Takht-e Soleyman" # Stage 6  
]

def connect_to_server(host, port):

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:  
s.connect((host, port))

for i in range(len(answers)):

response = s.recv(4096).decode('utf-8')  
print(response, end='')

if "Enter your answer:" in response:

answer = answers[i]  
s.sendall((answer + '\n').encode('utf-8'))

time.sleep(1)

while True:  
response = s.recv(4096).decode('utf-8')  
print(response, end='')

if "Enter your answer:" in response:  
user_answer = input()  
s.sendall((user_answer + '\n').encode('utf-8'))

if "Congratulations" in response or "Game Over" in response:  
pass

if __name__ == "__main__":  
connect_to_server(HOST, PORT)

```

output:

Welcome to the 'Heritage Encryption: Cracking the Past' Challenge!  
Solve the clues to reveal the ancient secrets of Persia.  
You have only 90 seconds to finish the challange :)

Stage 1:  
Clue: The ancient throne of kings, where stone pillars whisper tales of imperial grandeur.  
Enter your answer: Your similarity score: 100.00  
Congratulations! You've completed stage 1.  
The correct answer for this stage was: Takht-e Jamshīd

Stage 2:  
Clue: A towering relic from the sands, where echoes of ancient gods and ziggurats still resonate.  
Enter your answer: Your similarity score: 100.00  
Congratulations! You've completed stage 2.  
The correct answer for this stage was: Chogha Zanbil

Stage 3:  
Clue: A fortress of resilience amidst the desert, cradling centuries of forgotten secrets.  
Enter your answer: Your similarity score: 100.00  
Congratulations! You've completed stage 3.  
The correct answer for this stage was: Arg-e Bam

Stage 4:  
Clue: A monumental script carved in rock, narrating the epic victories of a king against a backdrop of rugged cliffs.  
Enter your answer: Your similarity score: 100.00  
Congratulations! You've completed stage 4.  
The correct answer for this stage was: Behistun Inscription

Stage 5:  
Clue: An ancient city of water and stone, where ingenious engineering defied the forces of nature.  
Enter your answer: Your similarity score: 100.00  
Congratulations! You've completed stage 5.  
The correct answer for this stage was: Shushtar

Stage 6:  
Clue: A solitary fortress steeped in mystery, guarding the whispers of Persia’s ancient past.  
Enter your answer: Your similarity score: 100.00  
Congratulations! You've completed stage 6.  
The correct answer for this stage was: Qal’at-e Jargar

Stage 7:  
Clue: A sacred sanctuary of fire and water, where divine mysteries and ancient rituals converge.  
Enter your answer: Your similarity score: 100.00  
Congratulations! You've completed stage 7.  
The correct answer for this stage was: Takht-e Soleyman  
Challenge Completed! Here is your flag: UCTF{T1m3l3ss_W0nd3r5_0f_4nc13nt_P3rs14_F4ll3n_Gr34tN3ss}
