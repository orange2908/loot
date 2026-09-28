---
title: "readme - ImaginaryCTF 2024"
category: "web"
type: "writeup"
tags: ["web", "nginx", "readme", "imaginaryctf", "imaginaryctf-2024", "2024", "ctf-writeup"]
summary: "All you had to do was read the DockerFile......"
source:
  name: "CTFtime writeup #39340"
  url: "https://ctftime.org/writeup/39340"
ctf:
  name: "ImaginaryCTF 2024"
  year: 2024
  challenge: "readme"
---

## Metadata

- **CTF:** ImaginaryCTF 2024
- **Task:** readme
- **Author team:** 2amResearch
- **CTFtime:** <https://ctftime.org/writeup/39340>

---
All you had to do was read the DockerFile...... really???

```dockerfile  
FROM node:20-bookworm-slim

RUN apt-get update \  
&& apt-get install -y nginx tini \  
&& apt-get clean \  
&& rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

WORKDIR /app  
COPY package.json yarn.lock ./  
RUN yarn install --frozen-lockfile  
COPY src ./src  
COPY public ./public

COPY default.conf /etc/nginx/sites-available/default  
COPY [start.sh](http://start.sh) /[start.sh](http://start.sh)

ENV FLAG="ictf{path_normalization_to_the_rescue}"

ENTRYPOINT ["/usr/bin/tini", "--"]  
CMD ["/[start.sh](http://start.sh)"]  
```

FLAG: `ictf{path_normalization_to_the_rescue}`
