---
title: "leaving soon - justCTF 2024 teaser"
category: "forensics"
subcategory: "network"
type: "writeup"
tags: ["forensics", "drm", "network", "suricata", "widevine", "shovel", "pcap", "wireshark", "justctf-2024-teaser", "2024", "ctf-writeup"]
summary: "We are given a single file catflix84211ce530de315018956d36098c1566.pcapng."
source:
  name: "CTFtime writeup #39222"
  url: "https://ctftime.org/writeup/39222"
ctf:
  name: "justCTF 2024 teaser"
  year: 2024
  challenge: "leaving soon"
---

## Metadata

- **CTF:** justCTF 2024 teaser
- **Task:** leaving soon
- **Author team:** ECSC Team France
- **CTFtime tags:** drm, network, suricata, widevine, shovel
- **CTFtime:** <https://ctftime.org/writeup/39222>

---
## Challenge description

> My friend wanted to rewatch this cool miniseries on Catflix but it looks like they removed it. Can you help him recover all episodes from the network capture?

We are given a single file `catflix_84211ce530de315018956d36098c1566.pcapng`.

## Network forensics using Suricata

We start be opening the PCAPng in Wireshark, there's a lot of traffic.  
Because there seems to be many HTTP requests, Wireshark is maybe not the best tool for that.  
We should rather use a tool that works at the TCP flow level rather than at the packet level.

Let's use a Suricata GUI to reassemble the HTTP traffic for us:  
```  
$ git clone <https://github.com/ANSSI-FR/shovel.git> && cd shovel  
Cloning into 'shovel'...  
[...] (commit 4625bf5ec48f1afcd7fe7615375b38e998ca7f3c)  
$ mkdir input_pcaps  
$ cp path/to/catflix_84211ce530de315018956d36098c1566.pcapng input_pcaps/  
$ cp example.env .env  
$ echo PCAP_FILE_CONTINUOUS=false >> .env  
$ docker compose up  
```  
We then go to http://localhost:8000/ and we are greeted with a lot of "RAW" flows.  
We add a protocol filter on "HTTP", and tadam! We now see some HTTP interesting flows.

![Shovel](<https://i.imgur.com/ZlVuthf.png>)

So there are many HTTP files that we should download to investigate more.  
**We notice some HTTP range requests, we need to reassemble these. Suricata already did most of the work by providing a `start` value in `fileinfo` events, which are triggered when a HTTP traffic exchange files.**  
Using Shovel API, we can quickly write a small Python script:

```python  
import requests  
import pathlib

data = {}  
# For each HTTP flow, get all corresponding `fileinfo` events  
for flow in requests.get("http://localhost:8000/api/flow?app_proto=http").json().get("flows"):  
flow_id = flow["id"]  
flow_event = requests.get(f"http://localhost:8000/api/flow/{flow_id}").json()  
for file in flow_event["fileinfo"]:  
# Get fileinfo properties  
filename = file["filename"]  
sha256 = file["sha256"]  
start = file.get("start", 0)

# Reconstruct the file  
if filename not in data:  
data[filename] = bytearray(1000000)  
d = open(f"/path/to/shovel/suricata/output/filestore/{sha256[:2]}/{sha256}", "rb").read()  
data[filename][start:start+len(d)] = d

# Save all files in webserver/ folder  
for filename, d in data.items():  
dest = f"webserver{filename}"  
pathlib.Path(dest).parent.mkdir(parents=True, exist_ok=True)  
open(dest, "wb").write(d)  
```

Tadam! We successfully extracted the whole HTTP server.

## Hosting the server

The files look like MPEG-DASH.  
We notice some references to `<https://github.com/shaka-project/shaka-packager>` project in the MPD files.  
Seeing `ContentProtection` and `"license_server":"<https://proxy.uat.widevine.com/proxy>"`, we understand that we need a player compatible with the Widevine DRM.

Let's host a static file server hosting Shaka-Player:  
```  
caddy file-server --root webserver/ --listen :8001  
```

We create `webserver/index.html` with:  
```html

<html>  
<head>  
<script src="shaka-player.compiled.js"></script>  
<script src="myapp.js"></script>  
</head>  
<body>  
<video id="video" width="640" poster="//[shaka-player-demo.appspot.com/assets/poster.jpg](https://shaka-player-demo.appspot.com/assets/poster.jpg)" controls autoplay></video>  
</body>  
</html>  
```  
and `webserver/myapp.js` with:  
```js  
const manifestUri = '/media/episode_5.mpd'; // CHANGE EP NUMBER HERE

function initApp() {  
shaka.polyfill.installAll();  
if (shaka.Player.isBrowserSupported()) {  
initPlayer();  
} else {  
console.error('Browser not supported!');  
}  
}  
async function initPlayer() {  
const video = document.getElementById('video');  
const player = new shaka.Player();  
await player.attach(video);  
window.player = player;  
player.addEventListener('error', onErrorEvent);  
player.configure({  
drm: {  
servers: {  
'com.widevine.alpha': '<https://proxy.uat.widevine.com/proxy'>,  
},  
},  
manifest: {  
dash: {  
keySystem: 'com.widevine.alpha',  
}  
}  
});

try {  
await player.load(manifestUri, startTime=17);  
console.log('The video has now been loaded!');  
} catch (e) {  
onError(e);  
}  
}  
function onErrorEvent(event) {  
onError(event.detail);  
}  
function onError(error) {  
console.error('Error code', error.code, 'object', error);  
}  
document.addEventListener('DOMContentLoaded', initApp);  
```

![Flag char "t"](<https://i.imgur.com/lZPjFil.png>)

Then we see a flag character in the video! After updating `manifestUri` 35 times, we get the flag:  
```  
justCTF{Y0u_w0uldnt_d0wnl04d_a_C4T}  
```
