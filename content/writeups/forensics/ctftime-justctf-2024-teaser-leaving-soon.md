---
title: "leaving soon - justCTF 2024 teaser"
category: "forensics"
subcategory: "network"
type: "writeup"
tags: ["forensics", "pcap", "tshark", "leaving", "soon", "network", "justctf-2024-teaser", "2024", "ctf-writeup"]
summary: "We were given a network packet capture named catflix.pcapng, consisting of various protocols, as follows:"
source:
  name: "CTFtime writeup #39251"
  url: "https://ctftime.org/writeup/39251"
original_source: "https://hackmd.io/@vidner/just-sksd-2024#Leaving-soon"
ctf:
  name: "justCTF 2024 teaser"
  year: 2024
  challenge: "leaving soon"
---

## Metadata

- **CTF:** justCTF 2024 teaser
- **Task:** leaving soon
- **Author team:** SKSD
- **CTFtime:** <https://ctftime.org/writeup/39251>
- **Original writeup:** <https://hackmd.io/@vidner/just-sksd-2024#Leaving-soon>

---
>My friend wanted to rewatch this cool miniseries on Catflix but it looks like they removed it. Can you help him recover all episodes from the network capture?

We were given a network packet capture named catflix.pcapng, consisting of various protocols, as follows:  
```sh  
» tshark -r catflix.pcapng -qz   
===================================================================  
Protocol Hierarchy Statistics  
Filter:

frame frames:31331 bytes:3780884  
eth frames:31331 bytes:3780884  
ip frames:31117 bytes:3779777  
udp frames:943 bytes:323491  
data frames:183 bytes:36741  
dns frames:36 bytes:3582  
quic frames:608 bytes:269396  
quic frames:14 bytes:10731  
nbns frames:28 bytes:2576  
mdns frames:56 bytes:4816  
ssdp frames:28 bytes:6020  
ntp frames:4 bytes:360  
tcp frames:30153 bytes:3747302  
tls frames:2834 bytes:4532961  
tcp.segments frames:602 bytes:1244373  
tls frames:590 bytes:1230237  
http frames:899 bytes:1281707  
json frames:35 bytes:13045  
tcp.segments frames:35 bytes:86964  
mp4 frames:350 bytes:936313  
tcp.segments frames:280 bytes:906773  
media frames:13 bytes:37289  
tcp.segments frames:13 bytes:37289  
data frames:13 bytes:18247  
tcp.segments frames:13 bytes:18247  
tcp.segments frames:14 bytes:23030  
data frames:40 bytes:58640  
igmp frames:21 bytes:1260  
arp frames:214 bytes:11076  
===================================================================  
```  
Based on the description, we've observed that most of the traffic came from a video-streaming service, which seems to have been taken down. Furthermore, let's see how many episodes need to be recovered.  
```sh  
» tshark -r catflix.pcapng -Y http.request -Tfields -e http.request.uri  
/  
/generate_204  
/api/episodes/0  
/media/episode_0.mpd  
/media/episodes%2Fepisode_0_video.mp4  
/media/episodes%2Fepisode_0_audio.mp4  
/media/episodes%2Fepisode_0_audio.mp4  
/media/episodes%2Fepisode_0_video.mp4  
[..snip..]  
/api/episodes/34  
/media/episode_34.mpd  
/media/episodes%2Fepisode_34_video.mp4  
/media/episodes%2Fepisode_34_audio.mp4  
/media/episodes%2Fepisode_34_audio.mp4  
/media/episodes%2Fepisode_34_video.mp4

» tshark -r catflix.pcapng -Y 'mp4' -Tfields -e http.content_range  
bytes 1276-1343/148728  
bytes 1126-1193/257048  
bytes 0-1275/148728  
bytes 0-1125/257048  
bytes 1344-84498/148728  
bytes 1194-105575/257048  
bytes 84499-128764/148728  
bytes 105576-212744/257048  
bytes 212745-257047/257048  
bytes 128765-148727/148728  
bytes 1276-1343/148490  
bytes 1126-1193/257048  
bytes 0-1125/257048  
bytes 0-1275/148490  
[..snip..]  
```  
As we can see, the traffic starts with an MPD file being fetched before the video segments are downloaded and played. Each of the video segments was partially requested using the `HTTP Range: bytes` header. As expected, this behavior was influenced by the MPD manifest file.  
```xml  
<Representation id="1" bandwidth="77715" codecs="avc1.640015" mimeType="video/mp4" sar="1:1">  
<BaseURL>episodes%2Fepisode_0_video.mp4</BaseURL>  
<SegmentBase indexRange="1276-1343" timescale="12800" presentationTimeOffset="294">  
<Initialization range="0-1275"/>  
</SegmentBase>  
</Representation>  
```  
Before diving deeper, let's try to reconstruct **episode_0_video.mp4** by sorting both **http.content_range** and **http.file_data**.  
```sh  
» tshark -r catflix.pcapng -Y 'mp4 and http.response_for.uri matches "_0_video.mp4"' -Tfields -e http.content_range > range  
» tshark -r catflix.pcapng -Y 'mp4 and http.response_for.uri matches "_0_video.mp4"' -Tfields -e http.file_data > data  
» paste range data | sort -k2 -n | awk '{print $3}' | xxd -r -p > episode_0_video.mp4  
```  
Unfortunately, we got no video playback from the MP4 file. Thus, we tried to force FFMPEG to ignore the error by doing something like this:  
```sh  
» ffmpeg -err_detect ignore_err -i episode_0_video.mp4 -c copy fixed.mp4  
```  
Eventually, we managed to see a cat video for the first 7 seconds. After that, the video became more distorted and unplayable. After a while, we decided to check the video properties.

```sh  
» mediainfo episode_0_video.mp4  
General  
Complete name : episode_0_video.mp4  
Format : MPEG-4  
Format profile : Base Media / Version 1  
Codec ID : mp41 (iso8/isom/mp41/dash/avc1/cmfc)  
File size : 145 KiB  
Duration : 18 s 600 ms  
Overall bit rate : 64.0 kb/s  
Encoded date : UTC 2024-06-13 20:43:31  
Tagged date : UTC 2024-06-13 20:43:31

Video  
ID : 1  
Format : AVC  
Format/Info : Advanced Video Codec  
Format profile : [[email protected]](https://ctftime.org/cdn-cgi/l/email-protection)  
Format settings : CABAC / 4 Ref Frames  
Format settings, CABAC : Yes  
Format settings, Reference frames : 4 frames  
Codec ID : encv / avc1  
Codec ID/Info : Advanced Video Coding  
Duration : 18 s 600 ms  
Bit rate : 59.1 kb/s  
Width : 480 pixels  
Height : 360 pixels  
Display aspect ratio : 4:3  
Frame rate mode : Constant  
Frame rate : 25.000 FPS  
Color space : YUV  
Chroma subsampling : 4:2:0  
Bit depth : 8 bits  
Scan type : Progressive  
Bits/(Pixel*Frame) : 0.014  
Stream size : 134 KiB (92%)  
Encoded date : UTC 2024-06-13 20:43:31  
Tagged date : UTC 2024-06-13 20:43:31  
Encryption : Encrypted  
Color range : Limited  
Color primaries : BT.709  
Transfer characteristics : sRGB/sYCC  
Codec configuration box : avcC  
```  
It turned out that the MP4 video was encrypted from the beginning, specifically DRM-protected. DRM (Digital Rights Management) refers to technology designed to control how digital content can be accessed, used, and distributed. DRM is used by content creators and distributors to protect their intellectual property rights and prevent unauthorized copying, sharing, and piracy. Therefore, the video content is often encrypted, making it unreadable without the proper decryption keys. This ensures that only authorized users can view the content.

Just in case, let's verify whether the manifest file is related to DRM or not.  
```xml  
» tshark -r catflix.pcapng --export-objects http,files  
» head files/episode_0.mpd

<MPD xmlns="urn:mpeg:dash:schema:mpd:2011" xmlns:xsi="<http://www.w3.org/2001/XMLSchema-instance>" xsi:schemaLocation="urn:mpeg:dash:schema:mpd:2011 DASH-MPD.xsd" xmlns:cenc="urn:mpeg:cenc:2013" profiles="urn:mpeg:dash:profile:isoff-on-demand:2011" minBufferTime="PT2S" type="static" mediaPresentationDuration="PT18.6S">  
<Period id="0">  
<AdaptationSet id="0" contentType="audio" subsegmentStartsWithSAP="1" subsegmentAlignment="true">  
<ContentProtection value="cenc" schemeIdUri="urn:mpeg:dash:mp4protection:2011" cenc:default_KID="e027ea1b-5f08-54ca-9bc7-8c1b6bd27245"/>  
<ContentProtection schemeIdUri="urn:uuid:edef8ba9-79d6-4ace-a3c8-27dcd51d21ed">  
<cenc:pssh>AAAAN3Bzc2gAAAAA7e+LqXnWSs6jyCfc1R0h7QAAABciD1vVaGBtAS9fZJX/djReK0jj3JWbBg==</cenc:pssh>  
</ContentProtection>  
<ContentProtection schemeIdUri="urn:uuid:1077efec-c0b2-4d02-ace3-3c1e52e2fb4b">

<MPD xmlns="urn:mpeg:dash:schema:mpd:2011" xmlns:xsi="<http://www.w3.org/2001/XMLSchema-instance>" xsi:schemaLocation="urn:mpeg:dash:schema:mpd:2011 DASH-MPD.xsd" xmlns:cenc="urn:mpeg:cenc:2013" profiles="urn:mpeg:dash:profile:isoff-on-demand:2011" minBufferTime="PT2S" type="static" mediaPresentationDuration="PT18.6S">  
<Period id="0">  
<AdaptationSet id="0" contentType="audio" subsegmentStartsWithSAP="1" subsegmentAlignment="true">  
<ContentProtection value="cenc" schemeIdUri="urn:mpeg:dash:mp4protection:2011" cenc:default_KID="e027ea1b-5f08-54ca-9bc7-8c1b6bd27245"/>  
<ContentProtection schemeIdUri="urn:uuid:edef8ba9-79d6-4ace-a3c8-27dcd51d21ed">  
<cenc:pssh>AAAAN3Bzc2gAAAAA7e+LqXnWSs6jyCfc1R0h7QAAABciD1vVaGBtAS9fZJX/djReK0jj3JWbBg==</cenc:pssh>  
</ContentProtection>  
<ContentProtection schemeIdUri="urn:uuid:1077efec-c0b2-4d02-ace3-3c1e52e2fb4b">  
```

Based on these findings, we know that each episode needs to be decrypted with a decryption key in the form of KID:DRM-KEY. The KID can be found inside the MPD manifest file, while the DRM key is supposed to be confidential. Fortunately, there are a few license servers that can fetch these DRM keys. In this case, we used [CDRM Project](<https://cdrm-project.com/api>), which is specifically designed for fetching Shaka DRM keys. Here's our full implementation code:

```py  
from binascii import unhexlify  
from pyshark import FileCapture

import os  
import re  
import requests

keys = list()  
paths = dict()  
packets = FileCapture(  
'catflix.pcapng',  
use_json=True,  
include_raw=True  
)

def get_decryption_key(pssh, keyid):  
body = {  
'PSSH': pssh.decode(),  
'License URL': '<https://cwip-shaka-proxy.appspot.com/no_auth'>,  
'Headers': "{'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0'}",  
'JSON': "{}",  
"Cookies": "{}",  
'Data': "{}",  
'Proxy': ""  
}

resp = [requests.post](http://requests.post)('<https://cdrm-project.com/'>, json=body)  
drm_keys = resp.json()['Message']  
keyid = keyid.replace(b'-', b'').decode()

for key in drm_keys.split('\n'):  
if keyid in key:  
return key

for pkt in packets:  
try:  
http = pkt.http

if 'video.mp4' in http.response_for.uri:  
target = http.uri.split('/')[-1][11:]  
brange = http.content_range.split('-')[0][6:]  
filedata = unhexlify(''.join(http.file_data_raw[0]))   
print(target)

value = paths.get(target, {})  
if not value:  
paths[target] = value  
value[int(brange)] = filedata  
  
elif '.mpd' in http.response_for.uri:  
filedata = unhexlify(''.join(http.file_data_raw[0]))  
pssh = re.findall(rb'pssh>(.+?)
