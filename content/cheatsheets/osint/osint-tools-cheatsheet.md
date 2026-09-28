---
title: "OSINT Tools and Sites Cheatsheet"
category: osint
subcategory: tools
type: cheatsheet
tags: [osint, sherlock, maigret, holehe, theharvester, amass, subfinder, crt-sh, wayback, shodan, censys, exiftool, gitleaks, trufflehog, openstreetmap, tineye, flightradar24, marinetraffic, google-dorks, cheatsheet]
summary: "Categorised OSINT tools and sites with the exact command or URL pattern for each."
tools: [sherlock, maigret, holehe, theharvester, amass, subfinder, dnsx, httpx, exiftool, gitleaks, trufflehog, whois, dig, curl, jq]
related: [osint-methodology, osint-people-pivoting, osint-geolocation, osint-infrastructure, osint-social-and-archives, osint-documents-and-code]
---

## Install

```bash
# most of the CLI tools, on debian/ubuntu
sudo apt install -y whois dnsutils curl jq exiftool ripgrep

# python tools
pipx install sherlock-project
pipx install maigret
pipx install holehe
pipx install theHarvester
pipx install phoneinfoga            # or use the released binary
pip install mmh3 requests

# go tools (projectdiscovery and friends)
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/owasp-amass/amass/v4/...@master

# secret scanners
brew install gitleaks trufflehog     # or download the release binaries
```

## Usernames and people

```bash
# sherlock: one username against hundreds of sites
sherlock exampleuser
sherlock exampleuser --print-found --timeout 10
sherlock user1 user2 --output-folder ./out
sherlock exampleuser --site GitHub --site Reddit

# maigret: bigger site list, extracts profile data, exports reports
maigret exampleuser
maigret exampleuser --html --pdf
maigret exampleuser -a                     # include the slow/unreliable sites
maigret --submit https://newsite.example/  # teach it a new site

# whatsmyname: the community data set behind several tools
# https://whatsmyname.app/    (web UI, takes a username)

# manual profile URLs worth checking by hand
https://github.com/USERNAME
https://gitlab.com/USERNAME
https://codeberg.org/USERNAME
https://www.reddit.com/user/USERNAME
https://news.ycombinator.com/user?id=USERNAME
https://keybase.io/USERNAME
https://medium.com/@USERNAME
https://dev.to/USERNAME
https://pypi.org/user/USERNAME/
https://www.npmjs.com/~USERNAME
https://hub.docker.com/u/USERNAME
https://ctftime.org/user/USERNAME
https://tryhackme.com/p/USERNAME
https://pastebin.com/u/USERNAME
https://www.twitch.tv/USERNAME
https://www.youtube.com/@USERNAME
https://mastodon.social/@USERNAME
```

## Email

```bash
# holehe: which services have an account for this address
holehe user@example.com
holehe --only-used user@example.com
holehe --no-color --no-clear user@example.com

# epieos (web): linked Google services and other public signals for an address
# https://epieos.com/

# gravatar: unsalted md5 of the trimmed, lowercased address
python3 -c "import hashlib;e='user@example.com';h=hashlib.md5(e.strip().lower().encode()).hexdigest();print(f'https://www.gravatar.com/avatar/{h}?s=256&d=404');print(f'https://www.gravatar.com/{h}.json')"

# theHarvester: emails, hosts and names for a domain from many sources
theHarvester -d example.com -b all
theHarvester -d example.com -b crtsh,bing,duckduckgo -l 500
theHarvester -d example.com -b hackertarget -f out.html

# commit emails from a repository
git log --format='%ae %an' | sort -u
curl -s https://github.com/owner/repo/commit/SHA.patch | grep '^From:'
curl -s https://api.github.com/users/USERNAME/events/public | jq -r '..|.email?|select(.)' | sort -u

# verify an address format passively (never send mail)
dig +short MX example.com
dig +short TXT example.com | grep -i spf
```

## Domains, DNS and whois

```bash
whois example.com
whois -h whois.iana.org example.com
whois 93.184.216.34
whois -h whois.cymru.com " -v 93.184.216.34"          # ASN, netblock, country
curl -s https://rdap.org/domain/example.com | jq .
curl -s https://rdap.org/ip/93.184.216.34 | jq .

for t in A AAAA MX NS SOA TXT CAA SRV; do echo "== $t"; dig +short "$t" example.com; done
dig +trace example.com
dig -x 93.184.216.34 +short
dig +short TXT _dmarc.example.com
dig AXFR example.com @ns1.example.com
dig +short nonexistent-host-check.example.com          # non-empty = wildcard DNS

# bulk resolution and probing
dnsx -l names.txt -a -resp -silent
httpx -l names.txt -title -tech-detect -status-code -silent
```

## Certificate transparency

```bash
# crt.sh JSON, all subdomains ever certificated
curl -s 'https://crt.sh/?q=%25.example.com&output=json' | jq -r '.[].name_value' | \
  tr '\\n' '\n' | sed 's/^\*\.//' | sort -u

# by organisation name
curl -s 'https://crt.sh/?O=Example+Inc&output=json' | jq -r '.[].name_value' | sort -u

# one certificate by id
curl -s 'https://crt.sh/?id=123456789&output=json' | jq .

# the live certificate's SAN list
echo | openssl s_client -connect example.com:443 -servername example.com 2>/dev/null | \
  openssl x509 -noout -text | grep -A2 'Subject Alternative Name'

# web UIs
# https://crt.sh/            certificate transparency search
# https://search.censys.io/  certificates, hosts, and their histories (free account)
```

## Subdomain enumeration

```bash
subfinder -d example.com -all -silent
subfinder -dL domains.txt -o subs.txt
amass enum -passive -d example.com
amass intel -d example.com -whois
assetfinder --subs-only example.com
curl -s "https://api.hackertarget.com/hostsearch/?q=example.com"

# permutations and brute force
dnsgen subs.txt | dnsx -silent
dnsx -d example.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -silent
ffuf -u https://FUZZ.example.com -w wordlist.txt -mc all -fs 0
```

## IP, ASN and ports

```bash
# shodan (free account, API key in ~/.config/shodan)
shodan init YOUR_KEY
shodan host 93.184.216.34
shodan search 'org:"Example Inc"'
shodan search 'ssl.cert.subject.CN:"example.com"'
shodan search 'http.favicon.hash:-247388890'
shodan domain example.com

# favicon hash for the search above
python3 -c "
import base64,urllib.request,mmh3
d=urllib.request.urlopen('https://example.com/favicon.ico').read()
print(mmh3.hash(base64.encodebytes(d)))"

# censys (free account)
# https://search.censys.io/search?resource=hosts&q=services.tls.certificates.leaf_data.subject.common_name%3A%22example.com%22

# passive port/banner alternatives
curl -s "https://api.hackertarget.com/reverseiplookup/?q=93.184.216.34"
curl -sI https://example.com | tee headers.txt
```

## Archives and history

```bash
# every archived URL for a host (CDX API)
curl -s 'https://web.archive.org/cdx/search/cdx?url=example.com*&output=json&fl=original,timestamp,statuscode&collapse=urlkey&limit=5000'

# only the snapshots where the content changed
curl -s 'https://web.archive.org/cdx/search/cdx?url=example.com/page&output=json&fl=timestamp,digest&collapse=digest'

# the closest snapshot to a date
curl -s 'https://archive.org/wayback/available?url=example.com&timestamp=20210101' | jq .

# the ORIGINAL bytes of a snapshot (no archive rewriting) - note the id_ suffix
curl -s 'https://web.archive.org/web/20210601000000id_/https://example.com/'

# wrappers
waybackurls example.com
gau example.com --threads 5

# archive.today: renders and saves on request, often has what the IA does not
# https://archive.ph/newest/https://example.com/page
```

## Images, reverse search and geolocation

```bash
# metadata first
exiftool -a -u -g1 photo.jpg
exiftool -n -GPSLatitude -GPSLongitude photo.jpg
exiftool -b -ThumbnailImage photo.jpg > thumb.jpg      # may be uncropped
exiftool -Make -Model -Software -DateTimeOriginal -OffsetTimeOriginal photo.jpg

# open coordinates
https://www.openstreetmap.org/?mlat=LAT&mlon=LON#map=18/LAT/LON
https://www.google.com/maps/search/?api=1&query=LAT,LON
https://www.bing.com/maps?cp=LAT~LON&lvl=18

# reverse image search (run several; their indexes differ a lot)
https://images.google.com/                 Google Images / Lens
https://yandex.com/images/                 strongest for faces and buildings
https://www.bing.com/visualsearch          Bing Visual Search
https://tineye.com/                        exact copies, crops, first appearance

# maps and imagery
https://www.openstreetmap.org/             base map, searchable by feature
https://overpass-turbo.eu/                 query OSM by tag
https://www.mapillary.com/                 crowd-sourced street-level imagery
https://kartaview.org/                     another street-level source
https://www.google.com/earth/              historical satellite imagery
https://www.suncalc.org/                   sun position for a place, date and time
```

## Social platforms

```bash
# Discord snowflake -> UTC creation time (epoch 1420070400000)
python3 -c "import datetime;i=int(input('id: '));print(datetime.datetime.fromtimestamp(((i>>22)+1420070400000)/1000, datetime.UTC))"

# Twitter/X snowflake -> UTC (epoch 1288834974657); only for ids > ~2.97e10
python3 -c "import datetime;i=int(input('id: '));print(datetime.datetime.fromtimestamp(((i>>22)+1288834974657)/1000, datetime.UTC))"

# a discord message link gives you three snowflakes at once
# https://discord.com/channels/<guild>/<channel>/<message>

# GitHub account metadata (creation date, name, blog, company, location)
curl -s https://api.github.com/users/USERNAME | jq '{login,name,company,blog,location,email,created_at,public_repos}'
curl -s https://api.github.com/users/USERNAME/repos | jq -r '.[].full_name'
curl -s https://api.github.com/users/USERNAME/gists | jq -r '.[].html_url'

# Reddit user posts as JSON, no account needed
curl -s -H 'User-Agent: ctf/1.0' https://www.reddit.com/user/USERNAME/about.json | jq .
curl -s -H 'User-Agent: ctf/1.0' https://www.reddit.com/user/USERNAME.json | jq -r '.data.children[].data.created_utc'

# Mastodon instance-level lookup
curl -s 'https://mastodon.social/api/v1/accounts/lookup?acct=USERNAME' | jq .
```

## Documents and metadata

```bash
exiftool -a -u -g1 file.pdf
exiftool -a -u -g1 file.docx
pdfinfo file.pdf
pdftotext -layout file.pdf - | head -60          # recovers "redacted" text
pdfimages -list file.pdf
qpdf --qdf --object-streams=disable file.pdf out.pdf
grep -aoba '%%EOF' file.pdf                      # >1 = incremental updates

unzip -l file.docx
unzip -p file.docx docProps/core.xml             # dc:creator, cp:lastModifiedBy
unzip -p file.docx docProps/app.xml              # Application, Company, TotalTime
unzip -p file.docx word/_rels/document.xml.rels  # hyperlinks, file:// paths
unzip -p book.xlsx xl/workbook.xml | grep -o 'state="[^"]*"'
unzip -p book.xlsx xl/sharedStrings.xml | head -c 3000

olemeta file.doc
oleid file.doc
olevba file.doc

# metagoofil-style: find documents for a domain, then read their metadata
# (search for filetype:pdf site:example.com, download, then run exiftool)
```

## Code and secrets

```bash
gitleaks detect --source . --report-format json --report-path leaks.json
gitleaks detect --source . --log-opts='--all'
trufflehog git file://. --json
trufflehog github --org=exampleorg --json

git clone --mirror https://github.com/owner/repo
git log -p --all -S 'AKIA'
git log -p --all -G 'BEGIN .*PRIVATE KEY'
git log --all --diff-filter=D --name-only
git fsck --full --unreachable --dangling
git log --format='%ae %an' | sort -u

# github code search qualifiers (use in the web UI)
org:exampleorg "AKIA"
org:exampleorg filename:.env
org:exampleorg extension:pem
org:exampleorg path:.github/workflows "secrets."
user:someone filename:id_rsa
org:exampleorg "BEGIN RSA PRIVATE KEY"

# package registries
npm view express
curl -s https://registry.npmjs.org/express | jq '.maintainers, .repository'
curl -s https://pypi.org/pypi/requests/json | jq '.info.author_email, .info.project_urls'
docker history --no-trunc image:tag

# source maps rebuild a bundled front end
curl -s https://example.com/static/app.js.map | jq -r '.sources[]' | head -30
```

## Phone numbers

```bash
phoneinfoga scan -n "+33612345678"
phoneinfoga serve -p 8080          # local web UI
# manual: the country calling code plus the national number length and prefix
# identify the country and often the carrier or region
```

## Transport trackers

```text
https://www.flightradar24.com/          live and historical flights, by registration or flight no.
https://flightaware.com/                flight history and airport activity
https://www.adsbexchange.com/           unfiltered ADS-B data, including blocked aircraft
https://www.marinetraffic.com/          ships by name, MMSI or IMO
https://www.vesselfinder.com/           another AIS aggregator
https://www.openrailwaymap.org/         railway infrastructure on an OSM base map
https://wigle.net/                      wardriving database: BSSID/SSID to a location
```

## Search operators

```text
"exact phrase"                  quotes force an exact match - use them
-exclude                        remove a term
site:example.com                restrict to a host or a TLD
inurl:admin                     the term appears in the URL
intitle:"index of"              the term appears in the page title
intext:"internal use only"      the term appears in the body
filetype:pdf   ext:xlsx         restrict by file extension
cache:example.com               the engine's cached copy (availability varies)
related:example.com             similar sites
before:2021-01-01 after:2020-01-01    date range (Google)
AROUND(5)                       terms within N words of each other (Google)
*                               wildcard inside a quoted phrase

# high-yield combinations
site:example.com filetype:pdf
site:example.com inurl:admin
site:example.com intitle:"index of"
site:example.com ext:log | ext:txt | ext:conf | ext:cnf | ext:ini | ext:env
site:pastebin.com "example.com"
site:github.com "example.com" password
"@example.com" -site:example.com
intitle:"index of" "backup"
```

Run the same query on more than one engine - Google, Bing, DuckDuckGo, Yandex and Mojeek index
different subsets of the small, recent pages that CTF artifacts live on.

## Sanity rules

```text
- Passive only: never message, friend, call or email anyone.
- Never log in to an account that is not yours.
- Do not use breach or paid-broker data; no good challenge needs it.
- Verify every fact with two independent sources before submitting.
- Respect rate limits and the event's scope; enumeration is not permission to attack.
- Redact real personal data in your writeup.
```
