---
title: "Email Forensics - Headers, Received Chains, Attachments and .eml/.msg/.pst"
category: forensics
subcategory: email
type: technique
tags: [email, eml, msg, pst, ost, mbox, rfc822, received-header, spf, dkim, dmarc, message-id, mime, base64, quoted-printable, readpst, extract-msg, libpff, phishing, dfir]
difficulty: easy
summary: "Read a Received chain bottom-up, spot a spoofed sender, and get every attachment out of .eml, .msg, .pst or .mbox."
when_to_use:
  - "The challenge ships a .eml / .msg / .pst / .ost / .mbox and asks who really sent it"
  - "You need the originating IP, the attachment, or a URL from a phishing mail"
  - "SPF/DKIM/DMARC results decide whether the mail is genuine"
  - "An exported mailbox must be searched for a keyword"
tools: [python3, readpst, extract-msg, msgconvert, libpff, ripmime, exiftool, oletools, dkimpy]
related: [docs-office-macros, docs-pdf-analysis, network-extract-files-creds, logs-analysis]
---

## TL;DR

Read `Received:` headers **bottom-up**: the lowest one is the first hop, the topmost is the last.
Compare `From:` against `Return-Path:` and `Authentication-Results:`. Then walk the MIME tree and
write every `Content-Disposition: attachment` part to disk before touching anything else.

## Header anatomy

```
Return-Path: <bounce@mailer.example>           <- envelope sender (MAIL FROM), set by the last MTA
Delivered-To: victim@corp.example
Received: from mx2.corp.example (...)          <- LAST hop  (read these BOTTOM-UP)
        by imap.corp.example with LMTP id ...; Mon, 15 Jan 2024 09:12:04 +0000
Received: from mailer.example ([203.0.113.9])
        by mx2.corp.example with ESMTPS id ...; Mon, 15 Jan 2024 09:12:01 +0000
Received: from workstation ([198.51.100.77])   <- FIRST hop: often the real origin
        by mailer.example with ESMTPA id ...;  Mon, 15 Jan 2024 09:11:58 +0000
Authentication-Results: mx2.corp.example;
        spf=pass smtp.mailfrom=mailer.example;
        dkim=fail header.d=bank.example;
        dmarc=fail header.from=bank.example
DKIM-Signature: v=1; a=rsa-sha256; d=bank.example; s=selector1;
        h=from:to:subject:date; bh=...; b=...
From: "Bank Security" <security@bank.example>  <- what the user sees; trivially forged
Reply-To: attacker@evil.example                <- where replies actually go
To: victim@corp.example
Subject: Urgent: verify your account
Date: Mon, 15 Jan 2024 09:11:55 +0000
Message-ID: <20240115091155.ABCD@mailer.example>
X-Originating-IP: [198.51.100.77]
X-Mailer: Microsoft Outlook 16.0
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="_004_ABCD_"
```

| Header | What it tells you |
| --- | --- |
| `Received` (bottom-up) | The delivery path. Each MTA prepends one. |
| `Return-Path` / `Envelope-From` | The SMTP `MAIL FROM`. Bounces go here. |
| `From` | Display header. Not authenticated by SMTP at all. |
| `Reply-To` | Where a reply goes. A divergence from `From` is a phishing tell. |
| `Message-ID` | Usually contains the generating server's domain. |
| `Date` | Sender-supplied; compare against the first `Received` timestamp. |
| `Authentication-Results` | The receiving MTA's SPF/DKIM/DMARC verdict. |
| `DKIM-Signature` | `d=` signing domain, `s=` selector, `h=` signed headers, `bh=` body hash. |
| `ARC-Seal` / `ARC-Message-Signature` | Forwarding chain of custody. |
| `X-Originating-IP`, `X-Sender-IP` | Client IP, when the provider adds it. |
| `X-Mailer`, `User-Agent` | The composing client; mismatched with the claimed sender is a tell. |
| `X-MS-Exchange-*`, `X-Forefront-*` | Microsoft 365 scoring, spam confidence level (SCL/BCL). |
| `Content-Type` + `boundary` | Where the MIME parts start. |
| `Content-Transfer-Encoding` | `base64`, `quoted-printable`, `7bit`, `8bit`. |

## Spoofing checklist

- `From:` domain != `Return-Path:` domain, with no legitimate mailing-list reason.
- `Reply-To:` points somewhere unrelated to `From:`.
- `Authentication-Results:` says `spf=fail`, `dkim=fail` or `dmarc=fail`.
- `DKIM-Signature d=` is not the `From:` domain (that is exactly what DMARC alignment checks).
- The `Received` chain has a gap, a jump backwards in time, or a first hop whose claimed
  hostname does not resolve to the bracketed IP.
- Timezone in `Date:` does not match the sender's claimed location or the first `Received`.
- `Message-ID` domain differs from the sending infrastructure.
- Homoglyph / lookalike domain (`rn` standing in for `m`, a Cyrillic a in place of an
  ASCII a, `bank-example.com` instead of `bank.example`).
- Display name contains a full email address different from the real one.
- `X-Mailer` claims Outlook but the MIME structure is clearly PHP `mail()` or a script.

```sh
# quick header dump
formail -X '' < mail.eml | head -60
sed -n '1,/^$/p' mail.eml
# the received chain, first hop last
grep -i '^Received:' -A2 mail.eml
# the three verdicts
grep -iE '^(Authentication-Results|Received-SPF|DKIM-Signature|ARC-Authentication-Results):' -A3 mail.eml
# every IP mentioned in the headers
sed -n '1,/^$/p' mail.eml | grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' | sort -u
# verify a DKIM signature offline (needs the public key, so usually online-only)
pip install dkimpy && dkimverify < mail.eml
```

## Formats and how to open them

| Extension | Container | Tool |
| --- | --- | --- |
| `.eml` | RFC 5322 plain text | `python3 -m email`, any text editor |
| `.msg` | OLE2 compound file | `extract_msg`, `msgconvert`, `oledump.py` |
| `.pst` / `.ost` | Outlook personal store | `readpst`, `pffexport` |
| `.mbox` | concatenated messages, `From ` separator lines | `python3 mailbox`, `formail` |
| Maildir | one file per message in `cur/`, `new/`, `tmp/` | just read the files |
| `.emlx` | Apple Mail: length line + RFC822 + plist | strip the first line |
| `.nsf` | Lotus Notes | `readnsf` / commercial tools |

```sh
# .msg -> .eml
pip install extract-msg
extract_msg --out ./out mail.msg          # writes message.txt + attachments
python3 -m extract_msg --json mail.msg
msgconvert mail.msg                       # perl, produces mail.eml alongside
# .msg is OLE2: you can also read its streams directly
oledump.py mail.msg
oledump.py -s 3 -S mail.msg               # __substg1.0_* streams hold the fields
# .pst / .ost
readpst -S -D -o ./out mail.pst           # -S one file per message, -D include deleted
readpst -r -o ./out mail.pst              # recursive mbox output preserving folders
readpst -m -o ./out mail.pst              # MH format
pffexport -f text -t ./out mail.pst       # libpff, handles OST too
pffinfo mail.pst
# .mbox -> individual messages
python3 - <<'PY'
import mailbox, pathlib
box = mailbox.mbox("inbox.mbox")
out = pathlib.Path("messages"); out.mkdir(exist_ok=True)
for i, msg in enumerate(box):
    (out / f"msg{i:05d}.eml").write_bytes(msg.as_bytes())
print(len(box), "messages")
PY
# ripmime: fast attachment extraction, no python
ripmime -i mail.eml -d ./attachments --name-by-type
# munpack (mpack package)
munpack -f mail.eml
```

## Attachments

```sh
# extract, then identify, then hash, then analyse - in that order
ripmime -i mail.eml -d ./att
file ./att/*
sha256sum ./att/*
# office documents
oleid ./att/invoice.doc && olevba --decode --deobf ./att/invoice.doc
# pdfs
pdfid.py ./att/statement.pdf
# archives: list before extracting
7z l ./att/archive.zip
unzip -l ./att/archive.zip
# an .iso / .img / .vhd attachment is a mark-of-the-web bypass
7z x ./att/setup.iso -o./iso
# decode a base64 part by hand if the tooling fails
awk '/^Content-Transfer-Encoding: base64/{f=1} f&&/^$/{g=1;next} g' mail.eml | base64 -d > part.bin
# quoted-printable
python3 -c "import quopri,sys;sys.stdout.buffer.write(quopri.decodestring(open('part.txt','rb').read()))"
# metadata of the attachment itself
exiftool -a -u -g1 ./att/*
```

## URLs and tracking

```sh
# every URL in the body, defanged for safe note-taking
grep -oiE 'https?://[^"'"'"' <>]{6,300}' mail.eml | sort -u | sed 's/\./[.]/g; s|http|hxxp|'
# 1x1 tracking pixels
grep -oiE '<img[^>]*(width="?1"?|height="?1"?)[^>]*>' mail.eml
# href text vs href target mismatch (the classic phishing tell)
python3 - <<'PY'
import email, re, sys, pathlib
msg = email.message_from_bytes(pathlib.Path("mail.eml").read_bytes())
for part in msg.walk():
    if part.get_content_type() == "text/html":
        html = (part.get_payload(decode=True) or b"").decode("utf-8", "replace")
        for m in re.finditer(r'<a\s[^>]*href=["\']([^"\']+)["\'][^>]*>(.*?)</a>',
                             html, re.I | re.S):
            target, text = m.group(1), re.sub(r"<[^>]+>", "", m.group(2)).strip()
            if text.startswith("http") and target.split("/")[2:3] != text.split("/")[2:3]:
                print(f"MISMATCH  text={text!r}  href={target!r}")
PY
```

## Code

```python
#!/usr/bin/env python3
"""Parse an .eml and report the Received chain, sender mismatches and attachments.

Pure stdlib (email, hashlib, pathlib). Writes every attachment to --outdir.

    python3 eml_triage.py phish.eml --outdir attachments
    python3 eml_triage.py phish.eml --no-save
"""
from __future__ import annotations

import argparse
import email
import email.policy
import email.utils
import hashlib
import os
import re
import sys
from datetime import datetime, timezone
from email.message import EmailMessage

IP_RE = re.compile(r"\[?\b((?:\d{1,3}\.){3}\d{1,3})\b\]?")
FROM_HOST_RE = re.compile(r"^\s*from\s+([^\s;(]+)", re.I)
BY_HOST_RE = re.compile(r"\bby\s+([^\s;(]+)", re.I)
PRIVATE = ("10.", "192.168.", "127.", "169.254.", "0.")


def is_private(ip: str) -> bool:
    if ip.startswith(PRIVATE):
        return True
    if ip.startswith("172."):
        try:
            return 16 <= int(ip.split(".")[1]) <= 31
        except (IndexError, ValueError):
            return False
    return False


def parse_received(value: str) -> dict[str, object]:
    ips = [ip for ip in IP_RE.findall(value)]
    frm = FROM_HOST_RE.search(value)
    by = BY_HOST_RE.search(value)
    stamp = None
    if ";" in value:
        try:
            stamp = email.utils.parsedate_to_datetime(value.rsplit(";", 1)[1].strip())
            if stamp.tzinfo is None:
                stamp = stamp.replace(tzinfo=timezone.utc)
        except (TypeError, ValueError, IndexError):
            stamp = None
    return {
        "from": frm.group(1) if frm else "?",
        "by": by.group(1) if by else "?",
        "ips": ips,
        "time": stamp,
        "raw": " ".join(value.split()),
    }


def domain_of(addr: str) -> str:
    _, email_addr = email.utils.parseaddr(addr or "")
    return email_addr.rsplit("@", 1)[-1].lower() if "@" in email_addr else ""


def report_headers(msg: EmailMessage) -> None:
    print("== identity headers")
    for h in ("From", "Return-Path", "Reply-To", "Sender", "To", "Cc", "Subject",
              "Date", "Message-ID", "X-Originating-IP", "X-Sender-IP", "X-Mailer",
              "User-Agent", "X-Priority"):
        val = msg.get(h)
        if val:
            print(f"  {h:<18} {' '.join(str(val).split())}")

    frm = domain_of(str(msg.get("From", "")))
    ret = domain_of(str(msg.get("Return-Path", "")))
    rep = domain_of(str(msg.get("Reply-To", "")))
    mid = str(msg.get("Message-ID", ""))
    mid_dom = mid.rsplit("@", 1)[-1].strip("<> ").lower() if "@" in mid else ""

    print("\n== alignment")
    if frm and ret and frm != ret:
        print(f"  [!] From domain ({frm}) != Return-Path domain ({ret})")
    if rep and frm and rep != frm:
        print(f"  [!] Reply-To domain ({rep}) != From domain ({frm})")
    if mid_dom and frm and not (mid_dom.endswith(frm) or frm.endswith(mid_dom)):
        print(f"  [!] Message-ID domain ({mid_dom}) unrelated to From domain ({frm})")
    if not any((frm and ret and frm != ret, rep and frm and rep != frm)):
        print("  no From/Return-Path/Reply-To mismatch")


def report_auth(msg: EmailMessage) -> None:
    print("\n== authentication")
    found = False
    for h in ("Authentication-Results", "ARC-Authentication-Results", "Received-SPF",
              "DKIM-Signature", "DomainKey-Signature", "X-Forefront-Antispam-Report"):
        for val in msg.get_all(h, []):
            found = True
            flat = " ".join(str(val).split())
            print(f"  {h}: {flat[:300]}")
    if not found:
        print("  no SPF/DKIM/DMARC headers present at all (direct-to-MX delivery?)")
        return
    joined = " ".join(" ".join(str(v).split())
                      for h in ("Authentication-Results", "ARC-Authentication-Results",
                                "Received-SPF")
                      for v in msg.get_all(h, []))
    for mech in ("spf", "dkim", "dmarc", "compauth"):
        m = re.search(rf"\b{mech}=(\w+)", joined, re.I)
        if m:
            verdict = m.group(1).lower()
            flag = "[!] " if verdict in ("fail", "softfail", "none", "permerror",
                                         "temperror") else "    "
            print(f"  {flag}{mech.upper()} = {verdict}")


def report_received(msg: EmailMessage) -> None:
    hops = [parse_received(str(v)) for v in msg.get_all("Received", [])]
    hops.reverse()      # bottom-up: first hop first
    print(f"\n== received chain ({len(hops)} hops, first hop first)")
    prev_time: datetime | None = None
    for i, hop in enumerate(hops, 1):
        stamp = hop["time"]
        when = stamp.astimezone(timezone.utc).isoformat() if isinstance(stamp, datetime) else "?"
        delay = ""
        if isinstance(stamp, datetime) and prev_time is not None:
            secs = (stamp - prev_time).total_seconds()
            delay = f"  (+{secs:.0f}s)" if secs >= 0 else f"  (!! {secs:.0f}s BACKWARDS)"
        if isinstance(stamp, datetime):
            prev_time = stamp
        public = [ip for ip in hop["ips"] if not is_private(ip)]  # type: ignore[union-attr]
        print(f"  {i}. {when}{delay}")
        print(f"     from {hop['from']}  by {hop['by']}")
        if public:
            print(f"     public IPs: {', '.join(public)}")
    if hops:
        first_public = [ip for ip in hops[0]["ips"] if not is_private(ip)]  # type: ignore[union-attr]
        if first_public:
            print(f"\n  originating IP candidate: {first_public[0]}")


def save_attachments(msg: EmailMessage, outdir: str | None) -> None:
    print("\n== mime tree")
    attachments: list[tuple[str, bytes]] = []
    for part in msg.walk():
        ctype = part.get_content_type()
        disp = part.get_content_disposition() or ""
        fname = part.get_filename()
        depth = "  " * (len(part.get("Content-Type", "").split(";")) - 1)
        marker = f"  {ctype:<32} {disp:<12} {fname or ''}"
        print(f"  {depth}{marker.strip()}")
        if disp == "attachment" or (fname and part.get_payload(decode=True)):
            data = part.get_payload(decode=True) or b""
            attachments.append((fname or f"unnamed_{len(attachments)}", data))

    if not attachments:
        print("\n== no attachments")
        return
    print(f"\n== attachments ({len(attachments)})")
    if outdir:
        os.makedirs(outdir, exist_ok=True)
    for name, data in attachments:
        safe = os.path.basename(name).replace("/", "_").replace("\\", "_") or "unnamed"
        digest = hashlib.sha256(data).hexdigest()
        print(f"  {safe}  {len(data)} bytes  sha256:{digest}")
        magic = data[:8].hex()
        print(f"      magic {magic}")
        if outdir:
            path = os.path.join(outdir, safe)
            with open(path, "wb") as fh:
                fh.write(data)
            print(f"      -> {path}")


def report_urls(msg: EmailMessage) -> None:
    urls: set[str] = set()
    url_re = re.compile(rb"https?://[^\s\"'<>)]{6,300}", re.I)
    for part in msg.walk():
        if part.get_content_maintype() == "text":
            body = part.get_payload(decode=True) or b""
            for m in url_re.findall(body):
                urls.add(m.decode("latin-1"))
    if urls:
        print(f"\n== urls ({len(urls)}, defanged)")
        for u in sorted(urls)[:60]:
            print("  " + u.replace("http", "hxxp").replace(".", "[.]"))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("eml")
    ap.add_argument("--outdir", default="attachments")
    ap.add_argument("--no-save", action="store_true", help="do not write attachments")
    args = ap.parse_args()

    try:
        with open(args.eml, "rb") as fh:
            msg = email.message_from_binary_file(fh, policy=email.policy.default)
    except FileNotFoundError:
        print(f"no such file: {args.eml}", file=sys.stderr)
        return 1

    report_headers(msg)          # type: ignore[arg-type]
    report_auth(msg)             # type: ignore[arg-type]
    report_received(msg)         # type: ignore[arg-type]
    save_attachments(msg, None if args.no_save else args.outdir)  # type: ignore[arg-type]
    report_urls(msg)             # type: ignore[arg-type]
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

```python
#!/usr/bin/env python3
"""Split an mbox or Maildir into individual .eml files and index the subjects.

    python3 mbox_split.py inbox.mbox messages/
    python3 mbox_split.py /path/to/Maildir messages/ --maildir
    python3 mbox_split.py inbox.mbox messages/ --grep 'invoice'
"""
from __future__ import annotations

import argparse
import mailbox
import os
import re
import sys


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("source")
    ap.add_argument("outdir", nargs="?", default="messages")
    ap.add_argument("--maildir", action="store_true", help="source is a Maildir, not an mbox")
    ap.add_argument("--grep", help="only keep messages whose raw bytes match this regex")
    args = ap.parse_args()

    if not os.path.exists(args.source):
        print(f"no such path: {args.source}", file=sys.stderr)
        return 1

    try:
        box: mailbox.Mailbox = (mailbox.Maildir(args.source, create=False)
                                if args.maildir else
                                mailbox.mbox(args.source, create=False))
    except (OSError, ValueError) as exc:
        print(f"cannot open mailbox: {exc}", file=sys.stderr)
        return 1

    needle = re.compile(args.grep.encode(), re.I) if args.grep else None
    os.makedirs(args.outdir, exist_ok=True)
    kept = 0
    total = 0
    for key in box.iterkeys():
        try:
            msg = box[key]
        except (KeyError, OSError):
            continue
        total += 1
        raw = msg.as_bytes()
        if needle and not needle.search(raw):
            continue
        kept += 1
        subject = " ".join(str(msg.get("Subject", "(no subject)")).split())[:60]
        sender = str(msg.get("From", "?"))
        date = str(msg.get("Date", "?"))
        path = os.path.join(args.outdir, f"msg{kept:05d}.eml")
        with open(path, "wb") as fh:
            fh.write(raw)
        print(f"{kept:5d}  {date[:31]:<31}  {sender[:40]:<40}  {subject}")
    box.close()
    print(f"\n[+] {kept}/{total} messages written to {args.outdir}/", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

## Variants & pitfalls

- **Received headers can be forged** for every hop *before* the first MTA you trust. Only the hops
  added by infrastructure you control are reliable, and those are the ones nearest the top.
- A missing `Received` chain entirely means the message was **injected directly** into the
  mailstore, or the sample was exported from a client that stripped them.
- `.msg` files store rich-text bodies as compressed RTF in `__substg1.0_10090102`. `extract_msg`
  handles it; raw `strings` will not.
- `readpst` can produce huge output. Use `-S` (one file per message) and `-o` a dedicated dir.
- Base64 attachments split across lines must be joined before decoding -- `base64 -d` tolerates
  newlines but not other whitespace in strict mode.
- **Encoded-word headers** (`=?UTF-8?B?...?=`) hide the real subject and display name. Python's
  `email.policy.default` decodes them automatically; `grep` does not.
- An attachment named `invoice.pdf.exe` will show as `invoice.pdf` in some clients due to RTLO
  (the U+202E right-to-left override) -- grep filenames for that codepoint.
- Timestamps in headers use the sender's timezone. Normalise everything to UTC before building a
  timeline.

## Tools

`python3` (`email`, `mailbox` stdlib), `extract_msg`, `msgconvert`, `readpst`/`libpst`,
`pffexport`/`libpff`, `ripmime`, `munpack`, `formail` (procmail), `exiftool`, `oletools`,
`pdfid`, `dkimpy`, `7z`.

## References

- RFC 5322 (message format), RFC 2045-2049 (MIME), RFC 7208 (SPF), RFC 6376 (DKIM),
  RFC 7489 (DMARC), RFC 8617 (ARC).
- `readpst -h`, `extract_msg --help`, `ripmime -h` for the exact flags.
