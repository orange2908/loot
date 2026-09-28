---
title: "MAC OS - keychain (Forensics)"
category: "forensics"
subcategory: "rsa"
type: "technique"
tags: ["my-notes", "personal", "rsa", "base64", "mac", "keychain", "forensics"]
summary: "Personal note: MAC OS - keychain (Forensics)."
source:
  name: "Personal notes"
origin_path: "Forensics/MAC OS - keychain.md"
---

#mac #macos #keychain #kcpassword
# Batman - Gotham's Secret

```
~/Desktop/ctf/Batman-GothamSecret/LiveResponseData/CopiedFiles/a1l4m/etc
❯ python3 decode-kcpassword/decode-kcpassword.py ./kcpassword
a1l894m
```

```bash
~/Desktop/ctf/Batman-GothamSecret
chainbreaker ❯ python3 -m chainbreaker --dump-all --password "a1l894m" ./login.keychain-db
2024-12-28 12:22:11,014 - INFO - Version - 3.0.3
2024-12-28 12:22:11,014 - INFO - Chainbreaker : https://github.com/n0fate/chainbreaker
2024-12-28 12:22:11,014 - INFO - Version: 3.0.3
2024-12-28 12:22:11,014 - INFO - Runtime Command: /home/serioton/Desktop/ctf/Batman-GothamSecret/LiveResponseData/chainbreaker/venv/lib/python3.10/site-packages/chainbreaker-3.0.3-py3.10.egg/chainbreaker/__main__.py --dump-all --password a1l894m ./login.keychain-db
2024-12-28 12:22:11,014 - INFO - Keychain: ./login.keychain-db
2024-12-28 12:22:11,014 - INFO - Keychain MD5: 132841b5c9fd79aa3a99265753c07d7e
2024-12-28 12:22:11,014 - INFO - Keychain 256: fac9bd0dc91dbc60603fdeea2dedfa1d8f5821c4137fcb5330f32b427a30e40f
2024-12-28 12:22:11,014 - INFO - Dump Start: 2024-12-28 12:22:11.014411
2024-12-28 12:22:11,019 - WARNING - [!] Certificate Table is not available
2024-12-28 12:22:11,019 - INFO - 1 Keychain Password Hash
2024-12-28 12:22:11,019 - INFO -        $keychain$*b'0ab14d687034830bd5843261322721111cbe7ca3'*b'118b775e4767c14f'*b'53de03adc36028b99bd454dd46d46e4db0bab52abd228e23d5ee65805180eafe39e9a7fcaa0518f71d4b995d5848ca99'
2024-12-28 12:22:11,019 - INFO -
2024-12-28 12:22:11,019 - INFO - 4 Generic Passwords
2024-12-28 12:22:11,019 - INFO -        [+] Generic Password Record
2024-12-28 12:22:11,019 - INFO -         [-] Create DateTime: 2024-12-17 22:29:35
2024-12-28 12:22:11,019 - INFO -         [-] Last Modified DateTime: 2024-12-17 22:29:35
2024-12-28 12:22:11,019 - INFO -         [-] Description:
2024-12-28 12:22:11,019 - INFO -         [-] Creator: b'aapl'
2024-12-28 12:22:11,019 - INFO -         [-] Type:
2024-12-28 12:22:11,019 - INFO -         [-] Print Name: b'MetadataKeychain'
2024-12-28 12:22:11,019 - INFO -         [-] Alias:
2024-12-28 12:22:11,020 - INFO -         [-] Account: b''
2024-12-28 12:22:11,020 - INFO -         [-] Service: b'MetadataKeychain'
2024-12-28 12:22:11,020 - INFO -         [-] Password: 4&/-]54)_mCMHddc@_Ec
2024-12-28 12:22:11,020 - INFO -
2024-12-28 12:22:11,020 - INFO -
2024-12-28 12:22:11,020 - INFO -        [+] Generic Password Record
2024-12-28 12:22:11,020 - INFO -         [-] Create DateTime: 2024-12-17 22:31:35
2024-12-28 12:22:11,020 - INFO -         [-] Last Modified DateTime: 2024-12-17 22:31:35
2024-12-28 12:22:11,020 - INFO -         [-] Description: b'secure note\x00not'
2024-12-28 12:22:11,020 - INFO -         [-] Creator:
2024-12-28 12:22:11,020 - INFO -         [-] Type: b'note'
2024-12-28 12:22:11,020 - INFO -         [-] Print Name: b'Secure Note'
2024-12-28 12:22:11,020 - INFO -         [-] Alias:
2024-12-28 12:22:11,020 - INFO -         [-] Account: b''
2024-12-28 12:22:11,020 - INFO -         [-] Service: b'Secure Note\x00\x00\x00\x01'
2024-12-28 12:22:11,020 - INFO -         [-] Password: <?xml version="1.0" encoding="UTF-8"?>
2024-12-28 12:22:11,020 - INFO -        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
2024-12-28 12:22:11,020 - INFO -        <plist version="1.0">
2024-12-28 12:22:11,020 - INFO -        <dict>
2024-12-28 12:22:11,020 - INFO -                <key>NOTE</key>
2024-12-28 12:22:11,020 - INFO -                <string>0xL4ugh{4ut0l0g1n5_4nd_k3ych41n5_54y_brrrrrr}</string>
2024-12-28 12:22:11,020 - INFO -                <key>RTFD</key>
2024-12-28 12:22:11,020 - INFO -                <data>
2024-12-28 12:22:11,020 - INFO -                cnRmZAAAAAADAAAAAgAAAAcAAABUWFQucnRmAQAAAC6qAQAAKwAAAAEAAACiAQAAe1xy
2024-12-28 12:22:11,020 - INFO -                dGYxXGFuc2lcYW5zaWNwZzEyNTJcY29jb2FydGYyNTgwClxjb2NvYXRleHRzY2FsaW5n
2024-12-28 12:22:11,020 - INFO -                MFxjb2NvYXBsYXRmb3JtMHtcZm9udHRibFxmMFxmbmlsXGZjaGFyc2V0MCBIZWx2ZXRp
2024-12-28 12:22:11,020 - INFO -                Y2FOZXVlLUxpZ2h0O30Ke1xjb2xvcnRibDtccmVkMjU1XGdyZWVuMjU1XGJsdWUyNTU7
2024-12-28 12:22:11,021 - INFO -                XHJlZDBcZ3JlZW4wXGJsdWUwO30Ke1wqXGV4cGFuZGVkY29sb3J0Ymw7O1xjc3NyZ2Jc
2024-12-28 12:22:11,021 - INFO -                YzBcYzBcYzBcY25hbWUgdGV4dENvbG9yO30KXHBhcmRcdHg1NjBcdHgxMTIwXHR4MTY4
2024-12-28 12:22:11,021 - INFO -                MFx0eDIyNDBcdHgyODAwXHR4MzM2MFx0eDM5MjBcdHg0NDgwXHR4NTA0MFx0eDU2MDBc
2024-12-28 12:22:11,021 - INFO -                dHg2MTYwXHR4NjcyMFxwYXJkaXJuYXR1cmFsXHBhcnRpZ2h0ZW5mYWN0b3IwCgpcZjBc
2024-12-28 12:22:11,021 - INFO -                ZnMyNiBcY2YyIDB4TDR1Z2hcezR1dDBsMGcxbjVfNG5kX2szeWNoNDFuNV81NHlfYnJy
2024-12-28 12:22:11,021 - INFO -                cnJyclx9fQEAAAAjAAAAAQAAAAcAAABUWFQucnRmEAAAAMf7YWe2AQAAAAAAAAAAAAA=
2024-12-28 12:22:11,021 - INFO -                </data>
2024-12-28 12:22:11,021 - INFO -        </dict>
2024-12-28 12:22:11,021 - INFO -        </plist>
2024-12-28 12:22:11,021 - INFO -
2024-12-28 12:22:11,021 - INFO -
2024-12-28 12:22:11,021 - INFO -
2024-12-28 12:22:11,021 - INFO -        [+] Generic Password Record
2024-12-28 12:22:11,021 - INFO -         [-] Create DateTime: 2024-12-17 22:33:58
2024-12-28 12:22:11,021 - INFO -         [-] Last Modified DateTime: 2024-12-17 22:33:58
2024-12-28 12:22:11,021 - INFO -         [-] Description:
2024-12-28 12:22:11,021 - INFO -         [-] Creator: b'aapl'
2024-12-28 12:22:11,021 - INFO -         [-] Type:
2024-12-28 12:22:11,021 - INFO -         [-] Print Name: b'com.apple.scopedbookmarksagent.xpc'
2024-12-28 12:22:11,021 - INFO -         [-] Alias:
2024-12-28 12:22:11,021 - INFO -         [-] Account: b'com.apple.scopedbookmarksagent.xpc'
2024-12-28 12:22:11,022 - INFO -         [-] Service: b'com.apple.scopedbookmarksagent.xpc'
2024-12-28 12:22:11,022 - INFO -         [-] Base64 Encoded Password: b'jQVsgrCdbhSuFWxkqwu7aJ/VSi+OxtLHrjlT0XISbk8='
2024-12-28 12:22:11,022 - INFO -
2024-12-28 12:22:11,022 - INFO -
2024-12-28 12:22:11,022 - INFO -        [+] Generic Password Record
2024-12-28 12:22:11,022 - INFO -         [-] Create DateTime: 2024-12-17 22:29:28
2024-12-28 12:22:11,022 - INFO -         [-] Last Modified DateTime: 2024-12-21 05:11:47
2024-12-28 12:22:11,022 - INFO -         [-] Description:
2024-12-28 12:22:11,022 - INFO -         [-] Creator:
2024-12-28 12:22:11,022 - INFO -         [-] Type:
2024-12-28 12:22:11,022 - INFO -         [-] Print Name: b'Apple Persistent State Encryption'
2024-12-28 12:22:11,022 - INFO -         [-] Alias:
2024-12-28 12:22:11,022 - INFO -         [-] Account: b'Window Bitmap Encryption'
2024-12-28 12:22:11,022 - INFO -         [-] Service: b'Apple Persistent State Encryption'
2024-12-28 12:22:11,022 - INFO -         [-] Password: 44409507CC4C1A1FD798313AA0E9067E
2024-12-28 12:22:11,022 - INFO -
2024-12-28 12:22:11,022 - INFO -
2024-12-28 12:22:11,022 - INFO - 0 Internet Passwords
2024-12-28 12:22:11,022 - INFO - 0 Appleshare Passwords
2024-12-28 12:22:11,022 - INFO - 1 Private Keys
2024-12-28 12:22:11,023 - INFO -        [+] Private Key
2024-12-28 12:22:11,023 - INFO -         [-] Print Name: b'<key>'
2024-12-28 12:22:11,023 - INFO -         [-] Key Class: CSSM_KEYCLASS_PRIVATE_KEY
2024-12-28 12:22:11,023 - INFO -         [-] Key Type: CSSM_ALGID_RSA
2024-12-28 12:22:11,023 - INFO -         [-] Key Size: 2048
2024-12-28 12:22:11,023 - INFO -         [-] Effective Key Size: 2048
2024-12-28 12:22:11,023 - INFO -         [-] CSSM Type: Core CSP (local space)
2024-12-28 12:22:11,023 - INFO -         [-] Base64 Encoded PrivateKey: b'MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDayyrFcBE0OoJXjea40DXPPFRj+R4Uwi5mLaIEjFOlhC7+STNz+wTBY+Dej/rbYXytO53WorI5zawjatFsLe0AwnO46eoBRULsZpASAYKMWOQWRMKVHnnGT9iJa4TV6rWRXW0y9jSL5rkYMRYYU9AbsiM2+Z99O7lgEmDdQzNlRDPKAFQviqtpWIg2gENFNrtwNSHZn5M8CgpFwMWCtgsV0IfylWTN4iT3YDyqm4FpnugXa/ag2p0gFLM1zCil0is4f5ottpYl65Anhq+Si71C2jkogX2bFHBURnrw7UizY3AULiVS9HTmrUYzx934jYw5tgWaBFEKTBoFlAgplkmTAgMBAAECggEBAK1Pa/TzfZ06j47dJ5rTyxv6NPrwFWTqICjuEr25jnS4zSS+RVSkzTKHdFO4B0UJ5uGuLKwdOkJRaf6wGW2wv2Dvpw0dtTAGdimeYJbyvT+BFkORefT3LAzrqKHKGnH8tpCMSfipUBxVyd6g21iv41Rc+koM18oyqfew9yutlKOsOIL5YptVxp5o+i/65H2SyfTfMRGXyLPo5ouLxr0kyz0DRrU3+FO9DqRlttjusthqP+LsWrgXh+T4TgihJNW93SZ5pz1FPhJ8ab8JbuwzlgCE4N3UTDyjEEzftYD5J2MXobpu24T3hSEZyqu9imzXIu4L0JN1MyWK/ovmkkSe8KkCgYEA9iI1vjT/1UAywGsYGVf6eP0UfrqvB/EGrzxXGvdFMqwnvs7xHSVveYU4zAytJqtNj3+GSKMOI3FoB+DBUAGOtScb2VXc5xhaPKDBrRtBUNNgrgwe4EeeepyUq5c0yfToaOo4ioQSGHEaQsFAb5fq0ii/kDcXrQMcx1C+pzalyx8CgYEA45Bly+i39+KaHMlELDFcPJLAWS/AUbdiy1Xvfbvuzy6nSHQsAIy43D+/zAfacV9rOCErWywoKyI4LS8p+bYx//nLUotnCyWZv3JCYQQgfdKibpv3u44tNpRhnCPkWkBDXnU7tCp3+OSI0lBeYckyXh7qKqabosHOKSLEWtze5w0CgYEA4+hRc0qICeJkHCAONIlueFF/hMlAAU6BLgnlbibAgGdAdkIQqThcvF1LdkXWnxPHwbQHl4LEOLVt6r2GwppulfccpmYHIkU+aR1BuRSfqkPQJdk7TdmDOW17jFd6nfaUrXET4c7hIpi4BFAFZk95NBhfKR6aYa2cHEL8BsFnS2kCgYBdNdw8dYpFQtAVUmtWHrHFLecToPeJgTA6UWzTd5MN0fI7Pzp2zy05KfOJwv26ynbEevGjWqbpZA7WkycCXZqFWu/pU6hVbIVZYZfG3UXhw9E8tS336PikDoscxabXQNNXcXWPCoYxsIpKexjtvNegrdEEv1GojPHA77i17xpuUQKBgQC+9TjqcqKHfDn2DHucu0rSIHO+bu106CN7d4OAGQrn8FYtx0/2rf/gtCwzXFxaXl2/ypgzOr4BtkRbn3UUWPi6gSD+8QFZk4R3mxMyA6hNes4HGyTjIUMxcKtcK9lbKUVWnUYckdaX148TS5Z2GgZy351qrPq7pHWCs0FJfi6aGA=='
2024-12-28 12:22:11,023 - INFO -
2024-12-28 12:22:11,023 - INFO -
2024-12-28 12:22:11,023 - INFO - 1 Public Keys
2024-12-28 12:22:11,023 - INFO -        [+] Public Key
2024-12-28 12:22:11,023 - INFO -         [-] Print Name: b'<key>'
2024-12-28 12:22:11,023 - INFO -         [-] Key Class: CSSM_KEYCLASS_PUBLIC_KEY
2024-12-28 12:22:11,023 - INFO -         [-] Private: 0
2024-12-28 12:22:11,023 - INFO -         [-] Key Type: CSSM_ALGID_RSA
2024-12-28 12:22:11,023 - INFO -         [-] Key Size: 2048
2024-12-28 12:22:11,023 - INFO -         [-] Effective Key Size: 2048
2024-12-28 12:22:11,023 - INFO -         [-] Extracted: 1
2024-12-28 12:22:11,023 - INFO -         [-] CSSM Type: Core CSP (local space)
2024-12-28 12:22:11,023 - INFO -         [-] Base64 Encoded Public Key: b'MIIBCgKCAQEA2ssqxXARNDqCV43muNA1zzxUY/keFMIuZi2iBIxTpYQu/kkzc/sEwWPg3o/622F8rTud1qKyOc2sI2rRbC3tAMJzuOnqAUVC7GaQEgGCjFjkFkTClR55xk/YiWuE1eq1kV1tMvY0i+a5GDEWGFPQG7IjNvmffTu5YBJg3UMzZUQzygBUL4qraViINoBDRTa7cDUh2Z+TPAoKRcDFgrYLFdCH8pVkzeIk92A8qpuBaZ7oF2v2oNqdIBSzNcwopdIrOH+aLbaWJeuQJ4avkou9Qto5KIF9mxRwVEZ68O1Is2NwFC4lUvR05q1GM8fd+I2MObYFmgRRCkwaBZQIKZZJkwIDAQAB'
2024-12-28 12:22:11,023 - INFO -
2024-12-28 12:22:11,023 - INFO -
2024-12-28 12:22:11,023 - INFO - 0 x509 Certificates
2024-12-28 12:22:11,023 - INFO - Chainbreaker : https://github.com/n0fate/chainbreaker
2024-12-28 12:22:11,023 - INFO - Version: 3.0.3
2024-12-28 12:22:11,023 - INFO - Runtime Command: /home/serioton/Desktop/ctf/Batman-GothamSecret/LiveResponseData/chainbreaker/venv/lib/python3.10/site-packages/chainbreaker-3.0.3-py3.10.egg/chainbreaker/__main__.py --dump-all --password a1l894m ./login.keychain-db
2024-12-28 12:22:11,023 - INFO - Keychain: ./login.keychain-db
2024-12-28 12:22:11,023 - INFO - Keychain MD5: 132841b5c9fd79aa3a99265753c07d7e
2024-12-28 12:22:11,023 - INFO - Keychain 256: fac9bd0dc91dbc60603fdeea2dedfa1d8f5821c4137fcb5330f32b427a30e40f
2024-12-28 12:22:11,023 - INFO - Dump Start: 2024-12-28 12:22:11.014411
2024-12-28 12:22:11,023 - INFO -        1 Keychain Password Hash
2024-12-28 12:22:11,024 - INFO -        4 Generic Passwords
2024-12-28 12:22:11,024 - INFO -        0 Internet Passwords
2024-12-28 12:22:11,024 - INFO -        0 Appleshare Passwords
2024-12-28 12:22:11,024 - INFO -        1 Private Keys
2024-12-28 12:22:11,024 - INFO -        1 Public Keys
2024-12-28 12:22:11,024 - INFO -        0 x509 Certificates
2024-12-28 12:22:11,024 - INFO - Dump End: 2024-12-28 12:22:11.023855
```

---

*From your own notes: `Forensics/MAC OS - keychain.md`*
