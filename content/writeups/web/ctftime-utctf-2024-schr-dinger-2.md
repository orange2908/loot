---
title: "Schrödinger - UTCTF 2024"
category: "web"
type: "writeup"
tags: ["web", "zip", "werkzeug", "symlink", "schr", "dinger", "utctf", "utctf-2024", "2024", "ctf-writeup"]
summary: "![Zimzi's avatar](https://substack.com/@zimzi)"
source:
  name: "CTFtime writeup #38984"
  url: "https://ctftime.org/writeup/38984"
original_source: "https://zimzi.substack.com/p/utctf-2024-schrodinger"
ctf:
  name: "UTCTF 2024"
  year: 2024
  challenge: "Schrödinger"
---

## Metadata

- **CTF:** UTCTF 2024
- **Task:** Schrödinger
- **Author team:** Zimzi
- **CTFtime tags:** zip
- **CTFtime:** <https://ctftime.org/writeup/38984>
- **Original writeup:** <https://zimzi.substack.com/p/utctf-2024-schrodinger>

---
# UTCTF 2024: Schrödinger

[![Zimzi's avatar](https://substackcdn.com/image/fetch/$s_!7J0a!,w_36,h_36,c_fill,f_auto,q_auto:good,fl_progressive:steep/https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2Fba6ea3a0-f2af-45ce-9f5d-82bf420f4890_1024x1024.png)](https://substack.com/@zimzi)

[Zimzi](https://substack.com/@zimzi)

Apr 01, 2024

Share

[![](https://substackcdn.com/image/fetch/$s_!RfEv!,w_1456,c_limit,f_auto,q_auto:good,fl_progressive:steep/https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2Fff6bd37d-38ac-4258-8542-6df387fb7e6a_522x580.png)](https://substackcdn.com/image/fetch/$s_!RfEv!,f_auto,q_auto:good,fl_progressive:steep/https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2Fff6bd37d-38ac-4258-8542-6df387fb7e6a_522x580.png)

Thanks for reading Zimzi’s Substack! Subscribe for free to receive new posts and support my work.

It seems we need to find a cat!

The task includes a link to the below webpage:

[![](https://substackcdn.com/image/fetch/$s_!AQcz!,w_1456,c_limit,f_auto,q_auto:good,fl_progressive:steep/https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2F56500944-a37a-4973-a5d2-e55247477982_623x98.png)](https://substackcdn.com/image/fetch/$s_!AQcz!,f_auto,q_auto:good,fl_progressive:steep/https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2F56500944-a37a-4973-a5d2-e55247477982_623x98.png)

After uploading zip `xz.zip` with files `cat.jpg`, `x.txt`, and `z.txt` to the webpage, it displayed the human-readable parts as follows:

[![](https://substackcdn.com/image/fetch/$s_!qunA!,w_1456,c_limit,f_auto,q_auto:good,fl_progressive:steep/https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2F3eab9726-e6c5-4951-9f19-d52ceca560a2_706x634.png)](https://substackcdn.com/image/fetch/$s_!qunA!,f_auto,q_auto:good,fl_progressive:steep/https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2F3eab9726-e6c5-4951-9f19-d52ceca560a2_706x634.png)

The webpage doesn't accept files other than zips.

[![](https://substackcdn.com/image/fetch/$s_!GbXy!,w_1456,c_limit,f_auto,q_auto:good,fl_progressive:steep/https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2F4204104b-080a-41fc-9696-d6b15f6793d3_677x182.png)](https://substackcdn.com/image/fetch/$s_!GbXy!,f_auto,q_auto:good,fl_progressive:steep/https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2F4204104b-080a-41fc-9696-d6b15f6793d3_677x182.png)

In the request headers, there is an interesting one with information about the server:

```
    Server: Werkzeug/3.0.1 Python/3.10.12
```

It could be worth noting, but I’ll leave it at that, because it doesn’t play any role in the solution.

Let’s think about a solution that focuses on zip files.

I didn’t know the path to the flag, unless it was `/home/flag.txt`. We could guess that the path looked like for `/home/{username_here}/flag.txt`. We need to read `/etc/passwd` file to get a username or try all possible injections like `../flag.txt`, `../../flag.txt`, `../../../flag.txt` to guess the right level in a directories tree structure.

First, I created a zip file with path injection for a file named `/etc/passwd`. The file contains information about the system's users.

[![](https://substackcdn.com/image/fetch/$s_!5Inx!,w_1456,c_limit,f_auto,q_auto:good,fl_progressive:steep/https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2F583f6d1c-5d0b-44ba-8a76-4e9ec3a96585_545x130.png)](https://substackcdn.com/image/fetch/$s_!5Inx!,f_auto,q_auto:good,fl_progressive:steep/https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2F583f6d1c-5d0b-44ba-8a76-4e9ec3a96585_545x130.png)

But the uploaded zip just returned the error:

[![](https://substackcdn.com/image/fetch/$s_!Jl_N!,w_1456,c_limit,f_auto,q_auto:good,fl_progressive:steep/https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2Fc77bc96c-675e-444b-9bc0-3252e122a4d2_670x207.png)](https://substackcdn.com/image/fetch/$s_!Jl_N!,f_auto,q_auto:good,fl_progressive:steep/https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2Fc77bc96c-675e-444b-9bc0-3252e122a4d2_670x207.png)

This didn’t work, so I tried to figure out how else I could confuse the code to read data outside of the target directory. So I tried to create a file with a**symlink** to `/etc/hostname`.

```
    ln -s /etc/hostname host.txt
```

A symlink is a type of file that points to another file or directory on the filesystem. It allows create a reference to another file or directory without duplicating the original content. 

Next, I zipped it with the flag that preserves symlinks –symlinks.

```
    zip --symlinks host.zip host.txt
```

[![](https://substackcdn.com/image/fetch/$s_!MFfv!,w_1456,c_limit,f_auto,q_auto:good,fl_progressive:steep/https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2Faf34de79-0d77-49ab-9e02-20cdc40d118b_697x289.png)](https://substackcdn.com/image/fetch/$s_!MFfv!,f_auto,q_auto:good,fl_progressive:steep/https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2Faf34de79-0d77-49ab-9e02-20cdc40d118b_697x289.png)

It worked!

Let's add `/etc/passwd` to get the username, which will be one of the lines without `nologin`. The `nologin` accounts are disabled for interactive shell access and used for system purposes. From the below list, we can guess that the username will be `copenhagen`.

[![](https://substackcdn.com/image/fetch/$s_!GEfC!,w_1456,c_limit,f_auto,q_auto:good,fl_progressive:steep/https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2Faaac001e-102e-4d57-9c31-585b8ed33ad2_900x641.png)](https://substackcdn.com/image/fetch/$s_!GEfC!,f_auto,q_auto:good,fl_progressive:steep/https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2Faaac001e-102e-4d57-9c31-585b8ed33ad2_900x641.png)

Finally, we get the flag from file `/home/copenhagen/flag.txt`.

[![](https://substackcdn.com/image/fetch/$s_!3ApL!,w_1456,c_limit,f_auto,q_auto:good,fl_progressive:steep/https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2F803d5e54-508a-4e73-9f50-9557a8f35173_378x131.png)](https://substackcdn.com/image/fetch/$s_!3ApL!,f_auto,q_auto:good,fl_progressive:steep/https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2F803d5e54-508a-4e73-9f50-9557a8f35173_378x131.png)

Uff, `no observable cats were harmed`. @helix cat is fine!

[![](https://substackcdn.com/image/fetch/$s_!A5Lp!,w_1456,c_limit,f_auto,q_auto:good,fl_progressive:steep/https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2Fff60e8f8-ad81-4a9a-93c2-b43d0d0fae98_1024x1024.png)](https://substackcdn.com/image/fetch/$s_!A5Lp!,f_auto,q_auto:good,fl_progressive:steep/https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2Fff60e8f8-ad81-4a9a-93c2-b43d0d0fae98_1024x1024.png)

Let me know in the comments if you have any questions or if you’d like to see a solution to any other web CTF task!

Happy hacking! Bye!

Thanks for reading Zimzi’s Substack! Subscribe for free to receive new posts and support my work.

Share
