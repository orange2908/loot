---
title: "ProfileEditor - PwnMe CTF Quals 2025"
category: "web"
subcategory: "lfi"
type: "writeup"
tags: ["web", "path-traversal", "flask", "profileeditor", "lfi", "pwnme-ctf-quals", "pwnme-ctf-quals-2025", "2025", "ctf-writeup"]
summary: "In this Capture The Flag (CTF) challenge, I tackled a Flask-based web application and uncovered a classic path traversal vulnerability."
source:
  name: "CTFtime writeup #40059"
  url: "https://ctftime.org/writeup/40059"
original_source: "https://a51f221b.vercel.app/blog/PwnMeCTF-2025"
ctf:
  name: "PwnMe CTF Quals 2025"
  year: 2025
  challenge: "ProfileEditor"
---

## Metadata

- **CTF:** PwnMe CTF Quals 2025
- **Task:** ProfileEditor
- **Author team:** deadly farts
- **CTFtime:** <https://ctftime.org/writeup/40059>
- **Original writeup:** <https://a51f221b.vercel.app/blog/PwnMeCTF-2025>

---
Authors
    

  * ![avatar](https://a51f221b.vercel.app/_next/image?url=%2Fstatic%2Fimages%2Fprofile.png&w=96&q=75)

Name
    Asif Masood
Twitter
    [@A51F221B](https://twitter.com/A51F221B)


# ProfileEditor - Web Challenge

In this Capture The Flag (CTF) challenge, I tackled a Flask-based web application and uncovered a classic path traversal vulnerability. By registering a cleverly crafted username, logging in, and navigating to the profile page, I retrieved the hidden flag with just a few clicks. This writeup walks through my journey—how I spotted the flaw, exploited it, and snagged the flag—while sharing insights to make it both fun and educational. Let’s dive in!

* * *

## The Challenge Setup

The application was a straightforward user management system built with Flask, offering a handful of features:

  * **Registration (`/register`)**: Create an account with a username and password.
  * **Login (`/login`)**: Log in to access protected features.
  * **Profile Editing (`/profile`)**: View or update your profile, stored as an HTML file.
  * **Profile Viewing (`/show_profile`)**: Display your profile by reading the file tied to your username.


The mission? Find a vulnerability and extract the flag—a secret string likely tucked away in a file on the server. Armed with the source code and a hunch, I set out to explore.

* * *

## Digging into the Code

First, I analyzed the Flask app’s source code to understand how it handled user data and file operations. The `/show_profile` route caught my eye—it fetched and displayed the user’s profile file based on their session username. Here’s the key snippet (simplified):

```
    @app.route('/show_profile')
    def show_profile():
        profiles_file = 'profile/' + session.get('username')
        if os.path.commonpath((app.root_path, abspath(profiles_file))) != app.root_path:
            return "Error: Invalid file path"
        with open(profiles_file, 'r') as f:
            return f.read()
```

## What Stood Out

  1. File Path Construction:
     * The path is built by concatenating 'profile/' with the username from the session (session.get('username')).
     * No sanitization was applied to the username—red flag alert!
  2. Security Check:
     * The os.path.commonpath check ensures the resolved file stays within app.root_path (the app’s root directory).
     * It blocks access to files outside the root (e.g., /etc/passwd), but not within it.
  3. Username Freedom:
     * The /register route accepted any username I threw at it—no restrictions on special characters like ...
     * This screamed path traversal vulnerability. If I could control the username, I might trick the app into reading a file outside the profile/ directory—like, say, a flag.txt file sitting in the root directory.


## Crafting the Exploit

Path traversal is all about manipulating file paths with ../ to climb up directories. Here’s how it could work:

  * Normal username: `alice` → File path: `profile/alice`.
  * Traversal username: `../flag.txt` → File path: `profile/../flag.txt` → Resolves to flag.txt.


The security check would pass as long as `flag.txt` was inside `app.root_path`. My hypothesis: the flag was likely stored in the app’s root directory (e.g., `/app/flag.txt`), and I could reach it with a well-crafted username.

## The Plan

  1. Register with a Malicious Username:
     * Use `../flag.txt` as the username to point to a hypothetical `flag.txt` file one level up from `profile/`.
  2. Log In:
     * Authenticate to set the session with my username.
  3. View the Profile:
     * Hit /show_profile to make the app read and display flag.txt.


Time to test it!

## Step-by-Step Exploitation

#### Step 1: Registration

I headed to `/register` and entered:

  * Username: `../flag.txt`
  * Password: `password123` (keeping it simple) The app accepted it without a hitch. My account was created, and I pictured the file path in my head: `profile/../flag.txt` collapsing to just `flag.txt`.


#### Step 2: Login

Next, I logged in using:

  * Username: `../flag.txt`
  * Password: `password123` The login succeeded, and my session was set with `username = '../flag.txt'`. So far, so good.


#### Step 3: Show Profile

I clicked the "Show Profile" link (taking me to `/show_profile`). The app constructed the path:

`'profile/' + '../flag.txt'` = `profile/../flag.txt` → Resolves to `flag.txt`. If `flag.txt` existed in the root directory, the app would read it and display its contents. I held my breath and… boom! The page loaded with a glorious string:

```
    PWNME{A_FAKE_FLAG_FOR_THE_WIN}
```

[Discuss on Twitter](https://mobile.twitter.com/search?q=https%3A%2F%2FA51F221B.vercel.app%2Fblog%2FPwnMeCTF-2025) • [View on GitHub](https://github.com/A51F221B/MyBlog/blob/main/data/blog/PwnMeCTF-2025.mdx)

Load Comments
