---
title: "Misc - Beta App - Hackअस्त्र"
category: "cloud"
subcategory: "storage"
type: "writeup"
tags: ["cloud", "s3", "iam", "privesc", "misc", "beta", "app", "storage", "hack", "ctf-writeup"]
summary: "For the complete documentation index, see llms.txt."
source:
  name: "CTFtime writeup #40816"
  url: "https://ctftime.org/writeup/40816"
original_source: "https://l1nuxkid.gitbook.io/l1nuxkid-docs/ctftime.org-writeups/beta-app-hack-2026"
ctf:
  name: "Hackअस्त्र"
  challenge: "Misc - Beta App"
---

## Metadata

- **CTF:** Hackअस्त्र
- **Task:** Misc - Beta App
- **Author team:** Team0Skills
- **CTFtime tags:** cloud
- **CTFtime:** <https://ctftime.org/writeup/40816>
- **Original writeup:** <https://l1nuxkid.gitbook.io/l1nuxkid-docs/ctftime.org-writeups/beta-app-hack-2026>

---
For the complete documentation index, see [llms.txt](https://l1nuxkid.gitbook.io/l1nuxkid-docs/llms.txt). This page is also available as [Markdown](https://l1nuxkid.gitbook.io/l1nuxkid-docs/ctftime.org-writeups/beta-app-hack-2026.md).

#### **Event** : [Hackअस्त्र CTF](https://ctftime.org/event/3270) on CTFtime

### Overview

This challenge is a classic **AWS Cognito Identity Pool misconfiguration** a real-world vulnerability class that has leaked sensitive data from dozens of production apps. The core idea: a mobile app's frontend accidentally exposed its AWS configuration in plain HTML, and the Cognito Identity Pool was configured to allow unauthenticated users to **escalate to the authenticated role** without any actual authentication. Let's walk through every step.

_**Attack Chain Diagram**_

![](https://l1nuxkid.gitbook.io/l1nuxkid-docs/~gitbook/image?url=https%3A%2F%2F3649623708-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYlNnAjgJP1t8Fm42Oonh%252Fuploads%252F9KYhaUpyhkyCCi3cmxo1%252Fattack-chain-beta-app.svg%3Falt%3Dmedia%26token%3D5512591c-e35a-4033-8eb0-2638de36d02a&width=768&dpr=3&quality=100&sign=796e69e14dcf3561f8beef84122839ef&sv=3)

###  Attack Chain

### Step 1 Visiting the Target

Opening the provided link led to a simple page at `beta.challenge.hackastra.tech`:

![](https://l1nuxkid.gitbook.io/l1nuxkid-docs/~gitbook/image?url=https%3A%2F%2F3649623708-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYlNnAjgJP1t8Fm42Oonh%252Fuploads%252FElJADVMoQHzrq3YcoguH%252Fimage.png%3Falt%3Dmedia%26token%3D144c202b-a571-4359-a46c-7b8ec5d3f62d&width=768&dpr=3&quality=100&sign=82a52529591694d73c54a8f9ec48616e&sv=3)

Nothing interesting on the surface. But in CTFs (and real-world pentests), **always view the page source**. Developers frequently hardcode config values directly into JavaScript on the frontend especially during beta phases. Hit `Ctrl+U` to view source.

![](https://l1nuxkid.gitbook.io/l1nuxkid-docs/~gitbook/image?url=https%3A%2F%2F3649623708-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYlNnAjgJP1t8Fm42Oonh%252Fuploads%252Ffese2tosJASYzQbidd4k%252Fimage.png%3Falt%3Dmedia%26token%3D90449810-50da-4359-8527-8bd8e8eef314&width=768&dpr=3&quality=100&sign=69f01a52d9886052452dc862004f0bb0&sv=3)

* * *

### Step 2 Leaking AWS Config from Source Code

The page source revealed this JavaScript block embedded directly in the HTML:

**Why this matters:** In legitimate apps, this config is used by the AWS Amplify SDK running in the user's browser to connect to backend services. The S3 bucket name and Cognito Identity Pool ID are supposed to be semi-public but only if the IAM roles attached to the pool are configured securely. Here, they weren't.

We now have two critical pieces:

  * **Cognito Identity Pool ID:** `us-east-1:08d85402-467a-4354-becc-97a9a5c549bd`

  * **S3 Bucket:** `mobileapp-mobile-assets-l9tp4r7x`


* * *

### Step 3 Understanding AWS Cognito Identity Pools

Before proceeding, a quick primer on how this service works:

AWS Cognito Identity Pools let you grant AWS credentials to users both **authenticated** (logged-in) and **unauthenticated** (anonymous/guest). Each type gets its own IAM role with different permissions. The pool issues temporary AWS credentials via STS (Security Token Service).

In a properly secured setup, the authenticated role should only be assumable by users who have **actually proven their identity** (via a login provider like Google, Facebook, or Cognito User Pools). The misconfiguration here let us bypass that.

* * *

### Step 4 Getting a Cognito Identity ID

The first AWS API call is to register ourselves as an anonymous identity in the pool:

![](https://l1nuxkid.gitbook.io/l1nuxkid-docs/~gitbook/image?url=https%3A%2F%2F3649623708-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYlNnAjgJP1t8Fm42Oonh%252Fuploads%252FqWnmaAxFkBHExp02OhAr%252Fimage.png%3Falt%3Dmedia%26token%3D35a2b2cf-9b46-4b8a-b7aa-2e61742a5571&width=768&dpr=3&quality=100&sign=4feaae833a7d3515b3c662157b410632&sv=3)

This returned a unique identity ID:

Think of this like a guest pass we're now a recognized (but untrusted) identity in the system.

* * *

### Step 5 Getting Temporary Credentials (Unauthenticated Role)

With an identity ID, we can request temporary AWS credentials:

This returned a full set of short-lived credentials (Access Key, Secret Key, Session Token). We exported them:

We're now acting as the **unauthenticated IAM role** a read-only guest.

![](https://l1nuxkid.gitbook.io/l1nuxkid-docs/~gitbook/image?url=https%3A%2F%2F3649623708-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYlNnAjgJP1t8Fm42Oonh%252Fuploads%252FYevv4C2sa7mYT3EY5pzp%252Fimage.png%3Falt%3Dmedia%26token%3De7f11c45-71fc-4dbb-8534-b5354738e5ae&width=768&dpr=3&quality=100&sign=97c5da2b7fe1b87ee2bde274647f4772&sv=3)

* * *

### Step 6 Enumerating the Public S3 Bucket

With these credentials, let's see what's in the public assets bucket:

![](https://l1nuxkid.gitbook.io/l1nuxkid-docs/~gitbook/image?url=https%3A%2F%2F3649623708-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYlNnAjgJP1t8Fm42Oonh%252Fuploads%252Fq6ip6IGDwJ60OyRg6EkP%252Fimage.png%3Falt%3Dmedia%26token%3Dd6f352ba-9f1c-4418-a9f7-fa6f1096f32d&width=768&dpr=3&quality=100&sign=c45ef6418b6894d78863a45e918248d4&sv=3)

Browsing through the files, one stood out immediately `config/backend-roles.json`. We downloaded and read it:

![](https://l1nuxkid.gitbook.io/l1nuxkid-docs/~gitbook/image?url=https%3A%2F%2F3649623708-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYlNnAjgJP1t8Fm42Oonh%252Fuploads%252FehbDvikJIG1lXPhRlK5N%252Fimage.png%3Falt%3Dmedia%26token%3D1f86f51b-5c0d-45be-9e5e-8bc9be800e1b&width=768&dpr=3&quality=100&sign=b4893e806615c9b4ae5a4020ba03562b&sv=3)

json

This is a goldmine. The developers left a config file accessible to anyone that reveals:

  * The **authenticated role ARN** we need to escalate to

  * The **premium S3 bucket** name: `mobileapp-premium-content-l9tp4r7x`


The flag is almost certainly in the premium bucket. We just need to become "authenticated."

* * *

### Step 7 Privilege Escalation via Cognito OpenID Token

Here's where the key misconfiguration is exploited. Normally, to assume the authenticated role you'd need a real identity provider token (from Google, Facebook, etc.). But Cognito has its own internal mechanism: `get-open-id-token`.

This call generates an OpenID token for _our own_ Cognito identity — essentially telling AWS "trust me, I'm this identity":

![](https://l1nuxkid.gitbook.io/l1nuxkid-docs/~gitbook/image?url=https%3A%2F%2F3649623708-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYlNnAjgJP1t8Fm42Oonh%252Fuploads%252FgzMN6OJ78sCME32Ags9k%252Fimage.png%3Falt%3Dmedia%26token%3D80f341f2-d9a2-4044-9f5d-8971e7e1f90a&width=768&dpr=3&quality=100&sign=c801bca13114886cf4c93a442e737c7c&sv=3)

The misconfiguration: the Identity Pool was **not configured with a trust condition** requiring a specific login provider. This means our unauthenticated identity could generate a valid OpenID token and use it to assume the authenticated role.

We passed this token to STS:

![](https://l1nuxkid.gitbook.io/l1nuxkid-docs/~gitbook/image?url=https%3A%2F%2F3649623708-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYlNnAjgJP1t8Fm42Oonh%252Fuploads%252F8MUFGS8Hptj8JYNU2rhA%252Fimage.png%3Falt%3Dmedia%26token%3D47fc6ae7-b705-4ced-b8dc-181003ff80cf&width=768&dpr=3&quality=100&sign=1676dc2f92fdc3d0a164fb0f1a85c8b7&sv=3)

This returned a **new, elevated set of credentials** now acting as the authenticated role.

### Step 8 Accessing the Premium Bucket and Capturing the Flag

We exported the new credentials and accessed the premium bucket:

![](https://l1nuxkid.gitbook.io/l1nuxkid-docs/~gitbook/image?url=https%3A%2F%2F3649623708-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYlNnAjgJP1t8Fm42Oonh%252Fuploads%252F3sW1ZZyeNPLs8ekHdCuD%252Fimage.png%3Falt%3Dmedia%26token%3D5525fd03-034f-45cb-a1e7-3d936b754f1a&width=768&dpr=3&quality=100&sign=a5cd54dabb07a4264097065764c8e534&sv=3)

### Vulnerability Summary

The attack chain exploited two layered mistakes:

Issue

Impact

AWS config hardcoded in HTML source

Identity Pool ID and bucket name leaked

`backend-roles.json` publicly readable

Authenticated role ARN and premium bucket name exposed

Cognito Identity Pool allows unauthenticated → authenticated escalation without a real login provider

Full privilege escalation without any credentials

The flag itself spells out the lesson: **don't trust the Cognito auth role without conditions** meaning the IAM trust policy on the authenticated role must include a condition that restricts which login providers are accepted. Without that condition, anyone with a Cognito identity (including anonymous users) can escalate.

### References

**In the "Understanding AWS Cognito Identity Pools" section (Step 3)** , add at the end:

> _For a deeper dive into this vulnerability class,_[_Hacking The Cloud's writeup on Overpermissioned Cognito Identity Pools_](https://hackingthe.cloud/aws/exploitation/cognito_identity_pool_excessive_privileges/) _is an excellent reference._

![](https://l1nuxkid.gitbook.io/l1nuxkid-docs/~gitbook/image?url=https%3A%2F%2F3649623708-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYlNnAjgJP1t8Fm42Oonh%252Fuploads%252FShijxSM2pKUP5yPbgRpl%252Fimage.png%3Falt%3Dmedia%26token%3De4393b6e-ea08-47b8-b579-9adaf7f735df&width=768&dpr=3&quality=100&sign=60e801996e459da194b03646530b79a2&sv=3)

[ PreviousSilent Oracle - 0xV01D CTF 2026](https://l1nuxkid.gitbook.io/l1nuxkid-docs/ctftime.org-writeups/silent-oracle-0xv01d-ctf-2026)[NextSWAG — Hackअस्त्र 2026](https://l1nuxkid.gitbook.io/l1nuxkid-docs/ctftime.org-writeups/swag-hack-2026)

Last updated 3 months ago
