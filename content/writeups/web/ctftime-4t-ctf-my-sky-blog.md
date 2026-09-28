---
title: "My Sky Blog - 4T$ CTF"
category: "web"
subcategory: "ssti"
type: "writeup"
tags: ["web", "ssti", "go", "sky", "blog", "4t-ctf", "ctf-writeup"]
summary: "This CTF challenge was mainly about SSTI in Go."
source:
  name: "CTFtime writeup #39655"
  url: "https://ctftime.org/writeup/39655"
original_source: "https://www.thesecuritywind.com/post/4t-ctf-2024-my-sky-blog"
ctf:
  name: "4T$ CTF"
  challenge: "My Sky Blog"
---

## Metadata

- **CTF:** 4T$ CTF
- **Task:** My Sky Blog
- **Author team:** WindTeam
- **CTFtime tags:** ssti, go
- **CTFtime:** <https://ctftime.org/writeup/39655>
- **Original writeup:** <https://www.thesecuritywind.com/post/4t-ctf-2024-my-sky-blog>

---
This CTF challenge was mainly about SSTI in Go. There were various functionalities, and I'm not sure if all of them were necessary, so I'll focus only on the ones relevant to this solution. Although there weren't many solves, this challenge wasn't hard and I liked it because it helped me learn more about Go and how SSTI works in Go.

Source code provided at the end (to be updated).

The web application is some kind of blog that lets us register, view and create blog posts.

As we can see, it's a Go application. There are different files for the different functionalities. Here we can see the web application's routes.

As always, one of the first things I do is to understand what is probably required for retrieving the flag. So let's see what the 'flag' function does.

As we can see (line 45), it checks if we are an admin user. If we are, the server returns the flag.

I checked a couple of things but then I saw on the CTF Discord server that there was an issue with this challenge and the creator sent the changes made in the code.

According to this, the solution should be related to something in the 'index.go' file.

In the old (and secure) code they rendered the template using {{.User.Username}} as the username of the logged in user. The username in this case will be safely displayed without evaluating the value within it (when the username value is an SSTI payload).

The new and insecure version takes the username itself, appends it to the random sentence (to one of the sentences in lines 13-16) and then renders the template.

Let's say the username is {{html "Orel"}}, it will look like this in secure code vs. insecure code:

Secure code before rendering: 

Hey, {{.User.Username}}; there are {{.NbPosts}} posts right now !  
Secure code after rendering: 

Hey, {{html "Orel"}}; there are 1 posts right now !

Insecure code before rendering:

Hey, {{html "Orel"}}; there are 1 posts right now !  
Insecure code after rendering:

Hey, Orel; there are 1 posts right now !

In Go, as far as I understand, SSTI is restricted in a way that we can only access exported (public) struct fields and methods passed to the template. Line 35 tells us that 's' is passed to it, which is the Session struct (line 20). 

So let's see what fields we can access in the Session struct. Remember that our goal is to access '/flag' using an admin account. 

'User' refers to our account, nothing interesting there. But let's see what's in the 'Post' struct.

'Author' looks interesting, it's a pointer to the 'User' struct.

Every user has access to a post that has the admin user as the 'Author' field.

Our payload would begin with {{ (index .Posts 0).Author }} which is the admin's User object.

Currently the payload is combined from Session > Posts (Post struct) > Author (User struct) > ?.

Let's see what fields or methods we can access in the 'User' struct. The 'ChangePassword' method looks interesting. 

Let's form our payload and try it: 

{{ ((index .Posts 0).Author).ChangePassword "NewPass" }}  
Registration with the SSTI payload as the username:

Log in so the web application will render the template with the username. Note that it evaluated the template action (expression) and shows 'true' as the rendered value.

We can log in with the new admin credentials and access the flag.
