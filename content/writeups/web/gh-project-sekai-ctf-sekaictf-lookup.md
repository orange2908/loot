---
title: "lookup - sekaictf 2024"
category: "web"
subcategory: "heap"
type: "writeup"
tags: ["web", "tcache", "lookup", "heap", "web-exploitation", "sekaictf"]
summary: "web writeup for \"lookup\" from sekaictf - techniques: tcache, lookup, heap, web-exploitation, sekaictf."
source:
  name: "project-sekai-ctf/sekaictf-2024"
  url: "https://github.com/project-sekai-ctf/sekaictf-2024/blob/e7c9183860a846dd2c4e0d1fd5d5a1fe468e1244/web/lookup/solution/README.md"
ctf:
  name: "sekaictf"
  year: 2024
  challenge: "lookup"
---

## Source

- **CTF:** sekaictf 2024
- **Challenge:** lookup
- **Repository:** [project-sekai-ctf/sekaictf-2024](https://github.com/project-sekai-ctf/sekaictf-2024)
- **File:** <https://github.com/project-sekai-ctf/sekaictf-2024/blob/e7c9183860a846dd2c4e0d1fd5d5a1fe468e1244/web/lookup/solution/README.md>

---
### Writeup
- parser differential through `new URI("//_/lookup").getPath() == "/lookup"` (https://github.com/openjdk/jdk17/blob/master/src/jdk.httpserver/share/classes/sun/net/httpserver/ServerImpl.java#L581)
- gadget in https://github.com/apache/commons-scxml/blob/88ca43e2c46161c529af28adcb1de5775f9a56ae/src/main/java/org/apache/commons/scxml2/env/groovy/GroovyExtendableScriptCache.java#L305 with the sink `groovy.lang.GroovyClassLoader.parseClass()`
- then make use of lower jdk version allowing deser by default through ldap for example (https://github.com/openjdk/jdk17/blob/master/src/java.naming/share/classes/com/sun/jndi/ldap/VersionHelper.java#L62)
