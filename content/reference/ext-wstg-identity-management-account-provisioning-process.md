---
title: "Account Provisioning Process (OWASP WSTG)"
category: "web"
subcategory: "identity-management"
type: "reference"
tags: ["wstg", "web", "wordpress", "account", "provisioning", "process", "identity-management", "identity", "management", "account-provisioning-process"]
summary: "The provisioning of accounts presents an opportunity for an attacker to create a valid account without application of the proper identification and authorization process."
source:
  name: "OWASP WSTG"
  url: "https://github.com/OWASP/wstg/blob/ea174034f91439a17a1595e57d51e5b461820273/document/4-Web_Application_Security_Testing/03-Identity_Management/03-Account_Provisioning_Process.md"
license: "CC BY-SA 4.0"
---

# Account Provisioning Process

|ID          |
|------------|
|WSTG-IDNT-03|

## Summary

The provisioning of accounts presents an opportunity for an attacker to create a valid account without application of the proper identification and authorization process.

## Test Objectives

- Verify which accounts may provision other accounts and of what type.

## How to Test

Determine which roles are able to provision users and what sort of accounts they can provision.

- Is there any verification, vetting and authorization of provisioning requests?
- Is there any verification, vetting and authorization of de-provisioning requests?
- Can an administrator provision other administrators or just users?
- Can an administrator or other user provision accounts with privileges greater than their own?
- Can an administrator or user de-provision themselves?
- How are the files or resources owned by the de-provisioned user managed? Are they deleted? Is access transferred?

### Example

In WordPress, only a user's name and email address are required to provision the user, as shown below:

![WordPress User Add](https://raw.githubusercontent.com/OWASP/wstg/ea174034f91439a17a1595e57d51e5b461820273/document/4-Web_Application_Security_Testing/03-Identity_Management/images/03-wordpress_useradd.png)\
*Figure 4.3.3-1: WordPress User Add*

De-provisioning of users requires the administrator to select the users to be de-provisioned, select Delete from the dropdown menu (circled) and then applying this action. The administrator is then presented with a dialog box asking what to do with the user's posts (delete or transfer them).

![WordPress Auth and Users](https://raw.githubusercontent.com/OWASP/wstg/ea174034f91439a17a1595e57d51e5b461820273/document/4-Web_Application_Security_Testing/03-Identity_Management/images/03-wordpress_authandusers.png)\
*Figure 4.3.3-2: WordPress Auth and Users*

## Tools

While the most thorough and accurate approach to completing this test is to conduct it manually, HTTP proxy tools could be also useful.

---

## Source

OWASP WSTG - <https://github.com/OWASP/wstg/blob/ea174034f91439a17a1595e57d51e5b461820273/document/4-Web_Application_Security_Testing/03-Identity_Management/03-Account_Provisioning_Process.md>

Mirrored into CTF-Brain at commit `ea174034f914`. Licence: CC BY-SA 4.0. The text is the original authors' work.
