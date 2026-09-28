---
title: "Number of Times a Function Can Be Used Limits (OWASP WSTG)"
category: "web"
subcategory: "business-logic"
type: "reference"
tags: ["wstg", "web", "business-logic", "number", "times", "function", "limits", "business", "logic", "number-of-times-a-function-can-b", "can", "used"]
summary: "Many of the problems that applications are solving require limits to the number of times a function can be used or action can be executed."
source:
  name: "OWASP WSTG"
  url: "https://github.com/OWASP/wstg/blob/ea174034f91439a17a1595e57d51e5b461820273/document/4-Web_Application_Security_Testing/10-Business_Logic/05-Number_of_Times_a_Function_Can_Be_Used_Limits.md"
license: "CC BY-SA 4.0"
---

# Number of Times a Function Can Be Used Limits

|ID          |
|------------|
|WSTG-BUSL-05|

## Summary

Many of the problems that applications are solving require limits to the number of times a function can be used or action can be executed. Applications must be "smart enough" to not allow the user to exceed their limit on the use of these functions since in many cases each time the function is used the user may gain some type of benefit that must be accounted for to properly compensate the owner. For example: an eCommerce site may only allow a users apply a discount once per transaction, or some applications may be on a subscription plan and only allow users to download three complete documents monthly.

Vulnerabilities related to testing for the function limits are application specific and misuse cases must be created that strive to exercise parts of the application/functions/actions more than the allowable number of times.

Attackers may be able to circumvent the business logic and execute a function more times than "allowable" exploiting the application for personal gain.

### Example

Suppose an eCommerce site allows users to take advantage of any one of many discounts on their total purchase and then proceed to checkout and tendering. What happens of the attacker navigates back to the discounts page after taking and applying the one "allowable" discount? Can they take advantage of another discount? Can they take advantage of the same discount multiple times?

## Test Objectives

- Identify functions that must set limits to the times they can be called.
- Assess if there is a logical limit set on the functions and if it is properly validated.

## How to Test

- Review the project documentation and use exploratory testing looking for functions or features in the application or system that should not be executed more that a single time or specified number of times during the business logic workflow.
- For each of the functions and features found that should only be executed a single time or specified number of times during the business logic workflow, develop abuse/misuse cases that may allow a user to execute more than the allowable number of times. For example, can a user navigate back and forth through the pages multiple times executing a function that should only execute once? or can a user load and unload shopping carts allowing for additional discounts.

## Related Test Cases

- [Account Enumeration and Guessable User Account](https://github.com/OWASP/wstg/blob/ea174034f91439a17a1595e57d51e5b461820273/document/4-Web_Application_Security_Testing/03-Identity_Management/04-Account_Enumeration_and_Guessable_User_Account.md)
- [Weak lock out mechanism](https://github.com/OWASP/wstg/blob/ea174034f91439a17a1595e57d51e5b461820273/document/4-Web_Application_Security_Testing/04-Authentication/03-Weak_Lock_Out_Mechanism.md)

## Remediation

The application should set hard controls to prevent limit abuse. This can be achieved by setting a coupon to be no longer valid on the database level, to set a counter limit per user on the backend or database level, as all users should be identified through a session, whichever is better to the business requirement.

## References

- [Gold Trading Was Temporarily Halted On The CME This Morning](https://www.businessinsider.com/gold-halted-on-cme-for-stop-logic-event-2013-10)

---

## Source

OWASP WSTG - <https://github.com/OWASP/wstg/blob/ea174034f91439a17a1595e57d51e5b461820273/document/4-Web_Application_Security_Testing/10-Business_Logic/05-Number_of_Times_a_Function_Can_Be_Used_Limits.md>

Mirrored into CTF-Brain at commit `ea174034f914`. Licence: CC BY-SA 4.0. The text is the original authors' work.
