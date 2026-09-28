---
title: "4ES - CrewCTF 2024"
category: "forensics"
subcategory: "heap"
type: "writeup"
tags: ["forensics", "heap", "terraform", "fuzzing", "crewctf", "crewctf-2024", "2024", "ctf-writeup"]
summary: "Home Services Products Training Portfolio Partners About Contact"
source:
  name: "CTFtime writeup #39365"
  url: "https://ctftime.org/writeup/39365"
original_source: "https://airoverflow.com/"
ctf:
  name: "CrewCTF 2024"
  year: 2024
  challenge: "4ES"
---

## Metadata

- **CTF:** CrewCTF 2024
- **Task:** 4ES
- **Author team:** AirOverFlow
- **CTFtime:** <https://ctftime.org/writeup/39365>
- **Original writeup:** <https://airoverflow.com/>

---
[Home](https://airoverflow.com/) [Services](https://airoverflow.com/services) [Products](https://airoverflow.com/products) [Training](https://airoverflow.com/training) [Portfolio](https://airoverflow.com/portfolio) [Partners](https://airoverflow.com/partners) [About](https://airoverflow.com/about) [Contact](https://airoverflow.com/contact)

Enterprise Offensive Security Practice

#  Security Testing by People  
Who Attack for a Living

Penetration Testing · Red Teaming · DFIR · Cyber Ranges

AirOverflow is an offensive security firm serving governments, telecoms and enterprises worldwide. Our certified engineers find what scanners miss, prove it with working exploits, and build the platforms that keep your team ready for what comes next.

Get a Free Security Review [Explore Services](https://airoverflow.com/services)

OSCP+OSEDOSEPCREST CRTCREST CPSAeWPTXRed Team Ops I & II

1,000+

Platform Users

500+

Wargame Challenges

11+

Certifications Held

<1day

Response Time

Organizations that trust our work

![Zain Telecom logo](https://www.google.com/s2/favicons?domain=zain.com&sz=128)Zain Telecom

![Orange logo](https://www.google.com/s2/favicons?domain=orange.com&sz=128)Orange

![Warner Bros. logo](https://www.google.com/s2/favicons?domain=warnerbros.com&sz=128)Warner Bros.

![Umniah logo](https://www.google.com/s2/favicons?domain=umniah.com&sz=128)Umniah

![Resecurity logo](https://www.google.com/s2/favicons?domain=resecurity.com&sz=128)Resecurity

![Antigen Security logo](https://www.google.com/s2/favicons?domain=antigensecurity.com&sz=128)Antigen Security

![Planning Commission of Pakistan logo](https://www.google.com/s2/favicons?domain=pc.gov.pk&sz=128)Planning Commission

![Pakistan Bureau of Statistics logo](https://www.google.com/s2/favicons?domain=pbs.gov.pk&sz=128)Bureau of Statistics

![National Centre for Cyber Security logo](https://www.google.com/s2/favicons?domain=nccs.pk&sz=128)NCCS

![National CERT Pakistan logo](https://www.google.com/s2/favicons?domain=pkcert.gov.pk&sz=128)nCERT

![Air University logo](https://www.google.com/s2/favicons?domain=au.edu.pk&sz=128)Air University

![Trillium Information Security Systems logo](https://www.google.com/s2/favicons?domain=trillium.com.pk&sz=128)Trillium (TISS)

What Changes for You

## Outcomes, Not Deliverables

Nobody buys a penetration test because they want a PDF. Here is what our clients actually walk away with — and how we get them there.

Know Every Way In — Before Attackers Do

Certified engineers map and exploit your real attack surface, so board conversations start from evidence instead of guesswork. Every finding proven, every fix verified with a free retest.

[Via Penetration Testing →](https://airoverflow.com/vapt)

Learn If You'd Catch a Real Attack

A controlled adversary campaign answers the question that keeps CISOs up at night: would our people and tooling notice, and how fast could we respond? Now you know — before it's real.

[Via Red Teaming →](https://airoverflow.com/red-teaming)

Turn an Incident Into a Contained Event

When something gets through, the difference between a bad week and a headline is response speed. Rapid triage, forensics and recovery — with evidence that stands up to regulators and courts.

[Via DFIR →](https://airoverflow.com/dfir)

Pass Audits Without the Scramble

Reports mapped to ISO 27001, PCI-DSS, SOC 2 and NIST — evidence in the format auditors expect, plus continuous coverage from $89/month so the next audit is a formality, not a fire drill.

[Via Klue Continuous Testing →](https://airoverflow.com/klue)

A Team That's Ready, Not Just Certified

Your engineers and analysts practice on live infrastructure — attacking, defending and responding under pressure — so the first real incident isn't their first incident.

[Via Training & the Arena Range →](https://airoverflow.com/training)

Definitive Answers on Suspicious Code

Within days of a suspicious binary appearing, you know exactly what it does, what it touched, and how to detect it next time — IOCs and YARA rules your SOC deploys the same day.

[Via Malware Analysis →](https://airoverflow.com/malware-analysis)

[See How We Deliver These](https://airoverflow.com/services)

Our Products

## Covered Year-Round, Not Once a Year

Point-in-time engagements have gaps between them. These platforms are how our clients stay tested, trained and watched in the months in between.

AI · PTaaS · Autonomous

Klue

An autonomous AI penetration testing engine that plans, adapts and exploits the way an experienced red teamer would. In benchmark testing it returned zero false positives.

[Explore Klue →](https://airoverflow.com/klue)

Cyber Range · On-Prem · Air-Gap

Arena

A self-hosted cyber range: real VMs, containers and full networks on demand, with browser attack machines, proctored practical exams, courses and CTF hosting.

[Explore Arena →](https://airoverflow.com/arena)

Competitive · CTF

Showdown

The CTF competition platform behind the Pakistan Cybersecurity Challenge and events for universities, enterprises and national organizers.

[Explore Showdown →](https://airoverflow.com/showdown)

Attack · Defense · Real-Time

Warzone

Teams attack each other's services while patching and defending their own, live. As close to operational cyber conflict as a training exercise gets.

[Explore Warzone →](https://airoverflow.com/warzone)

Bug Bounty · Disclosure

HuntMeDown

A bug bounty platform that connects organizations with vetted researchers for continuous, responsible vulnerability disclosure.

[Explore HuntMeDown →](https://airoverflow.com/huntmedown)

+

More in the Works

We keep building tools for the security community. Ask us what's next.

[Get Early Access →](https://airoverflow.com/contact)

1000+

Arena Users

Onboarded in 2 months

500+

Wargame Challenges

Community + team

10+

Competitions

Organized to date

11+

Certifications

OSCP+, OSED, CREST…

Case Studies

## How Engagements Actually Went

Anonymized, but real: what we were asked to do, what we found, and what changed afterwards.

[ Government · VAPT Securing a National Statistical Agency Infrastructure and application testing for an institution holding sensitive national data — and a clean retest inside one quarter. Impact: modernization programme proceeded on schedule, on hardened systems Read the Case Study → ](https://airoverflow.com/case-studies#statistical-agency) [ Telecom · External VAPT External Assessment for a Regional Telecom A partner-delivered engagement across a sprawling external estate, with an exploitable path to subscriber data closed before disclosure. Impact: subscriber-data exposure averted, zero downtime during testing Read the Case Study → ](https://airoverflow.com/case-studies#telecom-operator) [ Enterprise · Automation Security Automation for a Software Firm A custom security tool that removed a manual review bottleneck — the client's words: "the ideal one-stop solution." Impact: analyst hours redeployed from repetitive checks to real work Read the Case Study → ](https://airoverflow.com/case-studies#software-firm)

Research & Writeups

## From the AirOverflow Blog

Technical research, exploitation writeups and event retrospectives from the team.

[ Cloud SecurityJul 17, 2026 How Not to Write Insecure Infrastructure-as-Code The Terraform and cloud-config patterns that quietly hand your whole infrastructure to a stranger — and how to catch them before they ship. Read on the Blog → ](https://blog.airoverflow.com/blog/how-not-to-write-insecure-iac) [ FuzzingJul 15, 2026 Fuzzing Menu-Based CTF Challenges with AFL++ Building a structure-aware harness for stateful heap challenges — turning raw fuzzer bytes into menu operations to surface bugs automatically. Read on the Blog → ](https://blog.airoverflow.com/blog/fuzzing-menu-ctf-challenges-aflplusplus) [ Kernel ResearchJul 15, 2026 Fuzzing the Linux Kernel Locally with AFL++ Coverage-guided syscall fuzzing against the Linux kernel on your own machine — no cloud fleet required. A practical, reproducible setup. Read on the Blog → ](https://blog.airoverflow.com/blog/fuzzing-linux-kernel-aflplusplus)

[Visit the Blog](https://blog.airoverflow.com)

Now at AirOverflow

## Recent & Upcoming

Latest Engagement

External VAPT for a regional telecom operator, delivered with our partner Resecurity — final retest completed. [Read how it went →](https://airoverflow.com/case-studies)

Latest Event

UCP Takra 2025 — CTF competition and training event for the University of Central Punjab, hosted on our Showdown platform.

Upcoming

Planning a CTF, cyber drill or training cohort for your organization? We're scheduling events for the next two quarters. [Reserve a slot →](https://airoverflow.com/contact)

What Clients Say

## In Their Own Words

Ministries Audited Nationwide

"The founders have a decorated profile. They performed security audits of ministries of the GOP in collaboration with NCCS. I hope they excel not only in Pakistan but internationally."

Prof. Kashif Kifayat

Director — NCCS

Zero Breaches in Production Use

"We have never experienced any breach or security issue using their products, and their team is always available. They not only provide quality products, but also conduct workshops and trainings."

Khwaja Mansoor ul Hassan

Lead Auditor — nCERT

Manual Bottleneck Automated

"AirOverflow's ability to identify critical areas for automation significantly optimized our business processes. They are the ideal one-stop solution for the job."

Ali Abbas

Associate Manager — Blau Welt Solutions

[View Portfolio](https://airoverflow.com/portfolio)

Free · No Obligation

## Get a Free Security Posture Review

Tell us your website or primary domain. A certified engineer takes an attacker's first look at your external surface — what's exposed, what's inviting, what we'd probe first — and walks you through it on a 30-minute call.

  * An engineer's read of your externally visible attack surface
  * The two or three exposures we would pursue first, and why
  * A straight answer on whether you need testing now — or don't
  * No scanner spam, no obligation, no pressure follow-ups


Passive review of publicly visible information only — no testing is performed against your systems without a signed engagement.
