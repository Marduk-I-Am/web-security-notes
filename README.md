#   Web Security Notes

A growing collection of practical web application security notes, vulnerability research, lab walkthroughs, and bug bounty methodology focused on understanding how vulnerabilities work. Not just how to find them.

The goal of this repository is to document concepts, techniques, and real-world testing approaches in a way that's useful to aspiring security researchers, bug bounty hunters, and application security practitioners.

##  Topics:

### Cross-Site Scripting (XSS)

**Context-Based XSS (fundamentals)**
- [Context Is Everything: A Practical Guide to XSS](https://github.com/Marduk-I-Am/web-security-notes/blob/main/xss/context-is-everything.md)
- [Stop Guessing XSS Payloads: Identify Context in 3 Steps](https://github.com/Marduk-I-Am/web-security-notes/blob/main/xss/stop-guessing-xss-payloads.md)

**DOM & URL-Based Sinks**
- [Why `location.href` Isn't Just a Redirect: Understanding Navigation-Based XSS](https://github.com/Marduk-I-Am/web-security-notes/blob/main/xss/location-href-navigation-xss.md)
- [URL-Based XSS: When JavaScript Hides the Vulnerability](https://github.com/Marduk-I-Am/web-security-notes/blob/main/xss/url-based-xss.md)

**DOM Sources Beyond `location.search`**
- [Reading JS Files Like an Attacker: Notable Sources](https://github.com/Marduk-I-Am/web-security-notes/blob/main/xss/reading-js-files-like-an-attacker-notable-sources.md)

**Prototype Pollution & Gadget Chains**
- [Prototype Pollution: Turning Property Lookups into Code Execution](https://github.com/Marduk-I-Am/web-security-notes/blob/main/xss/prototype-pollution.md)
- [Gadget Hunting in Practice](https://github.com/Marduk-I-Am/web-security-notes/blob/main/xss/gadget-hunting.md)
- [Prototype Pollution in Practice: Solving DOM XSS Labs Methodically](https://github.com/Marduk-I-Am/web-security-notes/blob/main/xss/prototype-pollution-in-practice.md)

**Content Security Policy**
- [Reading CSPs Like an Attacker: Understanding Content Security Policy for XSS Testing](https://github.com/Marduk-I-Am/web-security-notes/blob/main/xss/reading-csps-like-an-attacker.md)
- [Breaking CSPs: Practical Content Security Policy Bypass Techniques](https://github.com/Marduk-I-Am/web-security-notes/blob/main/xss/breaking-csps.md)

**Real-World Application & Methodology**
- [DOM Invader on a Real Bug Bounty Target: 10 Sink Hits, 0 Vulnerabilities](https://github.com/Marduk-I-Am/web-security-notes/blob/main/xss/dom-invader-on-real-bug-bounty-target.md)

### SQL Injection
### Access Control
### Client-side vulnerabilities
### Bug bounty methodology