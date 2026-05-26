#   Gadget Hunting in Practice

![Gadgethunting header pic](img/gadget-hunting.png)

You're on a hunt and you think a particular site may be vulnerable to XSS. Maybe you saw `__proto__` accepted in a parameter or the page does something weird when you add a query string like `?__proto__[foo]=bar`. You can't tell if it's vulnerable, and you can't trace the rest of the JavaScript. It may be minified, bundled, or obfuscated.

You need a way to answer three questions:

1.  Did pollution succeed? - did I actually pollute a prototype that application objects inherit from?
2.  Is there a gadget? - does any code read a property I control and pass it somewhere dangerous?
3.  Does the gadget reach a sink? - does "*somewhere dangerous*" mean execution?

A lot of beginners try to answer all three at once by firing `alert(1)` payloads. If the gadget isn't there or the sink isn't reachable, you get nothing. No alert, no signal, no idea which link in the chain broke.

***Gadget hunting*** is how you break the chain down and test each link separately.

##  Step 1: Confirming pollution succeeded

Before looking for gadgets, you need proof that your pollution actually stuck. Did you write to `Object.prototype` or not?

- You can't use a gadget to test this because you don't know if any exist yet.
- You can't rely on visible page changes because those would require a gadget and a sink.

The solution is to use a ***canary***. A harmless property with a unique value that you can detect without needing a gadget. This can be anything: `canary`, `testing123`, `M4rduk`. All are equally fine.

After attempting pollution (e.g., `https://example.com/?__proto__[canary]=infected`), check for inheritance in the console:
```javascript
console.log(({}).canary);

// Or, more simply:
({}).canary
```

**Why not `Object.prototype.canary`?** That checks property existence, **not** inheritance. Even worse, if you've been experimenting in the console and set properties manually, `Object.prototype.canary` will lie to you. It'll show your value even if the application's pollution vector never worked. 

`({}).canary` verifies that a new plain object **inherits** the polluted property, which is what actually matters. If that returns your value, pollution succeeded. If `undefined`, your vector failed.

📓 **NOTE:** Prior console experiments contaminate your results. **Always test in a clean tab**.

Once you've confirmed pollution works, the real hunt begins. Finding where the application reads polluted properties.

##  Step 2: Finding gadgets without source access

With pollution confirmed, you now need to find where the application reads those polluted properties. Here are three ways to do it without source access.

1.  **DOM Invader (Burp)** - This is your primary tool. DOM Invader automates canary injection and gadget detection. Here's what it actually does under the hood so you understand what you're looking at:
    - Injects a canary value onto `Object.prototype` via multiple vectors simultaneously.
    - Monitors all property reads across the page's JS execution.
    - When a polluted property is read and appears to influence a known sink pattern, it reports it.

    To quickly learn how to use DOM Invader and to ensure it's enabled (disabled by default), visit here: [https://portswigger.net/burp/documentation/desktop/tools/dom-invader](https://portswigger.net/burp/documentation/desktop/tools/dom-invader)

    Any gadgets it finds will appear in the panel with the property name, the sink type, and an "Exploit" button that pre-fills the payload.

    The thing to understand about DOM Invader results is that it reports gadget candidates, not confirmed exploits. A gadget that reads a property and passes it to `location.href` is only exploitable if you can actually write to `Object.prototype` via the application's inputs. DOM Invader finds the downstream half of the chain.

    You still need to confirm the upstream half in order to prove that a real pollution vector exists.

2.  [**ppmap**](https://github.com/kleiton0x00/ppmap) - A standalone tool that runs a list of known gadgets against a page. Where DOM Invader monitors passively, ppmap actively tests a curated set of property names known to be gadgets in popular libraries. Useful when DOM Invader misses something or you're working outside Burp's browser.
    ```bash 
    # basic usage against a target

    python3 ppmap.py -u "https://target.com/"

    ```

    It outputs which property names triggered execution, which identifies both the gadget and the property you need to pollute.

3.  **Manual source review** - When you have partial source access from using DevTools, .js files in your recon, or JS bundles you've pulled with *katana* or *gau*, you're searching for the gadget pattern directly.

    In DevTools Sources panel, use the global search (Cmd/Ctrl+Shift+F) with these patterns:
    ```text
    location\.href\s*=
    location\.hash
    location\.search
    \.innerHTML\s*=
    eval\(
    document\.write\(
    \.src\s*=
    ```
Each hit is a potential sink. Note the property being read nearby. That's your gadget candidate. You'll trace whether it actually reaches the sink in Step 3.

##  Step 3: Does the gadget reach a sink?

For each hit you found, read it backwards from the sink: 
- what variable is being assigned?
- Where does that variable come from?
- Is it a property read off a plain object with no `hasOwnProperty` check?

If you see `element.innerHTML = userConfig.message`, trace `userConfig`. Does it come from `options.message` where `options` is a plain object with no `hasOwnProperty` check? If so, polluting `message` on `Object.prototype` might reach `innerHTML`.

Conversely, if `userConfig` comes from `Object.freeze()` or checks `hasOwnProperty` before assignment, that gadget likely isn't exploitable. Move on.

### Example:

```javascript
// From a minified library, you've extracted and prettified this:
function applyTheme(options) {
  const theme = options.theme || 'default';
  const el = document.getElementById('app');
  el.setAttribute('data-theme', theme);
}
```

**Consider:**
- Is this a gadget?
- If yes - what property do you pollute, and what's the sink?
- If no - why not?

**Answer:** Yes this is a gadget, but a low-impact one. `options.theme` reads a property off `options` with no ownership check. If you pollute `Object.prototype.theme = 'attacker-value'` and `options` is a plain object, `theme` gets your value. It passes into the sink `setAttribute('data-theme', theme)`. But `setAttribute` itself is not inherently dangerous here because the target is a harmless `data-*` attribute.

This is a gadget with a weak sink. You'd note it and keep looking for one that reaches `innerHTML`, `eval`, `location.href`, or `script.src`. Finding weak gadgets is useful because it confirms pollution is working. It's proof of concept for the pollution half of the chain, but you need a strong-sink gadget for a real impact finding.

##  The known gadget library

Once you understand how to trace gadgets manually, you can shortcut the process by learning from what others have already found.

Certain property names are known gadgets in specific libraries because of how those libraries are written. These are the ones you'll encounter most often on real targets:

- **jQuery (pre-3.4.0)**: Property `isFunction`, `isArray`, `type` read by jQuery internals. Pollution can influence how jQuery processes callbacks and internal option handling.
- **Lodash (pre-4.17.17)**: The `_.template` function reads options off a plain config object. `Object.prototype.sourceURL` was a known gadget. It ended up in a `//# sourceURL=` comment inside an `eval` call, giving code execution.
- **Handlebars**: has known vulnerabilities like `CVE-2021-23383`, which involves prototype pollution leading to remote code execution.
- **Generic SPA patterns**: Any router that reads `redirectUrl`, `nextUrl`, `returnUrl`, `callbackUrl` off a config object is a strong gadget candidate. These frequently feed into navigation sinks like `location.href`.

You don't need to memorize these. When you're on a target, check what libraries are loaded, then check whether those versions have known gadgets. Sites like [NIST](https://nvd.nist.gov/) and [Snyk](https://security.snyk.io/) are a great resource and make it easy to search for those libraries.

##  Putting it all together

The full hunting workflow:

1. Identify potential pollution vectors
    - URL params, JSON bodies, postMessage handlers
    - Look for deep merge patterns in loaded JS

2. Confirm pollution with a canary
    - ({}).canary === your-value in a fresh tab

3. Find gadgets
    - DOM Invader first pass
    - ppmap if DOM Invader misses
    - Manual source search for sink patterns

4. Confirm gadget reaches a strong sink
    - location.href, innerHTML, eval, script.src

5. Craft the exploit payload
    - Replace canary with javascript:... or XSS string
    - Confirm execution

##  Conclusion

You've gone from a hunch to a confirmed exploit. Remember the three questions from the beginning:

1.  Did pollution succeed?
2.  Is there a gadget?
3.  Does the gadget reach a sink?

Answer them in order, don't skip ahead, and you'll stop chasing alerts that never fire.

Prototype pollution hunting becomes much easier once you stop treating it like a single bug. Pollution, gadget discovery, and exploitation are separate problems. Test them separately, confirm each step, and you can methodically work through even heavily minified applications instead of blindly firing payloads and hoping for alerts.

---

*Marduk-I-Am*  
Web Security Notes  

GitHub:
https://github.com/Marduk-I-Am