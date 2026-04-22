#   URL-Based XSS: When JavaScript Hides the Vulnerability

![url-based xss header pic](img/url-based-xss.png)

You find an input. You search for `M4rduk`. Check the page source and `M4rduk` does not appear anywhere. Where did it go? How do you find it? This is where a lot of hunters move on. However, this is where things start to get interesting. The next step is hunting for your input inside JavaScript. Not HTML.

What do you do when the page source gives you nothing? This article will show you. From finding the JS files in the first place to reading and understanding what is happening to your search string.


##  Overview
In the previous article, "[Why `location.href` Isn’t Just a Redirect](https://github.com/Marduk-I-Am/web-security-notes/blob/main/xss/location-href-navigation-xss.md)", we covered the `location.href` sink in depth. If you haven't read it, you may want to start there.

This article covers:
- DOM-based XSS from URL sources (`location.search`, `location.hash`)
- The detection side from a methodology standpoint
- The `document.write` / `innerHTML` DOM XSS path

## When Page Source is Not Enough

In previous articles, it has been said to *always check the page source first* for your reflection. Which is true. But that HTML (page source) is just the starting point. 

Your browser then parses it, builds the DOM, and executes every script it finds. That script execution can rewrite the page substantially. Pulling in values from the URL, inserting content into the DOM (visible in Inspector), creating nodes that were never in the original HTML at all.

When looking for XSS vulnerabilities, your input may land in a value like `location.search`. This might never exist in the server's response. It may only appear after JavaScript runs and pushes it into the DOM. View Source will show you nothing. The injection is invisible until you look at what the browser has actually built.

## Finding the JS files

Now, how do we find the relevant JS files needed for us to analyze? If you are performing a full recon on your target, and would like to find more JS files, you can follow my article "[JavaScript File Hunting](https://medium.com/@marduk.i.am/recon-methodology-javascript-file-hunting-254127ecd211)". If you are exploring the site on the fly, use your DevTools. Go to the **Debugger**/**Sources** tab and you'll see a file tree on the left.

Depending on the site, there may be many JS files. Narrow it down some to save time:

- **Worth reading:** Files served from the same domain as the app. Look for names like `app.js`, `main.js`, `bundle.js`, `index.js`, or anything that looks hand-written.Short names, no hash in the filename. These are where application logic lives.

- **Skip:** Files from third-party domains (Google, CDNs, analytics). Minified files where everything is one line and variable names are single letters. You'll waste time and the logic you want is usually in the app's own code anyway. Also skip `.map` files for now.

- 📓 **Fast shortcut:** use the Search feature (***Ctrl+Shift+F*** inside DevTools) to search across all loaded files. Search for:
  ```text
  location.search
  location.hash
  location.href
  document.referrer
  window.name
  ```

## Sources and Sinks

**Sources**: Where attacker-controlled input enters the JavaScript runtime. This is data you can influence.

Common sources:
- `location.search` (the `?query=` part of the URL)
- `location.hash` (the `#fragment`)
- `location.href` (the whole URL)
- `document.referrer`
- `window.name`

**Sink**: Where that data gets written in a way that the browser can interpret as code or markup.

Common sinks:
- `document.write()`
- `element.innerHTML`
- `element.outerHTML`
- `eval()`
- `setTimeout()` / `setInterval()` with a string argument
- `location.href =` ... (when set to attacker-controlled data)

DOM-based XSS vulnerabilities exist when there's a path from source to sink with insufficient sanitization in between.

## Example Work-through: `document.write()`

Your page loads after searching for `M4rduk`. The URL reads: `https://example.com/?search=M4rduk`

You search the page source for your input. It's not there. That's the **signal**, not the dead end.

### Step 1: Identify the Source

You open **Debugger** in DevTools. Going through the list of common sources, you search for `location.search`. You find:
```javascript
var query = location.search.split('=')[1];
document.write('<p>You searched for: ' + query + '</p>');
```

What is happening here:
- `query` - variable being assigned 
- `location.search.split('=')[1]` - taking your search term from the URL
- `document.write()` - actually writing into page

`location.search.` is the source here.

### Step 2: Identify the sink

`document.write()` is your sink. It takes a string and writes raw HTML into the page.

### Step 3: Confirm in the Inspector

Open **Inspector**/**Elements** in DevTools. Find the `<p>` element. You'll see `M4rduk` sitting in the DOM. The source shows nothing, however the Inspector shows everything.

### Step 4: Exploit

Change `?search=M4rduk` to `?search=<img src=x onerror=alert(document.cookie)>` and reload the page.

The key detail is that `document.write()` does not escape HTML. It treats your input as trusted markup, allowing you to inject elements and event handlers directly into the DOM.

The `document.write()` call inserts your tag as live HTML. The browser renders it, `src=x` fails, `onerror` fires. That's DOM XSS confirmed.

## Example Work-through: `innerHTML`

Modern applications rarely use `document.write()`. Instead, they update the page dynamically using methods like `innerHTML`.

Let’s look at a slightly more realistic example. Same scenario as before. You search for `location.search`. But this time you find:
```javascript
var params = new URLSearchParams(location.search);
var searchTerm = params.get('q');

if (searchTerm) {
    var resultsContainer = document.getElementById('results');
    resultsContainer.innerHTML = `
        <h2>Search Results</h2>
        <p>You searched for: ${searchTerm}</p>
    `;
}
```

### Step 1: Identify the Source

- `params.get('q')` This pulls user-controlled input from the URL: `https://example.com/?q=M4rduk`

### Step 2: Identify the Sink

- `resultsContainer.innerHTML = ...`

This is **critical**. Unlike safer alternatives like `textContent`, `innerHTML` parses and renders HTML. If attacker-controlled data reaches this sink without sanitization, it becomes executable.

### Step 3: Confirm in the Inspector

Open Inspector you will see something like: `<p>You searched for: M4rduk</p>`

Once again, not in page source, but present in the live DOM.

### Step 4: Exploit

Now test a payload: `?q=<img src=x onerror=alert(document.cookie)>`

When the page loads:

- `searchTerm` contains your payload
- It gets injected into a template string
- No encoding or sanitization is applied before rendering
- `innerHTML` renders it as actual HTML

The browser creates the `<img>` element, the `src` fails, and `onerror` fires.

## Conclusion

View Source is a snapshot of what the server sent. The Inspector panel is a live view of what the browser has built and is currently rendering. For DOM XSS, only the second one tells you what's actually happening.

You will miss DOM XSS every time if you're hunting for XSS and you check the source, don't see your input, and move on. When your search string doesn't appear in view-source, you haven't hit a dead end. You've hit the starting line. The real page is built by JavaScript, and that JavaScript reads from the URL. Open your Inspector, trace the data from source to sink, and you'll find XSS where scanners and source-viewers never look.

