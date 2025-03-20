---
title: "Greenhorn Walkthrough(HTB)"
date: 2025-03-19
draft: true
description: "A straight forward walkthrough for Greenhorn box."
tags: ["Easy", "Linux", "HTB", "Hacking", "Web", "Walkthrough"]
---
## Reconnaissance #Linux 
- Got three ports open 80,22,3000
- ![[Pasted image 20241225141303.png]]
- Port 80 runs a web called greenhorn. It also had loginpage 
- Got the info of Pluck CMS from the greenhorn page
- Port 3000 runs Gitea web, it had repo of the greenhorn page
- ![[Pasted image 20241225163431.png]]
- Can view it unauthenticated
## Enumeration
- Found a hash in the repo from the info on `login.php`
- Which is a sha512 hash, cracked it using hashcat 
- ![[Pasted image 20241225163840.png]]
- Logged in on the greenhorn web as admin
- Found a exploit on exploit DB for pluck (ref: [CVE-2023-50564](https://github.com/Rai2en/CVE-2023-50564_Pluck-v4.7.18_PoC))
- Similar to [[2.7-Sea]] this exploit also upload a zip to the web.
- I made a zip with reverseshell.php in it.
- ![[Pasted image 20241225164451.png]]
## Exploitation
- Went to `manage modules` and uploaded the zip via `install module`
- Then I found out the installed modules are stored like this `<URL>/data/modules/<zip_extracts_here>` with the help of repo
- Triggered the reverse shell and got connection
- ![[Pasted image 20241225164758.png]]
- Learnt that there is a user called `junior`
- ![[Pasted image 20241225164853.png]]
- Used the previous cracked password and it worked
- Got  the user flag
- ![[Pasted image 20241225165007.png]]
## Privilege Escalation
- In the home directory of junior, there is not only user flag but also a file named `Using OpenVAS.pdf` was also there.
- So transferred it to my attack machine
- ![[Pasted image 20241225165235.png]]
- It had this
- ![[Pasted image 20241225165315.png]]
- Interesting right, Root password is blured
- From this article found that, actually blured part can be recovered https://labs.jumpsec.com/can-depix-deobfuscate-your-data/
- Using this tool [Depixelization](https://github.com/spipm/Depixelization_poc)
- There is was a option in my pdf reader to extract only the pix-elated image from the PDF as image
- ![[Pasted image 20241225165809.png]]
- Saved the image as `png` then used the tool to get the original text
```
python3 depix.py -p ../pixel.png -s images/searchimages/debruinseq_notepad_Windows10_closeAndSpaced.png -o ../download-notepad_Windows10_closeAndSpaced.png
```
- ![[Pasted image 20241225165946.png]]
- Got the root password
- ![[Pasted image 20241225170036.png]]
- Logged in as root and got the root flag
- ![[Pasted image 20241225170134.png]]
