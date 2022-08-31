---
title: "WannaCry: A Brief Analysis"
layout: single
header:
  image: /assets/images/WannaCry/infection.png
words_per_minute: 120
---

## What is WannaCry?
WannaCry was a ransomware worm that rapidly spread globally in May of 2017, infecting nearly 200,000 computers across 150 countries. The malware disrupted lots of important computer infrastructure, such as the NHS (National Health Service) in the UK. Some sources estimate the damages caused to computer systems around the world to amount to nearly 4 billion USD.

Ransomware is typically defined as a a type of malware which seizes personal user data and encrypts it, subsequently demanding a ransom to be paid in order to decrypt the data.

![WannaCry Background Ransom Note]({{ site.url }}{{ site.baseurl }}/assets/images/WannaCry/image-ransom.png)

## Initial Spread
WannaCry utilized the Windows [EternalBlue](https://en.wikipedia.org/wiki/EternalBlue) and [DoublePulsar](https://en.wikipedia.org/wiki/DoublePulsar) exploits, both developed by the NSA. These vulnerabilities were leaked in early 2017. The malware attacked public facing vulnerable SMB ports using EternalBlue to gain an inital foothold, and then leveraged DoublePulsar to establish a backdoor on the machine.

Furthermore, WannaCry continued to spread across networks using these exploits, causing the malware to expand rapidly.

## Infection Analysis
When detonated, WannaCry creates numerous files on the Desktop, including:
- @Please_Read_Me@.txt
- @WanaDecryptor@.exe
- @WanaDecryptor@.bmp
- Any files already present on the filesystem are encrypted and appended with '.WNCRY'

Using Procmon to monitor system operations, WannaCry drops a secondary encryptor .exe file inside the `C:\Windows\` directory named `tasksche.exe`.
 
![tasksche.exe payload is dropped]({{ site.url }}{{ site.baseurl }}/assets/images/WannaCry/procmon-tasksche.png)
 
`tasksche.exe` subsequently creates several new files in a hidden directory within `C:\ProgramData\`. These are the main files which WannaCry utilizes. 
 
![Hidden Directory]({{ site.url }}{{ site.baseurl }}/assets/images/WannaCry/hidden-directory.png)
 
![New files created by tasksche.exe]({{ site.url }}{{ site.baseurl }}/assets/images/WannaCry/tasksche-file-drop.png)
 
Within this hidden directory, WannaCry also downloads the Tor client for C2 communications. 
 
![Tor Download]({{ site.url }}{{ site.baseurl }}/assets/images/WannaCry/tor.png)

Ransom notes are stored within the `msg` directory.
 
![Ransom Notes]({{ site.url }}{{ site.baseurl }}/assets/images/WannaCry/ransom-notes.png)

Onto the network side of infection, the first sign of network interaction WannaCry makes is an odd connection to a seemingly random URL. This is the infamous URL which MalwareTech (Marcus Hutchins) [registered shortly after the attack began](https://www.wired.com/story/confessions-marcus-hutchins-hacker-who-saved-the-internet/).
 
![Kill Switch URL]({{ site.url }}{{ site.baseurl }}/assets/images/WannaCry/killswitch-request.png)

WannaCry sends out the DNS request to the domain to check if it is reachable, and if not, program execution flows as normal. However, if the domain is resolved, the URL essentially acts as a "killswitch", stopping other infected computers from being encrypted. This was what slowed the attack following its release.

In order to propagate across networks, WannaCry attempts to resolve all hosts on the network by continually sending ARP broadcasts, each time with an increased IP address. Since my VM is isolated, the addresses automatically resolve to the `169.254.x.x` range used by the Windows DHCP server. 

However, no SMB requests are sent, since there are no other machines in my virtual network. If there was a Windows machine, WannaCry would attempt to establish a connection and check if it was vulnerable to the EternalBlue exploit. This is done by checking the SMB version.
 
![ARP Propegation Requests]({{ site.url }}{{ site.baseurl }}/assets/images/WannaCry/network-spread.png)

Finally, WannaCry controls it's C2 operations for payment via Tor on ports 443 and 9001. 
## Decompilation Analysis
After loading WannaCry into a decompiler of choice, one of the first things that comes into view is the killswitch URL once again. When WannaCry is run, the first thing that it does is check for the DNS resolution of the mysterious URL. The string is moved into the ESI register and later pushed onto the stack to be used in the [`InternetOpenUrlA()`](https://docs.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-internetopenurla) function. 
 
![Decompiled View]({{ site.url }}{{ site.baseurl }}/assets/images/WannaCry/decompile-p1.png)

The "killswitch" nature of the URL is present in the result of the [`InternetOpenUrlA()`](https://docs.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-internetopenurla) function. The result of the function is stored into edi, and subsequently a jump not equals is tested. If the connection was successful, the program exits, otherwise, it calls the entry function which proceeds to encrypt the files on the computer.

![Decompiled View]({{ site.url }}{{ site.baseurl }}/assets/images/WannaCry/decompile-p2.png)

## Conclusion
WannaCry demonstrated quite a few security principles to keep in mind regarding software security. The attack was made possible due to the amount of computers unpatched of the EternalBlue exploit, as well as SMB being enabled. It is important to keep in mind that you should always:
- Keep your infrastructure <ins>**simple**</ins>. Disable things that are not used to reduce possible attack vectors!
- <ins>**Update**</ins> your systems regularly. When the WannaCry attack occured, an EternalBlue fix by Microsoft had already been release for nearly 2 months.
- <ins>**Isolate**</ins> important systems completely from the network. WannaCry spread through SMB over LAN, meaning that computers who were not connected to the network could not have been affected.

Thanks for reading. I hope this article gave you a little more insight about one of the largest cyberattacks and the measures that can be taken to mitigate or prevent a future attack on your computer systems.