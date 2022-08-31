---
title: "WannaCry: A Brief Analysis"
layout: single
header:
  image: /assets/images/wannacry-infection.png
---

## What is WannaCry?
WannaCry was a ransomware worm that rapidly spread globally in May of 2017, infecting nearly 200,000 computers across 150 countries. The malware disrupted lots of important computer infrastructure, such as the NHS (National Health Service) in the UK. Some sources estimate the damages caused to computer systems around the world to amount to nearly 4 billion USD.

Ransomware is typically defined as a a type of malware which seizes personal user data and encrypts it, subsequently demanding a ransom to be paid in order to decrypt the data.

![WannaCry Background Ransom Note]({{ site.url }}{{ site.baseurl }}/assets/images/wannacry-image-ransom.png)

## Initial Spread
WannaCry utilized the Windows [EternalBlue](https://en.wikipedia.org/wiki/EternalBlue) and [DoublePulsar](https://en.wikipedia.org/wiki/DoublePulsar) exploits, both developed by the NSA. These vulnerabilities were leaked in early 2017. The malware attacked public facing vulnerable SMB ports using EternalBlue to gain an inital foothold, and then leveraged DoublePulsar to establish a backdoor on the machine.

Furthermore, WannaCry continued to spread across networks using these exploits, causing the malware to expand rapidly.

## Infection Analysis
When detonated, WannaCry creates numerous files on the Desktop, including:
- @Please_Read_Me@.txt
- @WanaDecryptor@.exe
- @WanaDecryptor@.bmp
- Any files already present on the filesystem are encrypted and appended with '.WNCRY'