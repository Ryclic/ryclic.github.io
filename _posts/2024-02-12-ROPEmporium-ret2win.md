---
toc: true
toc_label: "Table of Contents"
toc_icon: "list"
title: "ROPEmporium: ret2win"
excerpt: "'ret2win' focuses on basic buffer overflow and return address overwriting."
category: "pwn"
---
## Preface
Having not practiced binary exploitation in a while, I thought it was a good idea to return to basics and practice solving all the ROPemporium challenges again.
ROPemporium is a set of pwn challenges that teaches you the basics about return-oriented binary exploitation, bringing you from your first ret2win to more advanced attacks.

You can find all the challenges [here](https://ropemporium.com/).

Let's get started!
### File Information
Running the file, we are met with the following:

![Initial Run]({{ site.url }}{{ site.baseurl }}/assets/images/ropemporium/ret2win/initial.png)

From the challenge description and name, it appears to be a simple return to function challenge. Let's check the protections and file info:

![Check Permissions]({{ site.url }}{{ site.baseurl }}/assets/images/ropemporium/ret2win/checksec.png)

No stack canaries, no PIE, and NX is enabled meaning that we won't be able to run shellcode. 
### Decompilation
However, if we open this up in Ghidra or GDB, we can see that there indeed is a 'win' function. In this case, this function directly prints the flag for us, so all we have to do is call it.

```c
void ret2win(void)
{
  puts("Well done! Here\'s your flag:");
  system("/bin/cat flag.txt");
  return;
}
```

The program hints towards us the fact that there is a buffer overflow, which we can verify this by checking the decompilation.

```c
void pwnme(void)
{
  undefined local_28 [32];
  
  memset(local_28,0,0x20);
  read(0,local_28,0x38);
  puts("Thank you!");
  return;
}
```

The program allocates 32 bytes but calls `read()` with 0x38 = 56 bytes, so we know we can overflow the buffer by 24 bytes. This is plenty enough for us to overwrite both the base and return pointer.
### Finding Offset and Address
First, let's find the offset to the return address so we know how much to write. There are multiple ways to do this, but we will use the built-in pwntools cyclic function in order to generate a [de-Bruijn sequence](https://en.wikipedia.org/wiki/De_Bruijn_sequence). Then, we can input this sequence into GDB and wait for the segmentation fault to trigger. This happens because the return address is overwritten with our cyclic input, which is garbage data.

![Segfault]({{ site.url }}{{ site.baseurl }}/assets/images/ropemporium/ret2win/segfault.png)

Notice that we can't directly find the offset using the value inside RIP, because 64-bit binaries will not pop an invalid address into RIP.

Because of this, we will use RBP to calculate the offset instead. Since RBP is 8 bytes below RIP, we can simply add the calculated offset value by 8. We will use `cyclic -l RBP_VAL` to find the offset.

![RBP Offset]({{ site.url }}{{ site.baseurl }}/assets/images/ropemporium/ret2win/rbp_offset.png)

Therefore, our offset is 40 bytes. Now, all we need is to overwrite the return address with the address of `ret2win()`. We can either get this address from GDB or Ghidra. In GDB, we grab the address of the first instruction in the function disassembly.

![ret2win Address]({{ site.url }}{{ site.baseurl }}/assets/images/ropemporium/ret2win/ret2win_addr.png)

Since PIE is not enabled, the function's location will be the same everytime we run it, so we can hardcode this address. We can write up an exploit using pwntools:

```python
from pwn import *

p = process('./ret2win_bin')

payload = b'A'*40
payload += p64(0x400756)

p.sendline(payload)
p.interactive()
```
### Fixing Alignment
When we run this exploit we encounter an odd issue. The program seems to jump to `ret2win` through the printed output, but segfaults before it can print the flag out.

![Early Segfault]({{ site.url }}{{ site.baseurl }}/assets/images/ropemporium/ret2win/error.png)

Due to architecture design choices, x64 requires the stack to be 16-byte aligned before returning to GLIBC functions. Since the `ret2win` function calls `system()`, this means that our stack is out of alignment. To fix this, we can add an additional `ret` instruction to pad the stack by 8 bytes.

In ROP, these instructions are called 'gadgets', and we can find them using numerous different tools. Here, I'll use ROPgadget in order to locate a `ret` instruction.

![Stack Alignment]({{ site.url }}{{ site.baseurl }}/assets/images/ropemporium/ret2win/ret_alignment.png)

Then, we can add this before our `ret2win` address to get a working script!

![Finished Script]({{ site.url }}{{ site.baseurl }}/assets/images/ropemporium/ret2win/done.png)
### Final Script
```python
from pwn import *

p = process('./ret2win_bin')

payload = b'A'*40 # offset to RIP
payload += p64(0x000000000040053e) # MOVAPS alignment
payload += p64(0x400756) # ret2win addr

p.sendline(payload)
p.interactive()
```