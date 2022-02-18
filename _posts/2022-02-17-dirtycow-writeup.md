---
layout: post
title: What is Dirty COW?
subtitle: Writeup for CVE-2016-5195
tags: [pwn, PoC]
---

This is more like a story telling about CVE-2016-5195 to be honest. Nothing related to writeup n stuffs here.

Yah i know I'm pretty late, but I do whatever I want so... here's a post about DirtyCOW in 2022 🔫.

So why does it named DirtyCOW? Is it a cow which is dirty?

Not really, COW is for [Copy-on-Write](https://en.wikipedia.org/wiki/Copy-on-write).

Which means when a process requests a copy of some data, the kernel does not create the actual copy until it's being written into.

So why is it dirty? "Dirty" here refers to a "dirty page" that could be thrown away with [madvise](https://man7.org/linux/man-pages/man2/madvise.2.html).

From the two above, we can somehow conclude that this vulnerability has something to do with Copy-on-Write technique and madvise function. That's right. This vulnerability is a [race condition](https://docs.microsoft.com/en-us/troubleshoot/developer/visualstudio/visual-basic/race-conditions-deadlocks) in the linux kernel.

So what causes this race condition?

Let's take an example.

1. We create a copy of some read-only file.

2. We made changes to that copy:

Now this is where the vulnerability appears.

The write syscall first choose the place to write then it perform a write.

But what if, something malicious get between these two? 🧠

Yeah, that's race condition:

Normal: <span class="color-green">thread1 (choose place to write) -> thread1 (write) -> thread2 (do something)</span>

Malicious: <span class="color-green">thread1 (choose place to write)</span> -> <span class="color-orange">thread2 (do something)</span> -> <span class="color-green">thread1 (write)</span>

In this case, that "do something" is actually a madvise call. So after the thread1 has chosen a place write a to-be-modified copy, the madvise will take place, madvise tells the kernel to throw away that copy, the kernel jsut simply do that instruction.

Then the write action take place, because the copy is thrown away, the kernel now misunderstand that the write is supposed to perform at the origin file (the read-only file), not the copy version of it.

Yeah, you're not wrong, the kernel has unexpectedly overwritten a "read-only" file, which is a critial bug. It can be used to overwrite anyfile, such as rewrite a "u+s" permission file, or create a new root account by editing /etc/passwd, etc.

Here's [my PoC for DirtyCOW](https://github.com/th3-5had0w/DirtyCOW-PoC), well, I wrote this PoC a long time ago but till now I have the inspriation to explain about this vulnerability.