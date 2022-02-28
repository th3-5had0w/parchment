---
layout: post
title: friendly-kernel
subtitle: Kernel tricks or tips noted
tags: [kernel, pwn]
---

- Content:
    - [Disable kernel mitigations](#disable-kernel-mitigations)
        - [Enable userfaultfd syscall for unprivileged users](#enable-userfaultfd-syscall-for-unprivileged-users)

# Disable kernel mitigations

### Enable userfaultfd syscall for unprivileged users:

```bash
sudo sysctl -w vm.unprivileged_userfaultfd=1
```