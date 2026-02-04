Buffer Overflow 101

This is a simple stack buffer overflow challenge.

The vulnerable program reads input without bounds checking.
Your goal is to overflow the buffer and overwrite the return address
to call the secret() function which prints the flag.

Compile: gcc -fno-stack-protector -no-pie -o vuln vuln.c
Run: ./vuln

Tools you might need:
- gdb / pwndbg
- python / pwntools
- checksec
