Format String Vulnerability

The program uses printf() unsafely with user-controlled input.

Your goal is to leak the flag from memory using format string specifiers.

Tools you might need:
- gdb / pwndbg
- python / pwntools

Try: %x %s %p to leak stack values
