Return to Win

Classic ret2win challenge.

There's a win() function at a known address that prints the flag.
Overflow the buffer and redirect execution to win().

Steps:
1. Find the offset to overwrite RIP
2. Find the address of win()
3. Craft your payload

Tools: gdb, pwntools, ROPgadget
