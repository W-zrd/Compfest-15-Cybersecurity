from pwn import *
import string

r = remote("34.101.174.85", 10000)
flag = b""
while b"}" not in flag:
    r.recvuntil(b"> ")
    r.sendline(b"2")
    r.recvuntil(b"(in hex) = ")
    payload = hex(ord('A'))[2:]*(length-1)
    r.sendline(payload.encode())
    check = r.recvuntil(b"(in hex): ")
    block = []
    resp = r.recvline().strip()
    resp = bytes.fromhex(resp.decode())
    for i in range(0,len(resp),16):
        block.append(resp[i:i+16])
    for i in string.printable[:-6]:
        r.recvuntil(b"> ")
        r.sendline(b"2")
        r.recvuntil(b"(in hex) = ")
        tmp_payload = payload + flag.hex() + hex(ord(i))[2:]
        r.sendline(tmp_payload.encode())
        check = r.recvuntil(b"(in hex): ")
        resp = r.recvline().strip()
        resp = bytes.fromhex(resp.decode())
        block_check = []
        for j in range(0,len(resp),16):
            block_check.append(resp[j:j+16])
        if(block[5]==block_check[5]):
            flag += i.encode()
            print("Decrypted msg : {}".format(flag))
            length -= 1
            break