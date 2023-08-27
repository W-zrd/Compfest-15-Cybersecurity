
from pwn import *
import string

def get_encrypted_block(r, payload):
    r.recvuntil(b"> ")
    r.sendline(b"2")
    r.recvuntil(b"(in hex) = ")
    r.sendline(payload)
    r.recvuntil(b"(in hex): ")
    resp = r.recvline().strip()
    blocks = [resp[i:i+32] for i in range(0, len(resp), 32)]
    return blocks

def main():
    r = remote("34.101.174.85", 10000)
    length = 96
    flag = b""
    while b"}" not in flag:
        payload = b'A' * (length - 1)
        blocks = get_encrypted_block(r, payload.hex())
        
        for char in string.printable:
            tmp_payload = payload + flag + char.encode()
            tmp_blocks = get_encrypted_block(r, tmp_payload.hex())
            
            if blocks[5] == tmp_blocks[5]:
                flag += char.encode()
                print("Flag:", flag.decode())
                length -= 1
                break
    r.close()

if __name__ == "__main__":
    main()