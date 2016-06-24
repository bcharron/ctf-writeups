CTF: Defcon Quals 2016
Challenge: step
Author: Benjamin Charron <bcharron@pobox.com>

Decompilation of two first functions from Hopper:
```c
void (*encoded_function)(char *key);

int main() {
	printf("Key1: ");
	rax = *stdout;
	fflush(rax);
	fgets(user_input, 0x6, *stdin);
	rcx = 0x49bf;
	decode_binary(encoded_data, 0x9e, user_input, rcx);

	encoded_function = (void *) 0x400e0e;
	encoded_function(user_input);
}
```

```c
int decode_binary(uint8_t * arg_encoded_data_ptr, int arg1, char * arg_key, int arg_checksum) {
	encoded_data_ptr = arg_encoded_data_ptr;
	encoded_data_len = arg1;
	key_ptr = arg_key;
	expected_checksum = arg_checksum;
	key_idx = 0x0;
	actual_checksum = 0x0;
	uint8_t *pos;

	for (pos = encoded_data_ptr; encoded_data_ptr + encoded_data_len > pos; pos = pos + 0x1) {
		*pos = *pos ^ *key_ptr[key_idx];
		actual_checksum = actual_checksum + *pos;

		// Is this just a signed modulo 4 ?  The key size would be 4 bytes, probably printable charaters.
		key_idx = ((SAR((key_idx & 0xff) + 0x1, 0x1f) >> 0x1e) + (key_idx & 0xff) + 0x1 & 0x3) - (SAR((key_idx & 0xff) + 0x1, 0x1f) >> 0x1e);
	}

	rax = actual_checksum;

	if (rax != expected_checksum) {
		printf("Failed");
		rax = exit(0x0);
	}
	return rax;
}
```

The program decodes its next function using an XOR with a user-specified key.
We have two hints to guess the key:

- There is a pseudo-checksum that has to match
- We can guess the prologue

Let's assume a typical prologue:

```asm
55             push rbp
48 89 e5       mov rbp, rsp
```

To find the XOR key, we xor the data at 0x00400e0e (07 27 fd a8) with what we think the data should be (I use R2 for this):

```
[0x00400fa6]> ? 0x554889e5 ^ 0x0727fda8
1383035981 0x526f744d 012233672115 1.3G 526f000:044d 1383035981 "MtoR" 01001101 1383035981.0 257112096768.000000f 0.000000
```

The key would be "RotM" ("MtoR" is reversed in memory). Sounds like a sensible acronym, "Return of the M??"..  let's try!

```
$ r2 -d ./step
Process with PID 26073 started...
Attached debugger to pid = 26073, tid = 26073
Debugging pid = 26073, tid = 26073 now
Using BADDR 0x400000
Assuming filepath ./step
bits 64
 -- r2 your penis
[0x7f9d074662d0]> Po step
Close current session? (Y/n)
Key1: Process with PID 26074 started...
Debugging pid = 26074, tid = 26074 now
Assuming filepath ./step
Attached debugger to pid = 26074, tid = 26074
Attached debugger to pid = 26074, tid = 26074
Attached debugger to pid = 26074, tid = 26074
[0x00400e0b]> db 0x00401019
[0x00400e0b]> dc
Key1: RotM
hit breakpoint at: 401019
Debugging pid = 26074, tid = 1 now
[0x00401b19]> pD 0x9e @ 0x00400e0e
    ; CALL XREF from 0x00401019 (unk)
    ; DATA XREF from 0x00401008 (unk)
            0x00400e0e      55             push rbp
            0x00400e0f      4889e5         mov rbp, rsp
            0x00400e12      4881ecb00000.  sub rsp, 0xb0
            0x00400e19      4889bd58ffff.  mov qword [rbp - 0xa8], rdi	; rdi = 0x7fffffffe310
            0x00400e20      64488b042528.  mov rax, qword fs:[0x28]    ; [0x28:8]=-1 ; '(' ; 40
            0x00400e29      488945f8       mov qword [rbp - 8], rax
            0x00400e2d      31c0           xor eax, eax
            0x00400e2f      488b8558ffff.  mov rax, qword [rbp - 0xa8]
            0x00400e36      b9c3490000     mov ecx, 0x49c3
            0x00400e3b      4889c2         mov rdx, rax
            0x00400e3e      beec000000     mov esi, 0xec               ; 236
            0x00400e43      bf36094000     mov edi, 0x400936
            0x00400e48      e816ffffff     call fcn.00400d63		; xor_decode_data()
            0x00400e4d      48c78560ffff.  mov qword [rbp - 0xa0], 0x400936 ; sigaction.sa_sigaction = 0x400936
            0x00400e58      c745e8040000.  mov dword [rbp - 0x18], 4	; ????? sigaction.sa_flags = SA_SIGINFO maybe?  The sigset_t is a big struct..
            0x00400e5f      488d8560ffff.  lea rax, [rbp - 0xa0]
            0x00400e66      4883c008       add rax, 8			; rax = &sigaction.sa_mask
            0x00400e6a      4889c7         mov rdi, rax
            0x00400e6d      e85ef9ffff     call sym.imp.sigfillset	; block every signal during execution of handler
            0x00400e72      488d8560ffff.  lea rax, [rbp - 0xa0]
            0x00400e79      ba00000000     mov edx, 0
            0x00400e7e      4889c6         mov rsi, rax
            0x00400e81      bf05000000     mov edi, 5			; 5 == SIGTRAP
            0x00400e86      e8d5f8ffff     call sym.imp.sigaction	sigaction(5, &(rbp - 0xa0), NULL)
            0x00400e8b      9c             pushfq
            0x00400e8c      58             pop rax
            0x00400e8d      480d00010000   or rax, 0x100		; set TRACE (Step?) flag
            0x00400e93      50             push rax
            0x00400e94      9d             popfq
	    0x00400e95      90             nop				; never breaks here; maybe one opcode before trace applies? 
									; or does it apply only after an instruction?
            0x00400e96      de8b45f8fe48   fimul word [rbx + 0x48fef845]
            0x00400e9c      330425280000.  xor eax, dword [0x28]
            0x00400ea3      d7             xlatb
            0x00400ea4      054dd6f8ff     add eax, 0xfff8d64d
            0x00400ea9      ff6368         jmp qword [rbx + 0x68]      ; rcx
```

Fuck yeah that looks legit :D  Well, until 0x00400e8b. Then it gets weird..
"fimul word [rbx + 0x48fef845]" doesn't look like a real instruction.

So it calls the xor_decode_data() again at 0x00400e48, decoding the stuff at
0x400936. 

In a nutshell, this function sets up a handler for SIGTRAP, then sets the Trace
flag via pushfq/pop/or/push/popfq. What it does is send a SIGTRAP at every
instruction. Everytime the program receives SIGTRAP, it calls the function at
0x400936.

We've already entered the key, let's see how it turns out once decoded:


```
[0x00400e2d]> pD 0xec @ 0x400936
    ;-- rdi:
            0x00400936      55             push rbp
            0x00400937      4889e5         mov rbp, rsp
            0x0040093a      4883ec50       sub rsp, 0x50
            0x0040093e      897dcc         mov dword [rbp - 0x34], edi
            0x00400941      488975c0       mov qword [rbp - 0x40], rsi
            0x00400945      488955b8       mov qword [rbp - 0x48], rdx
            0x00400949      64488b042528.  mov rax, qword fs:[0x28]    ; [0x28:8]=-1 ; '(' ; 40
            0x00400952      488945f8       mov qword [rbp - 8], rax
            0x00400956      31c0           xor eax, eax
            0x00400958      48b853494754.  movabs rax, 0x2050415254474953
            0x00400962      488945e0       mov qword [rbp - 0x20], rax
            0x00400966      c745e861740a.  mov dword [rbp - 0x18], 0xa7461 ; [0xa7461:4]=-1
            0x0040096d      488b45b8       mov rax, qword [rbp - 0x48]
            0x00400971      488945d8       mov qword [rbp - 0x28], rax
            0x00400975      488b05441720.  mov rax, qword [rip + 0x201744] ; [0x6020c0:8]=0
            0x0040097c      488905451720.  mov qword [rip + 0x201745], rax ; [0x6020c8:8]=0
            0x00400983      488b45d8       mov rax, qword [rbp - 0x28]
            0x00400987      488b80a80000.  mov rax, qword [rax + 0xa8] ; [0xa8:8]=-1 ; 168
            0x0040098e      4889052b1720.  mov qword [rip + 0x20172b], rax ; [0x6020c0:8]=0
            0x00400995      488b05241720.  mov rax, qword [rip + 0x201724] ; [0x6020c0:8]=0
            0x0040099c      483d35094000   cmp rax, 0x400935
        ┌─< 0x004009a2      7667           jbe 0x400a0b
        │   0x004009a4      488b05151720.  mov rax, qword [rip + 0x201715] ; [0x6020c0:8]=0
        │   0x004009ab      483d3d104000   cmp rax, 0x40103d
       ┌──< 0x004009b1      7758           ja 0x400a0b
       ││   0x004009b3      488b050e1720.  mov rax, qword [rip + 0x20170e] ; [0x6020c8:8]=0
       ││   0x004009ba      483d35094000   cmp rax, 0x400935
      ┌───< 0x004009c0      762b           jbe 0x4009ed
      │││   0x004009c2      488b05ff1620.  mov rax, qword [rip + 0x2016ff] ; [0x6020c8:8]=0
      │││   0x004009c9      483d3d104000   cmp rax, 0x40103d
     ┌────< 0x004009cf      771c           ja 0x4009ed
     ││││   0x004009d1      488b05f01620.  mov rax, qword [rip + 0x2016f0] ; [0x6020c8:8]=0
     ││││   0x004009d8      488b15e91620.  mov rdx, qword [rip + 0x2016e9] ; [0x6020c8:8]=0
     ││││   0x004009df      0fb60a         movzx ecx, byte [rdx]
     ││││   0x004009e2      488b15df1620.  mov rdx, qword [rip + 0x2016df] ; [0x6020c8:8]=0
     ││││   0x004009e9      31ca           xor edx, ecx
     ││││   0x004009eb      8810           mov byte [rax], dl
     └└───> 0x004009ed      488b05cc1620.  mov rax, qword [rip + 0x2016cc] ; [0x6020c0:8]=0
       ││   0x004009f4      488b15c51620.  mov rdx, qword [rip + 0x2016c5] ; [0x6020c0:8]=0
       ││   0x004009fb      0fb60a         movzx ecx, byte [rdx]
       ││   0x004009fe      488b15bb1620.  mov rdx, qword [rip + 0x2016bb] ; [0x6020c0:8]=0
       ││   0x00400a05      31ca           xor edx, ecx
       ││   0x00400a07      8810           mov byte [rax], dl
      ┌───< 0x00400a09      eb01           jmp 0x400a0c
      │└└─> 0x00400a0b      90             nop
      └───> 0x00400a0c      488b45f8       mov rax, qword [rbp - 8]
            0x00400a10      644833042528.  xor rax, qword fs:[0x28]
        ┌─< 0x00400a19      7405           je 0x400a20
        │   0x00400a1b      e860fdffff     call sym.imp.__stack_chk_fail
        └─> 0x00400a20      c9             leave
            0x00400a21      c3             ret
```

This function decodes the instruction that was about to be executed when TRAP
was sent.

The function should have the following prototype:

```c
             void    (*__sa_sigaction)(int, siginfo_t *, void *);
```

where the last argument is a context.

The debugger is making it hard to get to break at 0x00400936 since it
interferes with the SIGTRAP. In r2, we just deliver the signal to the process
and keep tracing. The problem is that the signal decodes one instruction at a
time, so it's hard to set a breakpoint and examine what it's doing.

```
[0x00400e3e]> db 0x400936
[0x00400e3e]> di
type=step
signal=SIGTRAP
signum=5
sigpid=13185
addr=0x400e3e
inbp=true
pid=13185
tid=1
cmdline=./step
stopreason=5
[0x00400e3e]> dck 5 $P

            0x7fd1f53b8d40      48c7c00f0000.  mov rax, 0xf            ; rax                                                                                    
            0x7fd1f53b8d47      0f05           syscall                                                                                                          


      ││    0x004009fb      0fb60a         movzx ecx, byte [rdx]                                                                                                
      ││    0x004009fe      488b15bb1620.  mov rdx, qword [rip + 0x2016bb] ; [0x6020c0:8]=0x400e96 rdx                                                          
      ││    0x00400a05      31ca           xor edx, ecx                                                                                                         
      ││    0x00400a07      8810           mov byte [rax], dl                                                                                                   

[0x400e96] is now 0x48

; step out of the routine..

[0x7fee3daead40]> as 15
15 = sigreturn (0x7ffed201e970)
```


# Use hardware handlers
```
[0x7f060703d2d0]> drx 2 0x400936 1 x
[0x7f060703d2d0]> dko 5 cont
```

Hmm. This is annoying.. all I want is to let the program run normally until
just before it exits. What about hooking exit()?  When the program calls
exit(), we'll intercept the call and spawn a shell instead. From there we can
inspect the program's state.

```
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

unsigned int exit(unsigned int n) {
	int x;
	unsigned char *data = 0x004009fb;
	int pid;
	char *new_argv[] = {
		"/bin/bash",
		NULL
	};

	pid = fork();

	if (pid == 0) {
		execve("/bin/bash", new_argv, NULL);
	} else {
		printf("Waiting.\n");
		wait(&x);
		printf("Leaving.\n");
	}
}
```

```
$ gcc -fPIC -shared fake_exit.c -o pre.so
$ LD_PRELOAD=./pre.so ./step
Key1: RotM
fake exit(1)
Waiting.
```

Cool, now we can inspect the parent pid with (supposedly) everything unpacked.

```
# need sudo because of kernel.yama.ptrace_scope
sudo r2 -d 14097
...
[0x00400929]> dbt
0  0x2aaaaaf92ab2  sp: 0x0  0   rip map._lib_x86_64_linux_gnu_libc_2.19.so._r_x+789170
1  0x2aaaaacd0a2b  sp: 0x7fffffffe218  0   map._home_bcharron_re_ctf_defcon_2016_quals_reverse_engineering_pre.so._r_x+2603 
2  0x00400efd  sp: 0x7fffffffe268  80   r12+1725 
3  0x2aaaaaef3ec5  sp: 0x7fffffffe2f8  144   map._lib_x86_64_linux_gnu_libc_2.19.so._r_x+138949 
4  0x00400869  sp: 0x7fffffffe3b8  192   r12+41 

# Cool, let's see what it was doing at 0x00400869
[0x00400929]> s 0x00400869 - 64
[0x00400829]> pD 64
<snip>
    ;-- r12:
            0x00400840      31ed           xor ebp, ebp
            0x00400842      4989d1         mov r9, rdx
            0x00400845      5e             pop rsi
            0x00400846      4889e2         mov rdx, rsp
            0x00400849      4883e4f0       and rsp, 0xfffffffffffffff0
            0x0040084d      50             push rax
            0x0040084e      54             push rsp
            0x0040084f      49c7c0c01040.  mov r8, 0x4010c0
            0x00400856      48c7c1501040.  mov rcx, 0x401050
            0x0040085d      48c7c7a60f40.  mov rdi, 0x400fa6
            0x00400864      e837ffffff     call 0x4007a0
```

argh! It's wiping ebp and changing RSP, so forget about the stack trace :(
Looks like they anticipated this.


Ok, let's go back to debugging then. Let's create a small r2pipe script that
dumps the instruction at the previous %RIP every time SIGTRAP is hit (so that
we get the decoded version). (See do-step-r2pipe.py)  We won't have the values
of the registers, but at least we'll see the progress.

The main part of our script looks like this:

```python
self.fd = open("trace.asm", "w+")

while True:
	if self.prev_rip > 0:
		# Show last instruction, which should be decoded now
		x = self.r2.cmd("pd 1 @ 0x%08X" % self.prev_rip)
		self.fd.write(x)

	# Save %RIP for next time
	self.prev_rip = rip

	# Send SIGTRAP to program and continue until next TRAP
	self.r2.cmd("dck 5 %s" % self.pid)

```

Here is the output from trace.asm, with most 0x7ffff (glibc and ld.so) removed:
```
            0x00400e96      488b45f8       mov rax, qword [rbp - 8]
            0x00400e9a      644833042528.  xor rax, qword fs:[0x28]
            0x00400ea3      7405           je 0x400eaa
            0x00400eaa      c9             leave
            0x00400eab      c3             ret
            0x0040101e      e889feffff     call 0x400eac
            0x00400eac      55             push rbp
            0x00400ead      4889e5         mov rbp, rsp
            0x00400eb0      4883ec60       sub rsp, 0x60
            0x00400eb4      64488b042528.  mov rax, qword fs:[0x28]    ; [0x28:8]=-1 ; '(' ; 40
            0x00400ebd      488945f8       mov qword [rbp - 8], rax
            0x00400ec1      31c0           xor eax, eax
            0x00400ec3      c645b066       mov byte [rbp - 0x50], 0x66 ; [0x66:1]=255 ; 'f' ; 102
            0x00400ec7      c645b16c       mov byte [rbp - 0x4f], 0x6c ; [0x6c:1]=255 ; 'l' ; 108
            0x00400ecb      c645b261       mov byte [rbp - 0x4e], 0x61 ; [0x61:1]=255 ; 'a' ; 97
            0x00400ecf      c645b367       mov byte [rbp - 0x4d], 0x67 ; [0x67:1]=255 ; 'g' ; 103
            0x00400ed3      c645b400       mov byte [rbp - 0x4c], 0
            0x00400ed7      488d45b0       lea rax, [rbp - 0x50]
            0x00400edb      bedb104000     mov esi, 0x4010db           ; "r" @ 0x4010db
            0x00400ee0      4889c7         mov rdi, rax
            0x00400ee3      e818f9ffff     call sym.imp.fopen
    ;-- imp.fopen:
            0x00400800      ff256a182000   jmp qword [rip + 0x20186a]  ; [0x602070:8]=0x400806 rip LEA reloc.fopen_112 ; reloc.fopen_112
            0x00400806      680b000000     push 0xb ; orax             ; 11
            0x0040080b      e930ffffff     jmp 0x400740
    ;-- section..plt:
            0x00400740      ff35c2182000   push qword [rip + 0x2018c2] ; [11] va=0x00400740 pa=0x00000740 sz=240 vsz=240 rwx=--r-x .plt
            0x00400746      ff25c4182000   jmp qword [rip + 0x2018c4]  ; [0x602010:8]=0x7ffff7df04e0 rip

[snip 50,000 linker instructions]

            0x00400ee8      488945a8       mov qword [rbp - 0x58], rax
            0x00400eec      48837da800     cmp qword [rbp - 0x58], 0
            0x00400ef1      750a           jne 0x400efd
            0x00400efd      488b45a8       mov rax, qword [rbp - 0x58]
            0x00400f01      4889c2         mov rdx, rax
            0x00400f04      be40000000     mov esi, 0x40               ; rsi
            0x00400f09      bfe0206000     mov edi, 0x6020e0           ; rdi. Put flag at 0x6020e0, up to 0x40 bytes
            0x00400f0e      e8adf8ffff     call sym.imp.fgets
            0x00400f13      488b45a8       mov rax, qword [rbp - 0x58]
            0x00400f17      4889c7         mov rdi, rax
            0x00400f1a      e851f8ffff     call sym.imp.fclose
    ;-- imp.fclose:
            0x00400770      ff25b2182000   jmp qword [rip + 0x2018b2]  ; [0x602028:8]=0x400776 rip LEA reloc.fclose_40 ; "v.@" @ 0x602028
            0x00400776      6802000000     push 2 ; orax               ; 2
            0x0040077b      e9c0ffffff     jmp 0x400740
    ;-- section..plt:
            0x00400740      ff35c2182000   push qword [rip + 0x2018c2] ; [11] va=0x00400740 pa=0x00000740 sz=240 vsz=240 rwx=--r-x .plt

            0x00400f1f      c645c04b       mov byte [rbp - 0x40], 0x4b ; [0x4b:1]=255 ; 'K' ; 75
            0x00400f23      c645c165       mov byte [rbp - 0x3f], 0x65 ; [0x65:1]=255 ; 'e' ; 101
            0x00400f27      c645c279       mov byte [rbp - 0x3e], 0x79 ; [0x79:1]=255 ; 'y' ; 121
            0x00400f2b      c645c332       mov byte [rbp - 0x3d], 0x32 ; [0x32:1]=255 ; '2' ; 50
            0x00400f2f      c645c43a       mov byte [rbp - 0x3c], 0x3a ; [0x3a:1]=255 ; ':' ; 58
            0x00400f33      c645c520       mov byte [rbp - 0x3b], 0x20 ; [0x20:1]=255 ; 32
            0x00400f37      c645c600       mov byte [rbp - 0x3a], 0
            0x00400f3b      488d45c0       lea rax, [rbp - 0x40]
            0x00400f3f      4889c7         mov rdi, rax
            0x00400f42      b800000000     mov eax, 0
            0x00400f47      e844f8ffff     call sym.imp.printf

            0x00400f53      4889c7         mov rdi, rax
            0x00400f56      e885f8ffff     call sym.imp.fflush

            0x00400f62      488d45d0       lea rax, [rbp - 0x30]	; fgets buffer address
            0x00400f66      be20000000     mov esi, 0x20               ; rsi
            0x00400f6b      4889c7         mov rdi, rax
            0x00400f6e      e84df8ffff     call sym.imp.fgets

            0x00400f73      c645ef00       mov byte [rbp - 0x11], 0
            0x00400f77      488d45d0       lea rax, [rbp - 0x30]	; user input ptr
            0x00400f7b      4889c7         mov rdi, rax
            0x00400f7e      e89ffaffff     call 0x400a22

            0x00400a22      55             push rbp
            0x00400a23      4889e5         mov rbp, rsp
            0x00400a26      4883ec50       sub rsp, 0x50
            0x00400a2a      48897db8       mov qword [rbp - 0x48], rdi	; rbp-0x48 = user input
            0x00400a2e      64488b042528.  mov rax, qword fs:[0x28]    ; [0x28:8]=-1 ; '(' ; 40
            0x00400a37      488945f8       mov qword [rbp - 8], rax
            0x00400a3b      31c0           xor eax, eax
            0x00400a3d      488d45d0       lea rax, [rbp - 0x30]	; prepare a 32-byte buffer at rbp-0x30
            0x00400a41      be20000000     mov esi, 0x20               ; rsi
            0x00400a46      4889c7         mov rdi, rax
            0x00400a49      e8c2fdffff     call sym.imp.bzero

    ;-- imp.bzero:
            0x00400810      ff2562182000   jmp qword [rip + 0x201862]  ; [0x602078:8]=0x400816 rip LEA reloc.bzero_120 ; reloc.bzero_120
            0x00400816      680c000000     push 0xc ; orax             ; 12
            0x0040081b      e920ffffff     jmp 0x400740
    ;-- section..plt:
            0x00400740      ff35c2182000   push qword [rip + 0x2018c2] ; [11] va=0x00400740 pa=0x00000740 sz=240 vsz=240 rwx=--r-x .plt


            0x00400a4e      c645cf00       mov byte [rbp - 0x31], 0	; rbp-0x31 is a counter (0-31)
            0x00400a52      e996010000     jmp 0x400bed
            0x00400bed      807dcf1f       cmp byte [rbp - 0x31], 0x1f ; [0x1f:1]=255 ; 31
            0x00400bf1      0f8660feffff   jbe 0x400a57
            0x00400a57      0fb655cf       movzx edx, byte [rbp - 0x31]		; edx = counter
            0x00400a5b      0fb645cf       movzx eax, byte [rbp - 0x31]
            0x00400a5f      4898           cdqe
            0x00400a61      0fb67405d0     movzx esi, byte [rbp + rax - 0x30]	; 32-byte buffer
            0x00400a66      0fb64dcf       movzx ecx, byte [rbp - 0x31]		; ecx = counter
            0x00400a6a      488b45b8       mov rax, qword [rbp - 0x48]		; rax = user input
            0x00400a6e      4801c8         add rax, rcx				; rax = &user_input[ecx]
            0x00400a71      0fb600         movzx eax, byte [rax]		; al = user_input[ecx]
            0x00400a74      c0e807         shr al, 7				; bit 7, move to bit 0
            0x00400a77      09c6           or esi, eax				; 
            0x00400a79      89f1           mov ecx, esi				
            0x00400a7b      4863c2         movsxd rax, edx			; rax = counter
            0x00400a7e      884c05d0       mov byte [rbp + rax - 0x30], cl	; user_input[counter] = &buf[0] or &buf[1]
            0x00400a82      0fb655cf       movzx edx, byte [rbp - 0x31]		; edx = counter
            0x00400a86      0fb645cf       movzx eax, byte [rbp - 0x31]		; eax = counter
            0x00400a8a      4898           cdqe
            0x00400a8c      0fb64405d0     movzx eax, byte [rbp + rax - 0x30]	; eax = user_input[counter]
            0x00400a91      89c6           mov esi, eax
            0x00400a93      0fb64dcf       movzx ecx, byte [rbp - 0x31]		; ecx = counter
            0x00400a97      488b45b8       mov rax, qword [rbp - 0x48]		; rax = &user_input[0]
            0x00400a9b      4801c8         add rax, rcx				; rax = &user_input[counter]
            0x00400a9e      0fb600         movzx eax, byte [rax]		; eax = user_input[counter]
            0x00400aa1      0fb6c0         movzx eax, al
            0x00400aa4      83e040         and eax, 0x40			; bit 6
            0x00400aa7      d1f8           sar eax, 1				; move to bit 5
            0x00400aa9      09f0           or eax, esi
            0x00400aab      89c1           mov ecx, eax
            0x00400aad      4863c2         movsxd rax, edx
            0x00400ab0      884c05d0       mov byte [rbp + rax - 0x30], cl	; buf[counter] = cl
            0x00400ab4      0fb655cf       movzx edx, byte [rbp - 0x31]
            0x00400ab8      0fb645cf       movzx eax, byte [rbp - 0x31]
            0x00400abc      4898           cdqe
            0x00400abe      0fb64405d0     movzx eax, byte [rbp + rax - 0x30]
            0x00400ac3      89c6           mov esi, eax
            0x00400ac5      0fb64dcf       movzx ecx, byte [rbp - 0x31]
            0x00400ac9      488b45b8       mov rax, qword [rbp - 0x48]
            0x00400acd      4801c8         add rax, rcx
            0x00400ad0      0fb600         movzx eax, byte [rax]
            0x00400ad3      0fb6c0         movzx eax, al
            0x00400ad6      83e020         and eax, 0x20			; bit 5
            0x00400ad9      01c0           add eax, eax				; move to bit 6
            0x00400adb      09f0           or eax, esi
            0x00400add      89c1           mov ecx, eax
            0x00400adf      4863c2         movsxd rax, edx
            0x00400ae2      884c05d0       mov byte [rbp + rax - 0x30], cl
            0x00400ae6      0fb655cf       movzx edx, byte [rbp - 0x31]
            0x00400aea      0fb645cf       movzx eax, byte [rbp - 0x31]
            0x00400aee      4898           cdqe
            0x00400af0      0fb64405d0     movzx eax, byte [rbp + rax - 0x30]
            0x00400af5      89c6           mov esi, eax
            0x00400af7      0fb64dcf       movzx ecx, byte [rbp - 0x31]
            0x00400afb      488b45b8       mov rax, qword [rbp - 0x48]
            0x00400aff      4801c8         add rax, rcx
            0x00400b02      0fb600         movzx eax, byte [rax]
            0x00400b05      0fb6c0         movzx eax, al
            0x00400b08      83e010         and eax, 0x10			; bit 4
            0x00400b0b      c1f803         sar eax, 3				; move to bit 1
            0x00400b0e      09f0           or eax, esi
            0x00400b10      89c1           mov ecx, eax
            0x00400b12      4863c2         movsxd rax, edx
            0x00400b15      884c05d0       mov byte [rbp + rax - 0x30], cl
            0x00400b19      0fb655cf       movzx edx, byte [rbp - 0x31]
            0x00400b1d      0fb645cf       movzx eax, byte [rbp - 0x31]
            0x00400b21      4898           cdqe
            0x00400b23      0fb64405d0     movzx eax, byte [rbp + rax - 0x30]
            0x00400b28      89c6           mov esi, eax
            0x00400b2a      0fb64dcf       movzx ecx, byte [rbp - 0x31]
            0x00400b2e      488b45b8       mov rax, qword [rbp - 0x48]
            0x00400b32      4801c8         add rax, rcx
            0x00400b35      0fb600         movzx eax, byte [rax]
            0x00400b38      0fb6c0         movzx eax, al
            0x00400b3b      83e008         and eax, 8				; bit 3
            0x00400b3e      c1e004         shl eax, 4				; move to bit 7
            0x00400b41      09f0           or eax, esi
            0x00400b43      89c1           mov ecx, eax
            0x00400b45      4863c2         movsxd rax, edx
            0x00400b48      884c05d0       mov byte [rbp + rax - 0x30], cl
            0x00400b4c      0fb655cf       movzx edx, byte [rbp - 0x31]
            0x00400b50      0fb645cf       movzx eax, byte [rbp - 0x31]
            0x00400b54      4898           cdqe
            0x00400b56      0fb64405d0     movzx eax, byte [rbp + rax - 0x30]
            0x00400b5b      89c6           mov esi, eax
            0x00400b5d      0fb64dcf       movzx ecx, byte [rbp - 0x31]
            0x00400b61      488b45b8       mov rax, qword [rbp - 0x48]
            0x00400b65      4801c8         add rax, rcx
            0x00400b68      0fb600         movzx eax, byte [rax]
            0x00400b6b      0fb6c0         movzx eax, al
            0x00400b6e      83e004         and eax, 4				; bit 2
            0x00400b71      01c0           add eax, eax				; move to bit 3
            0x00400b73      09f0           or eax, esi
            0x00400b75      89c1           mov ecx, eax
            0x00400b77      4863c2         movsxd rax, edx
            0x00400b7a      884c05d0       mov byte [rbp + rax - 0x30], cl
            0x00400b7e      0fb655cf       movzx edx, byte [rbp - 0x31]
            0x00400b82      0fb645cf       movzx eax, byte [rbp - 0x31]
            0x00400b86      4898           cdqe
            0x00400b88      0fb64405d0     movzx eax, byte [rbp + rax - 0x30]
            0x00400b8d      89c6           mov esi, eax
            0x00400b8f      0fb64dcf       movzx ecx, byte [rbp - 0x31]
            0x00400b93      488b45b8       mov rax, qword [rbp - 0x48]
            0x00400b97      4801c8         add rax, rcx
            0x00400b9a      0fb600         movzx eax, byte [rax]
            0x00400b9d      0fb6c0         movzx eax, al
            0x00400ba0      83e002         and eax, 2				; bit 1
            0x00400ba3      01c0           add eax, eax				; move to bit 2
            0x00400ba5      09f0           or eax, esi
            0x00400ba7      89c1           mov ecx, eax
            0x00400ba9      4863c2         movsxd rax, edx
            0x00400bac      884c05d0       mov byte [rbp + rax - 0x30], cl
            0x00400bb0      0fb655cf       movzx edx, byte [rbp - 0x31]
            0x00400bb4      0fb645cf       movzx eax, byte [rbp - 0x31]
            0x00400bb8      4898           cdqe
            0x00400bba      0fb64405d0     movzx eax, byte [rbp + rax - 0x30]
            0x00400bbf      89c6           mov esi, eax
            0x00400bc1      0fb64dcf       movzx ecx, byte [rbp - 0x31]
            0x00400bc5      488b45b8       mov rax, qword [rbp - 0x48]
            0x00400bc9      4801c8         add rax, rcx
            0x00400bcc      0fb600         movzx eax, byte [rax]
            0x00400bcf      0fb6c0         movzx eax, al
            0x00400bd2      83e001         and eax, 1				; bit 0
            0x00400bd5      c1e004         shl eax, 4				; move to bit 4
            0x00400bd8      09f0           or eax, esi
            0x00400bda      89c1           mov ecx, eax
            0x00400bdc      4863c2         movsxd rax, edx
            0x00400bdf      884c05d0       mov byte [rbp + rax - 0x30], cl
            0x00400be3      0fb645cf       movzx eax, byte [rbp - 0x31]
            0x00400be7      83c001         add eax, 1
            0x00400bea      8845cf         mov byte [rbp - 0x31], al
            0x00400bed      807dcf1f       cmp byte [rbp - 0x31], 0x1f ; [0x1f:1]=255 ; 31
            0x00400bf1      0f8660feffff   jbe 0x400a57

[snip the 31 other parts of the loop]

            0x00400bf7      488b45b8       mov rax, qword [rbp - 0x48]		; rax = user_input
            0x00400bfb      488b55d0       mov rdx, qword [rbp - 0x30]		; rdx = buf
            0x00400bff      488910         mov qword [rax], rdx			; user_input = buf
            0x00400c02      488b55d8       mov rdx, qword [rbp - 0x28]		; ? part of user_input ?
            0x00400c06      48895008       mov qword [rax + 8], rdx
            0x00400c0a      488b55e0       mov rdx, qword [rbp - 0x20]
            0x00400c0e      48895010       mov qword [rax + 0x10], rdx
            0x00400c12      488b55e8       mov rdx, qword [rbp - 0x18]
            0x00400c16      48895018       mov qword [rax + 0x18], rdx
            0x00400c1a      90             nop
            0x00400c1b      488b45f8       mov rax, qword [rbp - 8]
            0x00400c1f      644833042528.  xor rax, qword fs:[0x28]
            0x00400c28      7405           je 0x400c2f
            0x00400c2f      c9             leave
            0x00400c30      c3             ret
            0x00400f83      488d45d0       lea rax, [rbp - 0x30]
            0x00400f87      4889c7         mov rdi, rax			; rdi = buf
            0x00400f8a      e8a2fcffff     call 0x400c31


            0x00400c31      55             push rbp
            0x00400c32      4889e5         mov rbp, rsp
            0x00400c35      4883ec50       sub rsp, 0x50
            0x00400c39      48897db8       mov qword [rbp - 0x48], rdi	; decoded buf
            0x00400c3d      64488b042528.  mov rax, qword fs:[0x28]    ; [0x28:8]=-1 ; '(' ; 40
            0x00400c46      488945f8       mov qword [rbp - 8], rax
            0x00400c4a      31c0           xor eax, eax
            0x00400c4c      c645c06e       mov byte [rbp - 0x40], 0x6e ; [0x6e:1]=255 ; 'n' ; 110
            0x00400c50      c645c16f       mov byte [rbp - 0x3f], 0x6f ; [0x6f:1]=255 ; 'o' ; 111
            0x00400c54      c645c270       mov byte [rbp - 0x3e], 0x70 ; [0x70:1]=255 ; 'p' ; 112
            0x00400c58      c645c365       mov byte [rbp - 0x3d], 0x65 ; [0x65:1]=255 ; 'e' ; 101
            0x00400c5c      c645c40a       mov byte [rbp - 0x3c], 0xa
            0x00400c60      c645c500       mov byte [rbp - 0x3b], 0
            0x00400c64      c645d050       mov byte [rbp - 0x30], 0x50 ; [0x50:1]=255 ; 'P' ; 80		bit 4 & 6 : "!"
            0x00400c68      c645d16c       mov byte [rbp - 0x2f], 0x6c ; [0x6c:1]=255 ; 'l' ; 108		bit 6, 5, 2, 3: 
            0x00400c6c      c645d265       mov byte [rbp - 0x2e], 0x65 ; [0x65:1]=255 ; 'e' ; 101
            0x00400c70      c645d361       mov byte [rbp - 0x2d], 0x61 ; [0x61:1]=255 ; 'a' ; 97
            0x00400c70      c645d361       mov byte [rbp - 0x2d], 0x61 ; [0x61:1]=255 ; 'a' ; 97
            0x00400c74      c645d473       mov byte [rbp - 0x2c], 0x73 ; [0x73:1]=255 ; 's' ; 115
            0x00400c78      c645d565       mov byte [rbp - 0x2b], 0x65 ; [0x65:1]=255 ; 'e' ; 101
            0x00400c7c      c645d62c       mov byte [rbp - 0x2a], 0x2c ; [0x2c:1]=255 ; ',' ; 44
            0x00400c80      c645d720       mov byte [rbp - 0x29], 0x20 ; [0x20:1]=255 ; 32
            0x00400c84      c645d86d       mov byte [rbp - 0x28], 0x6d ; [0x6d:1]=255 ; 'm' ; 109
            0x00400c88      c645d961       mov byte [rbp - 0x27], 0x61 ; [0x61:1]=255 ; 'a' ; 97
            0x00400c8c      c645da79       mov byte [rbp - 0x26], 0x79 ; [0x79:1]=255 ; 'y' ; 121
            0x00400c90      c645db20       mov byte [rbp - 0x25], 0x20 ; [0x20:1]=255 ; 32
            0x00400c94      c645dc49       mov byte [rbp - 0x24], 0x49 ; [0x49:1]=255 ; 'I' ; 73
            0x00400c98      c645dd20       mov byte [rbp - 0x23], 0x20 ; [0x20:1]=255 ; 32
            0x00400c9c      c645de68       mov byte [rbp - 0x22], 0x68 ; [0x68:1]=255 ; 'h' ; 104
            0x00400ca0      c645df61       mov byte [rbp - 0x21], 0x61 ; [0x61:1]=255 ; 'a' ; 97
            0x00400ca4      c645e076       mov byte [rbp - 0x20], 0x76 ; [0x76:1]=255 ; 'v' ; 118
            0x00400ca8      c645e165       mov byte [rbp - 0x1f], 0x65 ; [0x65:1]=255 ; 'e' ; 101
            0x00400cac      c645e220       mov byte [rbp - 0x1e], 0x20 ; [0x20:1]=255 ; 32
            0x00400cb0      c645e374       mov byte [rbp - 0x1d], 0x74 ; [0x74:1]=255 ; 't' ; 116
            0x00400cb4      c645e468       mov byte [rbp - 0x1c], 0x68 ; [0x68:1]=255 ; 'h' ; 104
            0x00400cb8      c645e565       mov byte [rbp - 0x1b], 0x65 ; [0x65:1]=255 ; 'e' ; 101
            0x00400cbc      c645e620       mov byte [rbp - 0x1a], 0x20 ; [0x20:1]=255 ; 32
            0x00400cc0      c645e766       mov byte [rbp - 0x19], 0x66 ; [0x66:1]=255 ; 'f' ; 102
            0x00400cc4      c645e86c       mov byte [rbp - 0x18], 0x6c ; [0x6c:1]=255 ; 'l' ; 108
            0x00400cc8      c645e961       mov byte [rbp - 0x17], 0x61 ; [0x61:1]=255 ; 'a' ; 97
            0x00400ccc      c645ea67       mov byte [rbp - 0x16], 0x67 ; [0x67:1]=255 ; 'g' ; 103
            0x00400cd0      c645eb20       mov byte [rbp - 0x15], 0x20 ; [0x20:1]=255 ; 32
            0x00400cd4      c645ec6e       mov byte [rbp - 0x14], 0x6e ; [0x6e:1]=255 ; 'n' ; 110
            0x00400cd8      c645ed6f       mov byte [rbp - 0x13], 0x6f ; [0x6f:1]=255 ; 'o' ; 111
            0x00400cdc      c645ee77       mov byte [rbp - 0x12], 0x77 ; [0x77:1]=255 ; 'w' ; 119
            0x00400ce0      c645ef00       mov byte [rbp - 0x11], 0
            0x00400ce4      488d4dd0       lea rcx, [rbp - 0x30]	; "Please, may I have the flag now"
            0x00400ce8      488b45b8       mov rax, qword [rbp - 0x48]
            0x00400cec      ba20000000     mov edx, 0x20               ; rdx
            0x00400cf1      4889ce         mov rsi, rcx
            0x00400cf4      4889c7         mov rdi, rax
            0x00400cf7      e8b4faffff     call sym.imp.memcmp		; compare buf with 

    ;-- imp.memcmp:
            0x004007b0      ff2592182000   jmp qword [rip + 0x201892]  ; [0x602048:8]=0x4007b6 rip LEA reloc.memcmp_72 ; reloc.memcmp_72
            0x004007b6      6806000000     push 6 ; orax               ; 6
            0x004007bb      e980ffffff     jmp 0x400740
    ;-- section..plt:
            0x00400740      ff35c2182000   push qword [rip + 0x2018c2] ; [11] va=0x00400740 pa=0x00000740 sz=240 vsz=240 rwx=--r-x .plt
            0x00400746      ff25c4182000   jmp qword [rip + 0x2018c4]  ; [0x602010:8]=0x7ffff7df04e0 rip
[snip]
            0x00400d1d      90             nop
            0x00400d1e      488b45f8       mov rax, qword [rbp - 8]
            0x00400d22      644833042528.  xor rax, qword fs:[0x28]
            0x00400d2b      7405           je 0x400d32
            0x00400d32      c9             leave
            0x00400d33      c3             ret
            0x00400f8f      90             nop
            0x00400f90      488b45f8       mov rax, qword [rbp - 8]
            0x00400f94      644833042528.  xor rax, qword fs:[0x28]
            0x00400f9d      7405           je 0x400fa4
            0x00400fa4      c9             leave
            0x00400fa5      c3             ret
            0x00401023      b800000000     mov eax, 0
            0x00401028      488b4df8       mov rcx, qword [rbp - 8]
            0x0040102c      6448330c2528.  xor rcx, qword fs:[0x28]
            0x00401035      7405           je 0x40103c
            0x0040103c      c9             leave
            0x0040103d      c3             ret

```

The second key check boils down to this:

```c
f = fopen("flag", "r)
fgets(flag_data, 0x40, f);
fclose(f);

char buf[32];
bzero(buf, 32);

fgets(user_input, x, stdin);

for (i = 0; i < 31; i++) {
	c = user_input[i];
	buf[i] = (c & 0x01) << 3 | (c & 0x02) << 1 | (c & 0x04) << 1 | (c & 0x08) << 5 | (c & 0x10) >> 3 | (c & 0x20) << 1 | (c & 0x40) >> 1 | (c & 80) >> 7;
}

if (memcmp("Please, may I have the flag now", buf) == 0) {
	printf("%s", flag_data);
} else {
	printf("nope\n");
}
```

Let's create a small script to find the key that translates to "Please, may I have the flag now":

```python
TARGET = "Please, may I have the flag now"

MASKS = [
        4, # bit 0 becomes bit 4
        2, # bit 1 becomes bit 2
        3, # bit 2 becomes bit 3
        7, # bit 3 becomes bit 7
        1, # bit 4 becomes bit 1
        6, # bit 5 becomes bit 6
        5, # bit 6 becomes bit 5
        0, # bit 7 becomes bit 0
]

reverse_masks = [None] * 8

for idx in range(len(MASKS)):
        new_bit = MASKS[idx]
        reverse_masks[new_bit] = idx

result = ""
for c in TARGET:
        i = ord(c)

        out = 0

        for bit in range(8):
                byte = 1 << bit

                if i & byte:
                        out |= 1 << reverse_masks[bit]

        result = result + chr(out)

print result
```

Which produces the following result:
```bash
 ./step-step2.py  | xxd
0000000: 2166 e2e0 f1e2 4640 e6e0 e540 a440 64e0  !f....F@...@.@d.
0000010: 73e2 4063 64e2 4072 66e0 f240 76f6 f30a  s.@cd.@rf..@v...
```

So, we send "RotM" to the first check and that string to the second check and we get the flag!

