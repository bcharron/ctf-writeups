Hack in the box 2014 - bin100 - bcharron@pobox.com

First thing noticed: there doesn't seem to be any input to this program. It doesn't
read a file, read input or take arguments from the command-line.

The value of time() being sub'd from 0xdefaced is weird, because it's added right back after. Why bother?  The srand()
is not going to be random at all!  Ohhh! Ok, I get it now :)  It wasn't meant to be!

Everything is in main(), and it ends with "OK YOU WIN. HERE'S YOUR FLAG", followed by
xor decoding of a string.

There are quite a few loops, the outter one running 0x31337 times. 

This sequence looks weird at first, but it's just comparing the counter in r12 to the length of a string:

	0000000000400783 4883C9FF                        or         rcx, 0xffffffffffffffff ; XREF=main+134
	0000000000400787 31C0                            xor        eax, eax
	0000000000400789 4C89EF                          mov        rdi, r13
	000000000040078c F2AE                            repne scasb al, byte [ds:rdi]
	000000000040078e 4489E6                          mov        esi, r12d
	0000000000400791 4D63FC                          movsxd     r15, r12d
	0000000000400794 48F7D1                          not        rcx
	0000000000400797 48FFC9                          dec        rcx
	000000000040079a 4939CC                          cmp        r12, rcx
	000000000040079d 72A9                            jb         0x400748

There's a shitload of hardcoded strings, with the symbol "funny", referenced at 000000000040073e.


Running the program once, it becomes clearer. It shows a song, one line at a time. At the end, it shows the decoded key.

But can't wait for it, sleep(1) for every line would take more than 2 days (201527 seconds). Well ok I could actually wait for it,
but the timing of sleep() isn't perfect, at some point it's going to skip one second and fuck everything. Plus, where's the fun in that :)

So I nop-out sleep(1) and run it. The output is garbage :(   Ah, of course, 0x31337 seconds didn't elapse, so the srand() didn't get the proper values. I need to increase the number of seconds everytime sleep() is called.

I started with replacing the first time call with "xor r11,r11". Then I would have replaced the second (inside the loop) time() call with "mov rax, r11", and sleep(1) with "inc r11". But after overwriting the wrong offset with r2, I thought "this sucks, I'll just write a preload":

```c
	#include <stdio.h>
	#include <time.h>

	static long fake_t = 0;

	time_t time(time_t *t) {
		// printf("fake time(%ld)\n", fake_t);
		return(fake_t);
	}

	unsigned int sleep(unsigned int seconds) {
		// printf("fake sleep()\n");
		fake_t++;
	}
```

```bash
gcc -fPIC -shared time_preload.c -o pre.so

export LD_PRELOAD=./pre.so
./hitb-bin100.elf.bak | tail -n 100
[...]
 ♫                                    tHiS sOME 99 tHROWBACK sHiT tHAT iM sCREAMiNG ♫
KEY: 19 8f 67 74 c9 68 e6 0c 6f 54 1a 43 af 7b 5f b3 5c 01 98 58 68 56 1a 5e 31 0c 46 29 b8 a8 93 fc bf f9 70 5e 
OK YOU WIN. HERE'S YOUR FLAG: p4ul_1z_d34d_1z_wh4t_th3_r3c0rd_s4ys
```
