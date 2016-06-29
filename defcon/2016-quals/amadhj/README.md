```
CTF: Defcon Quals 2016
Challenge: amadhj
Author: Benjamin Charron <bcharron@pobox.com>
```

The binary is accompanied by this:
```
Reverse me and get the flag. Get it here. Service here amadhj_b76a229964d83e06b7978d0237d4d2b0.quals.shallweplayaga.me:4567
```

Let's see what we're dealing with:

```bash
$ file amadhj
amadhj: ELF 64-bit LSB  executable, x86-64, version 1 (GNU/Linux), statically linked, for GNU/Linux 2.6.24, BuildID[sha1]=e0faec541ed57fa1cdaac5a5cf11332355b70622, stripped
```

The file is statically linked, so it's pretty big (800k). We might need some FLIRT signatures to help us map out this thing.

From Hopper, after looking around a bit, the main looks like this:

```c
int main(int arg0, int arg1) {
    canary = *0x28;
    sub_41db80(var_30, 0x20);
    rdi = var_30;
    if (sub_4026d1(rdi) != 0x0) {
            sub_40288d();
    }
    rax = 0x0;
    rdx = canary ^ *0x28;
    COND = rdx == 0x0;
    if (!COND) {
            rax = __stack_chk_fail(rdi, 0x20, rdx, rcx, r8, r9);
    }
    return rax;
}
```

Hopper doesn't decompile sub_41db80 very well, but looking at it for a few
moments, the function looks like a bzero(), possibly also a memset() depending
how it's called.

After a bit of cleanup, the main looks like this:

```c
int main(int arg0, int arg1) {
    char buf[32];

    bzero(buf, 32);

    if (read_and_compute(buf) != 0x0) {
            open_and_show_flag();
    }

    return(0);
}
```

The open_and_show_flag():

```c
int open_and_show_flag() {
    canary = *0x28;
    rsi = 0x0;
    flag_fd = sys_open("flag", rsi);
    if (flag_fd <= 0x0) {
            rdi = "Failed to open flag.";
            print(rdi);
    }
    else {
            flag_size = sys_lseek(flag_fd, 0x0, 0x2);
            sys_lseek(flag_fd, 0x0, 0x0);
            if (flag_size > 128) {
                    flag_size = 128;
            }
            memset_probably(flag_data_buf, 0x0, 0x80);
            rdx = sign_extend_64(flag_size);
            rcx = flag_data_buf;
            rsi = rcx;
            sys_read(flag_fd, rsi, rdx);
            sys_close(flag_fd);
            rdi = flag_data_buf;
            print(rdi);
    }
    rax = canary ^ *0x28;
    COND = rax == 0x0;
    if (!COND) {
            rax = __stack_chk_fail(rdi, rsi, rdx, rcx, r8, r9);
    }
    return rax;
}
```

Ok, so it looks like the challenge will be to get read_and_compute() to return != 0.

Let's look at the read_and_compute() then:

```c
int read_and_compute(int8_t * buf) {
    buf_ptr = buf;
    sys_read(0x0, buf_ptr, 32);
    var_2C = 0x0;
    goto loc_4027ee;

loc_4027ee:
    if (var_2C <= 0x1f) goto loc_40270e;

loc_4027f8:
    if ((sub_401960(*(buf_ptr + 0x8)) ^ sub_401464(*buf_ptr) ^ sub_401dc5(*(buf_ptr + 0x10)) ^ sub_402252(*(buf_ptr + 0x18))) == 0xb101124831c0110a) {
            rax = 0x1;
    }
    else {
            rax = 0x0;
    }
    return rax;

loc_40270e:
    if (((*(int8_t *)(buf_ptr + sign_extend_64(var_2C)) & 0xff) <= 0x40) || ((*(int8_t *)(buf_ptr + sign_extend_64(var_2C)) & 0xff) > 0x7a)) goto loc_402736;

loc_402754:
    if ((*(int8_t *)(buf_ptr + sign_extend_64(var_2C)) & 0xff) != 0x5d) goto loc_402772;

loc_402768:
    rax = 0x0;
    return rax;

loc_402772:
    if ((*(int8_t *)(buf_ptr + sign_extend_64(var_2C)) & 0xff) != 0x5c) goto loc_402790;

loc_402786:
    rax = 0x0;
    return rax;

loc_402790:
    if ((*(int8_t *)(buf_ptr + sign_extend_64(var_2C)) & 0xff) != 0x5e) goto loc_4027ae;

loc_4027a4:
    rax = 0x0;
    return rax;

loc_4027ae:
    if ((*(int8_t *)(buf_ptr + sign_extend_64(var_2C)) & 0xff) != 0x60) goto loc_4027cc;

loc_4027c2:
    rax = 0x0;
    return rax;

loc_4027cc:
    if ((*(int8_t *)(buf_ptr + sign_extend_64(var_2C)) & 0xff) != 0x5b) goto loc_4027ea;

loc_4027e0:
    rax = 0x0;
    return rax;

loc_4027ea:
    var_2C = var_2C + 0x1;
    goto loc_4027ee;

loc_402736:
    if ((*(int8_t *)(buf_ptr + sign_extend_64(var_2C)) & 0xff) == 0x20) goto loc_402754;

loc_40274a:
    rax = 0x0;
    return rax;
}
```

Hmmm. Clearly we'll want all those funcs to end-up computing 0xb101124831c0110a
so that the return value (eax) is 0x1.

Let's see what those sub functions look like:

```c
int sub_401960(int arg0) {
    rax = sub_4010d2(arg0, 0x16);
    rax = sub_4011aa(rax);
    rax = sub_401259(rax, 0x4, 0x1);
    rax = sub_4011aa(rax);
    rax = sub_401326(rax);
    rax = sub_4010d2(rax, 0x23);
    rax = sub_401259(rax, 0x2, 0x6);
    rax = sub_4010b9(rax, 0x80a9ea4f90944fea);
    rax = sub_4010d2(rax, 0x3);
    rax = sub_401259(rax, 0x0, 0x1);
    rax = sub_401259(rax, 0x1, 0x2);
    rax = sub_4011aa(rax);
    rax = sub_401326(rax);
    rax = sub_401259(rax, 0x5, 0x1);
    rax = sub_40113e(rax, 0x18);
    rax = sub_4010d2(rax, 0x27);
    rax = sub_401259(rax, 0x2, 0x4);
    rax = sub_4010b9(rax, 0x678e70a16230a437);
    rax = sub_401259(rax, 0x4, 0x3);
    rax = sub_401259(rax, 0x0, 0x7);
    rax = sub_4010d2(rax, 0x3e);
    rax = sub_4011aa(rax);
    rax = sub_401259(rax, 0x7, 0x6);
    rax = sub_401259(rax, 0x2, 0x6);
    rax = sub_4011aa(rax);
    rax = sub_401326(rax);
    rax = sub_401259(rax, 0x5, 0x2);
    rax = sub_401326(rax);
    rax = sub_401259(rax, 0x1, 0x7);
    rax = sub_4010b9(rax, 0x41ea5cf418a918e7);
    rax = sub_4011aa(rax);
    rax = sub_401326(rax);
    rax = sub_401259(rax, 0x1, 0x4);
    rax = sub_4010d2(rax, 0xa);
    rax = sub_4011aa(rax);
    rax = sub_4011aa(rax);
    rax = sub_40113e(rax, 0x18);
    rax = sub_401259(rax, 0x0, 0x4);
    rax = sub_40113e(rax, 0x3d);
    rax = sub_401259(rax, 0x3, 0x4);
    rax = sub_40113e(rax, 0x23);
    rax = sub_4010d2(rax, 0x37);
    rax = sub_4010d2(rax, 0x22);
    rax = sub_401326(rax);
    rax = sub_401326(rax);
    rax = sub_40113e(rax, 0x17);
    rax = sub_4010d2(rax, 0x3b);
    rax = sub_40113e(rax, 0x14);
    rax = sub_4010d2(rax, 0x1c);
    rax = sub_4010b9(rax, 0xc26499379c0927cd);
    rax = sub_401326(rax);
    rax = sub_40113e(rax, 0xd);
    rax = rax;
    return rax;
}

int sub_4010d2(int arg0, int arg1) {
    var_18 = arg0;
    var_20 = arg1 & 0x3f;
    if (var_20 == 0x0) {
            rax = var_18;
    }
    else {
            rax = var_18 >> 0x40 - var_20 | var_18 << var_20;
    }
    return rax;
}
```

Uggh. This is starting to look a lot like the earlier "baby-re" challenge: a
bunch of arithmetics with constraints that would take ages to reverse and solve
manually. Hopefully _angr_ can take care of it.

We'll need to find the path that sets the return value (eax) to 0x1:

```asm
000000000040287f B801000000                      mov        eax, 0x1		; GOOD
0000000000402884 EB05                            jmp        0x40288b

0000000000402886 B800000000                      mov        eax, 0x0            ; XREF=read_and_compute+428

000000000040288b C9                              leave                          ; AVOID
000000000040288c C3                              ret
```

Starting with a factory.entry_state() was taking forever and consuming more RAM
than I had (static binary?), so I opted for a blank_state() starting at the
first instruction of read_and_compute() and creating the 32-byte buffer
somewhere on the stack. (rsp + 100)

We'll want to find a path to 0x40287f, and avoid the "leave" at 0x40288b. It's
counter-intuitive because the good path jumps to the "leave" right after
setting eax to 0x1, but what we are looking for is for angr to break as soon as
it finds a path to "mov eax, 0x1", so any path that gets to the "leave" without
first going through the "mov eax, 0x1" is "Bad".

```python
import angr

p = angr.Project('amadhj')

state = p.factory.blank_state(addr = 0x4026d1)

user_input_array_addr = state.regs.rsp + 100
state.regs.rbp = state.regs.rsp
state.regs.rdi = user_input_array_addr

for i in range(32):
        state.memory.store(user_input_array_addr + i, 0)

print('Creating path')
path = p.factory.path(state)

print('Creating explorer')
ex = p.surveyors.Explorer(start = path, find=(0x040287f,), avoid=(0x40288b,))

print('running explorer')
ex.run()

print('got something')
print ex.found

for found in ex.found:
        s = ""

        for i in range(32):
                addr = user_input_array_addr + i
                d = found.state.se.any_int(found.state.memory.load(addr, 1))

                print "0x%x (%c)" % ( d, chr(d) )

                s += chr(d)

        print "Key: [%s]" % s
```

Launch it..

```bash
$ ./solve-amadhj.py 
Creating path
Creating explorer
running explorer
got something
[<Path with 774 runs (at 0x40287f)>]
0x20 ( )
0x49 (I)
0x52 (R)
0x72 (r)
0x52 (R)
0x41 (A)
0x46 (F)
0x42 (B)
0x6c (l)
0x65 (e)
0x6c (l)
0x55 (U)
0x7a (z)
0x48 (H)
0x5a (Z)
0x59 (Y)
0x75 (u)
0x6d (m)
0x61 (a)
0x71 (q)
0x58 (X)
0x66 (f)
0x67 (g)
0x54 (T)
0x41 (A)
0x52 (R)
0x61 (a)
0x6e (n)
0x74 (t)
0x66 (f)
0x53 (S)
0x64 (d)
Key: [ IRrRAFBlelUzHZYumaqXfgTARantfSd]
```

Done :)

