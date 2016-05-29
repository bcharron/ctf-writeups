CTF: Defcon Quals 2016
Challenge: baby-re
Author: Benjamin Charron <bcharron@pobox.com>

First things first, what is this?

```bash
$ file baby-re
baby-re: ELF 64-bit LSB  executable, x86-64, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.32, BuildID[sha1]=5d5783d23d78bf70b80d658bccbce365f7448693, not stripped
```

Ok, it's a 64-bit linux binary. Cool, something "normal" :)

Before running it, I opened it in r2. The main is simple enough, read 13
integers from stdin to rbp-0x60, then call CheckSolution function and, if
successful, print the corresponding ASCII characters.

Opening CheckSolution() in r2, I can already see it's going to be a bitch when r2 shows this:

```
[0x004006c6]> pdf
Do you want to print 2300 lines? (y/N)
```

That's a lot of function.

So I start digging in. It's a very long function that validates the input. It
becomes clear pretty quickly that r2 is not going to cut-it; I need a
decompiler, so I pull out Hopper, which produces this decompilation:

```c
int CheckSolution(int arg0) {
    user_input_ptr = arg0;
    var_8 = *0x28;
    var_2B0 = 0x926c ^ 0x1;
    var_2AC = SAR(0x2a3a8, 0x3);
    var_2A8 = SAR(0x3a90, 0x3);
    var_2A0 = 0xc514 ^ 0xdd;
    var_298 = SAR(0x1cdc8, 0x2);
    var_294 = SAR(0x10010, 0x2);
    var_288 = 0x524c ^ 0x2e;
    var_27C = SAR(0xc6f80, 0x4);
    var_278 = SAR(0x12c90, 0x4);
    var_268 = 0x5808 ^ 0x4f;
    var_260 = SAR(0x11eee, 0x1);
    var_250 = SAR(0x90a0, 0x2);
    var_248 = SAR(0x974a0, 0x4);
    var_244 = SAR(0x19d9e, 0x1);
    var_240 = SAR(0x20f90, 0x3);
    var_234 = 0x4865 ^ 0xcc;
    var_22C = 0xb947 ^ 0xf0;
    var_21C = 0x1466 ^ 0x9d;
    var_214 = SAR(0x3864c, 0x2);
    var_210 = 0x5d02 ^ 0x53;
    var_20C = SAR(0xcb40, 0x1);
    var_1FC = SAR(0xa664, 0x2);
    var_1F8 = 0x878d ^ 0x78;
    var_1F4 = SAR(0x23d30, 0x4);
    var_1F0 = 0x59a7 ^ 0xe0;
    var_1EC = SAR(0x86b4, 0x2);
    var_1E8 = SAR(0x4f4, 0x1);
    var_1D8 = 0xabd9 ^ 0x65;
    var_1CC = SAR(0x2ffa, 0x1);
    var_1C8 = 0x8a42 ^ 0x21;
    var_1C0 = 0x6d95 ^ 0x73;
    var_1B4 = SAR(0x79b4, 0x1);
    var_1AC = SAR(0x27ce0, 0x2);
    var_1A0 = 0x13c5 ^ 0x97;
    var_19C = SAR(0x343f0, 0x3);
    var_194 = 0x9a9f ^ 0x2c;
    var_190 = 0x357e ^ 0x5c;
    var_188 = SAR(0xffc4, 0x1);
    var_184 = 0x72a3 ^ 0x3e;
    var_180 = 0x28d2 ^ 0x93;
    var_178 = SAR(0x2e62c, 0x2);
    var_16C = SAR(0x4fd6, 0x1);
    var_168 = 0x1342 ^ 0xea;
    var_164 = 0x52ed ^ 0xc2;
    var_160 = 0x73a4 ^ 0x3;
    var_15C = 0xd75a ^ 0x93;
    var_158 = SAR(0x5ec4, 0x2);
    var_154 = SAR(0xfabc, 0x2);
    var_150 = SAR(0x8e50, 0x3);
    var_144 = 0xff11 ^ 0x9a;
    var_140 = 0x438f ^ 0x98;
    var_13C = SAR(0x4984, 0x1);
    var_134 = SAR(0x33264, 0x2);
    var_130 = SAR(0x4826, 0x1);
    var_128 = SAR(0x5d928, 0x3);
    var_120 = 0xa1d6 ^ 0x9f;
    var_110 = SAR(0x1c34, 0x2);
    var_10C = 0x10fe ^ 0xd9;
    var_104 = 0x825b ^ 0x3e;
    var_100 = SAR(0x2dabc, 0x2);
    var_F4 = 0xaf41 ^ 0x39;
    var_EC = SAR(0x140c8, 0x2);
    var_E8 = SAR(0x1ea98, 0x3);
    var_E4 = 0x8e6b ^ 0x9e;
    var_DC = 0xa7ac ^ 0x11;
    var_C8 = 0x67ce ^ 0xf9;
    var_C4 = 0xb7c3 ^ 0xf;
    var_BC = SAR(0x1d5c8, 0x3);
    var_B8 = 0x4a9d ^ 0x82;
    var_B0 = 0x828e ^ 0xa9;
    var_A8 = SAR(0x24374, 0x2);
    var_A4 = 0xc95d ^ 0xdb;
    var_9C = 0x2776 ^ 0xf9;
    var_98 = SAR(0x19948, 0x1);
    var_88 = SAR(0x10268, 0x3);
    var_84 = SAR(0xb0aa, 0x1);
    var_80 = 0x7848 ^ 0x69;
    var_7C = 0x517f ^ 0xa;
    var_78 = 0x7da5 ^ 0x7d;
    var_74 = 0x8fc6 ^ 0xec;
    var_70 = 0xb910 ^ 0xde;
    var_68 = SAR(0xe72c0, 0x4);
    var_64 = 0xfe5e ^ 0xf2;
    var_60 = 0x24ef ^ 0xe3;
    var_5C = 0xe871 ^ 0xbe;
    var_58 = 0xf551 ^ 0xf9;
    var_54 = SAR(0x5f278, 0x3);
    var_40 = 0xca69 ^ 0x7e;
    var_34 = 0x101e ^ 0x18;
    var_28 = 0x5182 ^ 0xa3;
    var_24 = SAR(0xcf2a, 0x1);
    var_20 = SAR(0x1b7e4, 0x2);
    var_1C = SAR(0x62a40, 0x4);
    var_14 = SAR(0xc842, 0x1);
    var_10 = 0x1c85 ^ 0x17;
    if (*(int32_t *)(user_input_ptr + 0x30) * 0xd5e5 + *(int32_t *)(user_input_ptr + 0x2c) * 0x99ae + *(int32_t *)(user_input_ptr + 0x28) * var_288 + *(int32_t *)(user_input_ptr + 0x24) * 0x3922 + *(int32_t *)(user_input_ptr + 0x20) * 0xe15d + *(int32_t *)(user_input_ptr + 0x1c) * var_294 + *(int32_t *)(user_input_ptr + 0x18) * var_298 + *(int32_t *)(user_input_ptr + 0x14) * 0xa89e + (var_2B0 * *(int32_t *)user_input_ptr - *(int32_t *)(user_input_ptr + 0x4) * var_2AC - *(int32_t *)(user_input_ptr + 0x8) * var_2A8 - *(int32_t *)(user_input_ptr + 0xc) * 0xb4c1) + *(int32_t *)(user_input_ptr + 0x10) * var_2A0 != 0x1468753) {
            rax = 0x0;
    }
    else {
            if (*(int32_t *)(user_input_ptr + 48) * 0xcfec + (*(int32_t *)(user_input_ptr + 0x14) * var_268 + *(int32_t *)(user_input_ptr + 0x10) * 0x39ca + (var_27C * *(int32_t *)user_input_ptr + *(int32_t *)(user_input_ptr + 0x4) * var_278 - *(int32_t *)(user_input_ptr + 0x8) * 0x1783) + *(int32_t *)(user_input_ptr + 0xc) * 0x9832 - *(int32_t *)(user_input_ptr + 0x18) * 0x345 - *(int32_t *)(user_input_ptr + 0x1c) * var_260 - *(int32_t *)(user_input_ptr + 0x20) * 0xc5a0 - *(int32_t *)(user_input_ptr + 0x24) * 0x2e35 - *(int32_t *)(user_input_ptr + 0x28) * 0x4e4e - *(int32_t *)(user_input_ptr + 0x2c) * var_250) != 0x162f30) {
                    rax = 0x0;
            }
            else {
                    if (*(int32_t *)(user_input_ptr + 0x30) * 0x2ccd + *(int32_t *)(user_input_ptr + 0x2c) * var_21C + (((-var_248 * *(int32_t *)user_input_ptr + *(int32_t *)(user_input_ptr + 0x4) * var_244 - *(int32_t *)(user_input_ptr + 0x8) * var_240) + *(int32_t *)(user_input_ptr + 0xc) * 0x691b - *(int32_t *)(user_input_ptr + 0x10) * 0xad9e - *(int32_t *)(user_input_ptr + 0x14) * var_234 - *(int32_t *)(user_input_ptr + 0x18) * 0xfec5 - *(int32_t *)(user_input_ptr + 0x1c) * var_22C) + *(int32_t *)(user_input_ptr + 0x20) * 0x4526 - *(int32_t *)(user_input_ptr + 0x24) * 0x8476) + *(int32_t *)(user_input_ptr + 0x28) * 0xa69e != 0xffb2939c) {
                            rax = 0x0;
                    }
                    else {
                            if ((*(int32_t *)(user_input_ptr + 0x1c) * var_1F8 + ((var_214 * *(int32_t *)user_input_ptr - *(int32_t *)(user_input_ptr + 0x4) * var_210 - *(int32_t *)(user_input_ptr + 0x8) * var_20C - *(int32_t *)(user_input_ptr + 0xc) * 0x6252) + *(int32_t *)(user_input_ptr + 0x10) * 0xd42d - *(int32_t *)(user_input_ptr + 0x14) * 0x7e51) + *(int32_t *)(user_input_ptr + 0x18) * var_1FC - *(int32_t *)(user_input_ptr + 0x20) * var_1F4 - *(int32_t *)(user_input_ptr + 0x24) * var_1F0) + *(int32_t *)(user_input_ptr + 0x28) * var_1EC - *(int32_t *)(user_input_ptr + 0x2c) * var_1E8 - *(int32_t *)(user_input_ptr + 0x30) * 0x2e58 != 0xffac90e3) {
                                    rax = 0x0;
                            }
                            else {
                                    if (*(int32_t *)(user_input_ptr + 0x30) * 0xc3a2 + (*(int32_t *)(user_input_ptr + 0x24) * 0xa8b2 + (*(int32_t *)(user_input_ptr + 0x10) * 0xd669 + *(int32_t *)(user_input_ptr + 0xc) * 0x876e + *(int32_t *)(user_input_ptr + 0x8) * var_1D8 + -0x36b5 * *(int32_t *)user_input_ptr + *(int32_t *)(user_input_ptr + 0x4) * 0x3fc3 - *(int32_t *)(user_input_ptr + 0x14) * var_1CC - *(int32_t *)(user_input_ptr + 0x18) * var_1C8 - *(int32_t *)(user_input_ptr + 0x1c) * 0xf219) + *(int32_t *)(user_input_ptr + 0x20) * var_1C0 - *(int32_t *)(user_input_ptr + 0x28) * 0xe91c) + *(int32_t *)(user_input_ptr + 0x2c) * var_1B4 != 0x76d288) {
                                            rax = 0x0;
                                    }
                                    else {
                                            if (*(int32_t *)(user_input_ptr + 0x2c) * var_180 + (*(int32_t *)(user_input_ptr + 0x1c) * var_190 + ((-var_1AC * *(int32_t *)user_input_ptr - *(int32_t *)(user_input_ptr + 0x4) * 0x55fe) + *(int32_t *)(user_input_ptr + 0x8) * 0x3528 - *(int32_t *)(user_input_ptr + 0xc) * var_1A0 - *(int32_t *)(user_input_ptr + 0x10) * var_19C - *(int32_t *)(user_input_ptr + 0x14) * 0x7bdc) + *(int32_t *)(user_input_ptr + 0x18) * var_194 - *(int32_t *)(user_input_ptr + 0x20) * 0xe6af - *(int32_t *)(user_input_ptr + 0x24) * var_188) + *(int32_t *)(user_input_ptr + 0x28) * var_184 - *(int32_t *)(user_input_ptr + 0x30) * 0x3d22 != 0xff78bf99) {
                                                    rax = 0x0;
                                            }
                                            else {
                                                    if (*(int32_t *)(user_input_ptr + 0x30) * 0x49d7 + (((*(int32_t *)(user_input_ptr + 0x8) * 0x34a5 + -var_178 * *(int32_t *)user_input_ptr + *(int32_t *)(user_input_ptr + 0x4) * 0xe200 - *(int32_t *)(user_input_ptr + 0xc) * var_16C - *(int32_t *)(user_input_ptr + 0x10) * var_168 - *(int32_t *)(user_input_ptr + 0x14) * var_164 - *(int32_t *)(user_input_ptr + 0x18) * var_160) + *(int32_t *)(user_input_ptr + 0x1c) * var_15C - *(int32_t *)(user_input_ptr + 0x20) * var_158) + *(int32_t *)(user_input_ptr + 0x24) * var_154 - *(int32_t *)(user_input_ptr + 0x28) * var_150 - *(int32_t *)(user_input_ptr + 0x2c) * 0x8d6) != 0xfff496e3) {
                                                            rax = 0x0;
                                                    }
                                                    else {
                                                            if ((*(int32_t *)(user_input_ptr + 0x1c) * var_128 + (-var_144 * *(int32_t *)user_input_ptr + *(int32_t *)(user_input_ptr + 0x4) * var_140 - *(int32_t *)(user_input_ptr + 0x8) * var_13C - *(int32_t *)(user_input_ptr + 0xc) * 0x57f2 - *(int32_t *)(user_input_ptr + 0x10) * var_134 - *(int32_t *)(user_input_ptr + 0x14) * var_130) + *(int32_t *)(user_input_ptr + 0x18) * 0xd03d - *(int32_t *)(user_input_ptr + 0x20) * 0xe6e7 - *(int32_t *)(user_input_ptr + 0x24) * var_120 - *(int32_t *)(user_input_ptr + 0x28) * 0x5f66) + *(int32_t *)(user_input_ptr + 0x2c) * 0xa0da - *(int32_t *)(user_input_ptr + 0x30) * 0x5b97 != 0xff525e90) {
                                                                    rax = 0x0;
                                                            }
                                                            else {
                                                                    if (*(int32_t *)(user_input_ptr + 0x30) * 0x4737 + ((*(int32_t *)(user_input_ptr + 0x14) * 0xe4b7 + *(int32_t *)(user_input_ptr + 0x10) * var_100 + (var_110 * *(int32_t *)user_input_ptr + *(int32_t *)(user_input_ptr + 0x4) * var_10C - *(int32_t *)(user_input_ptr + 0x8) * 0x4204) + *(int32_t *)(user_input_ptr + 0xc) * var_104 - *(int32_t *)(user_input_ptr + 0x18) * 0x8546 - *(int32_t *)(user_input_ptr + 0x1c) * var_F4 - *(int32_t *)(user_input_ptr + 0x20) * 0x2e9d - *(int32_t *)(user_input_ptr + 0x24) * var_EC) + *(int32_t *)(user_input_ptr + 0x28) * var_E8 - *(int32_t *)(user_input_ptr + 0x2c) * var_E4) != 0xfffd7704) {
                                                                            rax = 0x0;
                                                                    }
                                                                    else {
                                                                            if (*(int32_t *)(user_input_ptr + 0x30) * 0xf8c0 + (*(int32_t *)(user_input_ptr + 0x28) * 0x2a24 + *(int32_t *)(user_input_ptr + 0x24) * var_B8 + *(int32_t *)(user_input_ptr + 0x20) * var_BC + *(int32_t *)(user_input_ptr + 0x1c) * 0xa57b + ((-var_DC * *(int32_t *)user_input_ptr + *(int32_t *)(user_input_ptr + 0x4) * 0xee80 - *(int32_t *)(user_input_ptr + 0x8) * 0xb071) + *(int32_t *)(user_input_ptr + 0xc) * 0xa144 - *(int32_t *)(user_input_ptr + 0x10) * 0x6ba - *(int32_t *)(user_input_ptr + 0x14) * var_C8) + *(int32_t *)(user_input_ptr + 0x18) * var_C4 - *(int32_t *)(user_input_ptr + 0x2c) * var_B0) != 0x897cbb) {
                                                                                    rax = 0x0;
                                                                            }
                                                                            else {
                                                                                    if (*(int32_t *)(user_input_ptr + 0x30) * var_78 + (*(int32_t *)(user_input_ptr + 0x28) * var_80 + (*(int32_t *)(user_input_ptr + 0x1c) * 0xe5a2 + *(int32_t *)(user_input_ptr + 0x18) * 0x312b + (-var_A8 * *(int32_t *)user_input_ptr - *(int32_t *)(user_input_ptr + 0x4) * var_A4 - *(int32_t *)(user_input_ptr + 0x8) * 0x4586 - *(int32_t *)(user_input_ptr + 0xc) * var_9C - *(int32_t *)(user_input_ptr + 0x10) * var_98) + *(int32_t *)(user_input_ptr + 0x14) * 0x31ca - *(int32_t *)(user_input_ptr + 0x20) * var_88) + *(int32_t *)(user_input_ptr + 0x24) * var_84 - *(int32_t *)(user_input_ptr + 0x2c) * var_7C) != 0xffc05f9f) {
                                                                                            rax = 0x0;
                                                                                    }
                                                                                    else {
                                                                                            if (*(int32_t *)(user_input_ptr + 0x30) * 0x9e3e + (*(int32_t *)(user_input_ptr + 0x24) * 0xb8f4 + (*(int32_t *)(user_input_ptr + 0x14) * var_60 + (var_74 * *(int32_t *)user_input_ptr + *(int32_t *)(user_input_ptr + 0x4) * var_70 - *(int32_t *)(user_input_ptr + 0x8) * 0x8202 - *(int32_t *)(user_input_ptr + 0xc) * var_68) + *(int32_t *)(user_input_ptr + 0x10) * var_64 - *(int32_t *)(user_input_ptr + 0x18) * var_5C - *(int32_t *)(user_input_ptr + 0x1c) * var_58) + *(int32_t *)(user_input_ptr + 0x20) * var_54 - *(int32_t *)(user_input_ptr + 0x28) * 0x92d8) + *(int32_t *)(user_input_ptr + 0x2c) * 0xe10c != 0x3e4761) {
                                                                                                    rax = 0x0;
                                                                                            }
                                                                                            else {
                                                                                                    if (*(int32_t *)(user_input_ptr + 0x30) * var_10 + (*(int32_t *)(user_input_ptr + 0x24) * var_1C + *(int32_t *)(user_input_ptr + 0x20) * var_20 + (*(int32_t *)(user_input_ptr + 0x10) * 0xe877 + (var_40 * *(int32_t *)user_input_ptr + *(int32_t *)(user_input_ptr + 0x4) * 0x8c27 - *(int32_t *)(user_input_ptr + 0x8) * 0xf992) + *(int32_t *)(user_input_ptr + 0xc) * var_34 - *(int32_t *)(user_input_ptr + 0x14) * 0x538a - *(int32_t *)(user_input_ptr + 0x18) * var_28) + *(int32_t *)(user_input_ptr + 0x1c) * var_24 - *(int32_t *)(user_input_ptr + 0x28) * 0xab0d) + *(int32_t *)(user_input_ptr + 0x2c) * var_14 != 0x1b4945) {
                                                                                                            rax = 0x0;
                                                                                                    }
                                                                                                    else {
                                                                                                            rax = 0x1;
                                                                                                    }
                                                                                            }
                                                                                    }
                                                                            }
                                                                    }
                                                            }
                                                    }
                                            }
                                    }
                            }
                    }
            }
    }
    rsi = var_8 ^ *0x28;
    COND = rsi == 0x0;
    if (!COND) {
            rax = __stack_chk_fail();
    }
    return rax;
}
```

This is insane. How the fuck am I going to reverse this??

Hmm.. the first part is just setting-up variables, nothing to do here. It's
just computing an array of 169 integers from a hardcoded set. 169 is a pretty odd number.

The second part is using the first computations. There are 13 IFs.. And we
entered 13 numbers in main().. And 169 = 13 * 13. Could it be a system of 13 equations with 13 unknowns?

At a quick glance, it checks out!  The inputs are all used at least once per equation!

Ok, so it's an equation system. How do I resolve it?  By hand it would take ages. (And I'm not quite sure I remember how to do this.)

Online I find two things: wolfram and z3. Ok, I can either write a z3-script or it also has python bindings. Cool :)

I try to feed it to Wolfram, but the accepted input is pretty small, so I go with z3. 

First, I capture the computed variables with r2:
The last compute of the 169 int array is done at 0x401558. So I run `r2 -d
baby-re`, then say "db 0x401558" and "dc". Once r2 breaks, I grab the memory from rbp-0x2B0 to rbp-0x10. I want it in Python format, but r2 only seems to be able to extract bytes and I want dwords, so I use "pcw" instead:

```
[0x00401558]> pcw 169*4 @ rbp-0x2b0
#define _BUFFER_SIZE 169
unsigned int buffer[169] = {
  0x0000926d, 0x00005475, 0x00000752, 0x0000b4c1, 0x0000c5c9, 
  0x0000a89e, 0x00007372, 0x00004004, 0x0000e15d, 0x00003922, 
  0x00005262, 0x000099ae, 0x0000d5e5, 0x0000c6f8, 0x000012c9, 
  0x00001783, 0x00009832, 0x000039ca, 0x00005847, 0x00000345, 
  0x00008f77, 0x0000c5a0, 0x00002e35, 0x00004e4e, 0x00002428, 
  0x0000cfec, 0x0000974a, 0x0000cecf, 0x000041f2, 0x0000691b, 
  0x0000ad9e, 0x000048a9, 0x0000fec5, 0x0000b9b7, 0x00004526, 
  0x00008476, 0x0000a69e, 0x000014fb, 0x00002ccd, 0x0000e193, 
  0x00005d51, 0x000065a0, 0x00006252, 0x0000d42d, 0x00007e51, 
  0x00002999, 0x000087f5, 0x000023d3, 0x00005947, 0x000021ad, 
  0x0000027a, 0x00002e58, 0x000036b5, 0x00003fc3, 0x0000abbc, 
  0x0000876e, 0x0000d669, 0x000017fd, 0x00008a63, 0x0000f219, 
  0x00006de6, 0x0000a8b2, 0x0000e91c, 0x00003cda, 0x0000c3a2, 
  0x00009f38, 0x000055fe, 0x00003528, 0x00001352, 0x0000687e, 
  0x00007bdc, 0x00009ab3, 0x00003522, 0x0000e6af, 0x00007fe2, 
  0x0000729d, 0x00002841, 0x00003d22, 0x0000b98b, 0x0000e200, 
  0x000034a5, 0x000027eb, 0x000013a8, 0x0000522f, 0x000073a7, 
  0x0000d7c9, 0x000017b1, 0x00003eaf, 0x000011ca, 0x000008d6, 
  0x000049d7, 0x0000ff8b, 0x00004317, 0x000024c2, 0x000057f2, 
  0x0000cc99, 0x00002413, 0x0000d03d, 0x0000bb25, 0x0000e6e7, 
  0x0000a149, 0x00005f66, 0x0000a0da, 0x00005b97, 0x0000070d, 
  0x00001027, 0x00004204, 0x00008265, 0x0000b6af, 0x0000e4b7, 
  0x00008546, 0x0000af78, 0x00002e9d, 0x00005032, 0x00003d53, 
  0x00008ef5, 0x00004737, 0x0000a7bd, 0x0000ee80, 0x0000b071, 
  0x0000a144, 0x000006ba, 0x00006737, 0x0000b7cc, 0x0000a57b, 
  0x00003ab9, 0x00004a1f, 0x00002a24, 0x00008227, 0x0000f8c0, 
  0x000090dd, 0x0000c986, 0x00004586, 0x0000278f, 0x0000cca4, 
  0x000031ca, 0x0000312b, 0x0000e5a2, 0x0000204d, 0x00005855, 
  0x00007821, 0x00005175, 0x00007dd8, 0x00008f2a, 0x0000b9ce, 
  0x00008202, 0x0000e72c, 0x0000feac, 0x0000240c, 0x0000e8cf, 
  0x0000f5a8, 0x0000be4f, 0x0000b8f4, 0x000092d8, 0x0000e10c, 
  0x00009e3e, 0x0000ca17, 0x00008c27, 0x0000f992, 0x00001006, 
  0x0000e877, 0x0000538a, 0x00005121, 0x00006795, 0x00006df9, 
  0x000062a4, 0x0000ab0d, 0x00006421, 0x00001c92, };
```

In order to feed them to z3, I need their reference, so I write a small program
to restore their names:

```c
int main(int argc, char *argv[]) {
	int pos = 0x2b0;
	int x;

	for (x = 0; x < _BUFFER_SIZE; x++) {
		printf("var_%X = %d\n", pos, buffer[x]);
		pos -= 4;
	}

	return(0);
}
```

Then I dump Hopper's decompilation into a file, replacing "user_input + whatever" into "user_input_0xZZ" with a bit of sed:

```
user_input_0x30 * 0xd5e5 + user_input_0x2c * 0x99ae + user_input_0x28 * 21090 + user_input_0x24 * 0x3922 + user_input_0x20 * 0xe15d + user_input_0x1c * 16388 + user_input_0x18 * 29554 + user_input_0x14 * 0xa89e + ( 37485 * user_input_0x00 - user_input_0x4 * 21621 - user_input_0x8 * 1874 - user_input_0xc * 0xb4c1) + user_input_0x10 * 50633 = 0x1468753
user_input_0x30 * 0xcfec + (user_input_0x14 * 22599 + user_input_0x10 * 0x39ca + ( 50936 * user_input_0x00 + user_input_0x4 * 4809 - user_input_0x8 * 0x1783) + user_input_0xc * 0x9832 - user_input_0x18 * 0x345 - user_input_0x1c * 36727 - user_input_0x20 * 0xc5a0 - user_input_0x24 * 0x2e35 - user_input_0x28 * 0x4e4e - user_input_0x2c * 9256) = 0x162f30
user_input_0x30 * 0x2ccd + user_input_0x2c * 5371 + (((-38730 * user_input_0x00 + user_input_0x4 * 52943 - user_input_0x8 * 16882) + user_input_0xc * 0x691b - user_input_0x10 * 0xad9e - user_input_0x14 * 18601 - user_input_0x18 * 0xfec5 - user_input_0x1c * 47543) + user_input_0x20 * 0x4526 - user_input_0x24 * 0x8476) + user_input_0x28 * 0xa69e = 0xffb2939c
(user_input_0x1c * 34805 + ((57747 * user_input_0x00 - user_input_0x4 * 23889 - user_input_0x8 * 26016 - user_input_0xc * 0x6252) + user_input_0x10 * 0xd42d - user_input_0x14 * 0x7e51) + user_input_0x18 * 10649 - user_input_0x20 * 9171 - user_input_0x24 * 22855) + user_input_0x28 * 8621 - user_input_0x2c * 634 - user_input_0x30 * 0x2e58 = 0xffac90e3
user_input_0x30 * 0xc3a2 + (user_input_0x24 * 0xa8b2 + (user_input_0x10 * 0xd669 + user_input_0xc * 0x876e + user_input_0x8 * 43964 + -0x36b5 * user_input_0x00 + user_input_0x4 * 0x3fc3 - user_input_0x14 * 6141 - user_input_0x18 * 35427 - user_input_0x1c * 0xf219) + user_input_0x20 * 28134 - user_input_0x28 * 0xe91c) + user_input_0x2c * 15578 = 0x76d288
user_input_0x2c * 10305 + (user_input_0x1c * 13602 + ((-40760 * user_input_0x00 - user_input_0x4 * 0x55fe) + user_input_0x8 * 0x3528 - user_input_0xc * 4946 - user_input_0x10 * 26750 - user_input_0x14 * 0x7bdc) + user_input_0x18 * 39603 - user_input_0x20 * 0xe6af - user_input_0x24 * 32738) + user_input_0x28 * 29341 - user_input_0x30 * 0x3d22 = 0xff78bf99
user_input_0x30 * 0x49d7 + (((user_input_0x8 * 0x34a5 + -47499 * user_input_0x00 + user_input_0x4 * 0xe200 - user_input_0xc * 10219 - user_input_0x10 * 5032 - user_input_0x14 * 21039 - user_input_0x18 * 29607) + user_input_0x1c * 55241 - user_input_0x20 * 6065) + user_input_0x24 * 16047 - user_input_0x28 * 4554 - user_input_0x2c * 0x8d6) = 0xfff496e3
(user_input_0x1c * 47909 + (-65419 * user_input_0x00 + user_input_0x4 * 17175 - user_input_0x8 * 9410 - user_input_0xc * 0x57f2 - user_input_0x10 * 52377 - user_input_0x14 * 9235) + user_input_0x18 * 0xd03d - user_input_0x20 * 0xe6e7 - user_input_0x24 * 41289 - user_input_0x28 * 0x5f66) + user_input_0x2c * 0xa0da - user_input_0x30 * 0x5b97 = 0xff525e90
user_input_0x30 * 0x4737 + ((user_input_0x14 * 0xe4b7 + user_input_0x10 * 46767 + (1805 * user_input_0x00 + user_input_0x4 * 4135 - user_input_0x8 * 0x4204) + user_input_0xc * 33381 - user_input_0x18 * 0x8546 - user_input_0x1c * 44920 - user_input_0x20 * 0x2e9d - user_input_0x24 * 20530) + user_input_0x28 * 15699 - user_input_0x2c * 36597) = 0xfffd7704
ser_input_0x30 * 0xf8c0 + (user_input_0x28 * 0x2a24 + user_input_0x24 * 18975 + user_input_0x20 * 15033 + user_input_0x1c * 0xa57b + ((-42941 * user_input_0x00 + user_input_0x4 * 0xee80 - user_input_0x8 * 0xb071) + user_input_0xc * 0xa144 - user_input_0x10 * 0x6ba - user_input_0x14 * 26423) + user_input_0x18 * 47052 - user_input_0x2c * 33319) = 0x897cbb
user_input_0x30 * 32216 + (user_input_0x28 * 30753 + (user_input_0x1c * 0xe5a2 + user_input_0x18 * 0x312b + (-37085 * user_input_0x00 - user_input_0x4 * 51590 - user_input_0x8 * 0x4586 - user_input_0xc * 10127 - user_input_0x10 * 52388) + user_input_0x14 * 0x31ca - user_input_0x20 * 8269) + user_input_0x24 * 22613 - user_input_0x2c * 20853) = 0xffc05f9f
user_input_0x30 * 0x9e3e + (user_input_0x24 * 0xb8f4 + (user_input_0x14 * 9228 + (36650 * user_input_0x00 + user_input_0x4 * 47566 - user_input_0x8 * 0x8202 - user_input_0xc * 59180) + user_input_0x10 * 65196 - user_input_0x18 * 59599 - user_input_0x1c * 62888) + user_input_0x20 * 48719 - user_input_0x28 * 0x92d8) + user_input_0x2c * 0xe10c = 0x3e4761
ser_input_0x30 * 7314 + (user_input_0x24 * 25252 + user_input_0x20 * 28153 + (user_input_0x10 * 0xe877 + (51735 * user_input_0x00 + user_input_0x4 * 0x8c27 - user_input_0x8 * 0xf992) + user_input_0xc * 4102 - user_input_0x14 * 0x538a - user_input_0x18 * 20769) + user_input_0x1c * 26517 - user_input_0x28 * 0xab0d) + user_input_0x2c * 25633 = 0x1b4945
```

.. and create "z3-solve-baby.py" using both of these.

Just run z3-solve-baby.py and voila!

```
$ ./solve-baby.py 
unsat
Traceback (most recent call last):
  File "./solve-baby.py", line 379, in <module>
    print(s.model())
  File "/data/Users/bcharron/re/defcon-quals-2016/babys-first/baby-re/z3-4.4.1-x64-debian-8.2/bin/z3.py", line 5989, in model
    raise Z3Exception("model is not available")
z3types.Z3Exception: model is not available
```

wtf? Damn it!!

I tried a bunch of things, I was never able to get z3 to solve these constraints.

Then I spent about an hour looking for a tool I remembered seeing for something
like this, tweeted by @PythonArsenal or @REhints..  angr!  Made by the
Shellphish guys, I remembered watching a presentation on it (defcon? blackhat?
can't remember.)

Copying from
https://github.com/angr/angr-doc/blob/master/examples/google2016_unbreakable_1/solve.py,
I created a script to solve baby-re.

However, for the longest time, it would never return a valid path. Always it
would return 12 or 13 avoided and 1 deadened. I tried multiple things, like
changing the start address: at the start of CheckSolution, just before it, in
the middle of it.. Explicitely listed all the paths to avoid.. Always the same
output.

At the time, I had the following constraint on all my user inputs, since all the inputs were 8-bit.
```python
def dword(state, n):
    """Returns a symbolic BitVector and contrains it to byte values"""
    vec = state.se.BVS('c{}'.format(n), 32, explicit_name=True)
    return vec, state.se.And(vec >= 0x00, vec <= 0xff)
```

Evnetually I changed the condition "vec <= 0xff" for "vec <= 0xffffffff" and
then it finally found a path!!  The output was weird though, and that's when I
realized I was probably having some sort of issues with endianness, which is
maybe why the constraint was failling..  Notice how I extract one byte at a time, because this returns the number in big-endian:

```python
"%08X" % found.state.se.any_int(found.state.memory.load(addr, 4))
```

Final solve (see angr-solve-baby.py)

```
$ python solve-baby.py 
adding BitVectors and constraints
Creating path
Creating explorer
running explorer
got something
[<Path with 136 runs (at 0x4025cc)>]
0x4d (M)
0x61 (a)
0x74 (t)
0x68 (h)
0x20 ( )
0x69 (i)
0x73 (s)
0x20 ( )
0x68 (h)
0x61 (a)
0x72 (r)
0x64 (d)
0x21 (!)
```

