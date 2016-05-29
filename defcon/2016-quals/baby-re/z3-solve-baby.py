#!/usr/bin/python

from z3 import *

user_input_0x00 = Int('user_input_0x00')
user_input_0x10 = Int('user_input_0x10')
user_input_0x14 = Int('user_input_0x14')
user_input_0x18 = Int('user_input_0x18')
user_input_0x1c = Int('user_input_0x1c')
user_input_0x20 = Int('user_input_0x20')
user_input_0x24 = Int('user_input_0x24')
user_input_0x28 = Int('user_input_0x28')
user_input_0x2c = Int('user_input_0x2c')
user_input_0x30 = Int('user_input_0x30')
user_input_0x4 = Int('user_input_0x4')
user_input_0x8 = Int('user_input_0x8')
user_input_0xc = Int('user_input_0xc')

var_2B0 = Int('var_2B0')
var_2AC = Int('var_2AC')
var_2A8 = Int('var_2A8')
var_2A4 = Int('var_2A4')
var_2A0 = Int('var_2A0')
var_29C = Int('var_29C')
var_298 = Int('var_298')
var_294 = Int('var_294')
var_290 = Int('var_290')
var_28C = Int('var_28C')
var_288 = Int('var_288')
var_284 = Int('var_284')
var_280 = Int('var_280')
var_27C = Int('var_27C')
var_278 = Int('var_278')
var_274 = Int('var_274')
var_270 = Int('var_270')
var_26C = Int('var_26C')
var_268 = Int('var_268')
var_264 = Int('var_264')
var_260 = Int('var_260')
var_25C = Int('var_25C')
var_258 = Int('var_258')
var_254 = Int('var_254')
var_250 = Int('var_250')
var_24C = Int('var_24C')
var_248 = Int('var_248')
var_244 = Int('var_244')
var_240 = Int('var_240')
var_23C = Int('var_23C')
var_238 = Int('var_238')
var_234 = Int('var_234')
var_230 = Int('var_230')
var_22C = Int('var_22C')
var_228 = Int('var_228')
var_224 = Int('var_224')
var_220 = Int('var_220')
var_21C = Int('var_21C')
var_218 = Int('var_218')
var_214 = Int('var_214')
var_210 = Int('var_210')
var_20C = Int('var_20C')
var_208 = Int('var_208')
var_204 = Int('var_204')
var_200 = Int('var_200')
var_1FC = Int('var_1FC')
var_1F8 = Int('var_1F8')
var_1F4 = Int('var_1F4')
var_1F0 = Int('var_1F0')
var_1EC = Int('var_1EC')
var_1E8 = Int('var_1E8')
var_1E4 = Int('var_1E4')
var_1E0 = Int('var_1E0')
var_1DC = Int('var_1DC')
var_1D8 = Int('var_1D8')
var_1D4 = Int('var_1D4')
var_1D0 = Int('var_1D0')
var_1CC = Int('var_1CC')
var_1C8 = Int('var_1C8')
var_1C4 = Int('var_1C4')
var_1C0 = Int('var_1C0')
var_1BC = Int('var_1BC')
var_1B8 = Int('var_1B8')
var_1B4 = Int('var_1B4')
var_1B0 = Int('var_1B0')
var_1AC = Int('var_1AC')
var_1A8 = Int('var_1A8')
var_1A4 = Int('var_1A4')
var_1A0 = Int('var_1A0')
var_19C = Int('var_19C')
var_198 = Int('var_198')
var_194 = Int('var_194')
var_190 = Int('var_190')
var_18C = Int('var_18C')
var_188 = Int('var_188')
var_184 = Int('var_184')
var_180 = Int('var_180')
var_17C = Int('var_17C')
var_178 = Int('var_178')
var_174 = Int('var_174')
var_170 = Int('var_170')
var_16C = Int('var_16C')
var_168 = Int('var_168')
var_164 = Int('var_164')
var_160 = Int('var_160')
var_15C = Int('var_15C')
var_158 = Int('var_158')
var_154 = Int('var_154')
var_150 = Int('var_150')
var_14C = Int('var_14C')
var_148 = Int('var_148')
var_144 = Int('var_144')
var_140 = Int('var_140')
var_13C = Int('var_13C')
var_138 = Int('var_138')
var_134 = Int('var_134')
var_130 = Int('var_130')
var_12C = Int('var_12C')
var_128 = Int('var_128')
var_124 = Int('var_124')
var_120 = Int('var_120')
var_11C = Int('var_11C')
var_118 = Int('var_118')
var_114 = Int('var_114')
var_110 = Int('var_110')
var_10C = Int('var_10C')
var_108 = Int('var_108')
var_104 = Int('var_104')
var_100 = Int('var_100')
var_FC = Int('var_FC')
var_F8 = Int('var_F8')
var_F4 = Int('var_F4')
var_F0 = Int('var_F0')
var_EC = Int('var_EC')
var_E8 = Int('var_E8')
var_E4 = Int('var_E4')
var_E0 = Int('var_E0')
var_DC = Int('var_DC')
var_D8 = Int('var_D8')
var_D4 = Int('var_D4')
var_D0 = Int('var_D0')
var_CC = Int('var_CC')
var_C8 = Int('var_C8')
var_C4 = Int('var_C4')
var_C0 = Int('var_C0')
var_BC = Int('var_BC')
var_B8 = Int('var_B8')
var_B4 = Int('var_B4')
var_B0 = Int('var_B0')
var_AC = Int('var_AC')
var_A8 = Int('var_A8')
var_A4 = Int('var_A4')
var_A0 = Int('var_A0')
var_9C = Int('var_9C')
var_98 = Int('var_98')
var_94 = Int('var_94')
var_90 = Int('var_90')
var_8C = Int('var_8C')
var_88 = Int('var_88')
var_84 = Int('var_84')
var_80 = Int('var_80')
var_7C = Int('var_7C')
var_78 = Int('var_78')
var_74 = Int('var_74')
var_70 = Int('var_70')
var_6C = Int('var_6C')
var_68 = Int('var_68')
var_64 = Int('var_64')
var_60 = Int('var_60')
var_5C = Int('var_5C')
var_58 = Int('var_58')
var_54 = Int('var_54')
var_50 = Int('var_50')
var_4C = Int('var_4C')
var_48 = Int('var_48')
var_44 = Int('var_44')
var_40 = Int('var_40')
var_3C = Int('var_3C')
var_38 = Int('var_38')
var_34 = Int('var_34')
var_30 = Int('var_30')
var_2C = Int('var_2C')
var_28 = Int('var_28')
var_24 = Int('var_24')
var_20 = Int('var_20')
var_1C = Int('var_1C')
var_18 = Int('var_18')
var_14 = Int('var_14')
var_10 = Int('var_10')

x = Int('x')
y = Int('y')
s = Solver()
#s.add(x + y == 5)
#s.add(x + y + user_input_0x00> 5, x > 1, y > 1, user_input_0x00 > 1)
s.add(var_2B0 == 37485)
s.add(var_2AC == 21621)
s.add(var_2A8 == 1874)
s.add(var_2A4 == 46273)
s.add(var_2A0 == 50633)
s.add(var_29C == 43166)
s.add(var_298 == 29554)
s.add(var_294 == 16388)
s.add(var_290 == 57693)
s.add(var_28C == 14626)
s.add(var_288 == 21090)
s.add(var_284 == 39342)
s.add(var_280 == 54757)
s.add(var_27C == 50936)
s.add(var_278 == 4809)
s.add(var_274 == 6019)
s.add(var_270 == 38962)
s.add(var_26C == 14794)
s.add(var_268 == 22599)
s.add(var_264 == 837)
s.add(var_260 == 36727)
s.add(var_25C == 50592)
s.add(var_258 == 11829)
s.add(var_254 == 20046)
s.add(var_250 == 9256)
s.add(var_24C == 53228)
s.add(var_248 == 38730)
s.add(var_244 == 52943)
s.add(var_240 == 16882)
s.add(var_23C == 26907)
s.add(var_238 == 44446)
s.add(var_234 == 18601)
s.add(var_230 == 65221)
s.add(var_22C == 47543)
s.add(var_228 == 17702)
s.add(var_224 == 33910)
s.add(var_220 == 42654)
s.add(var_21C == 5371)
s.add(var_218 == 11469)
s.add(var_214 == 57747)
s.add(var_210 == 23889)
s.add(var_20C == 26016)
s.add(var_208 == 25170)
s.add(var_204 == 54317)
s.add(var_200 == 32337)
s.add(var_1FC == 10649)
s.add(var_1F8 == 34805)
s.add(var_1F4 == 9171)
s.add(var_1F0 == 22855)
s.add(var_1EC == 8621)
s.add(var_1E8 == 634)
s.add(var_1E4 == 11864)
s.add(var_1E0 == 14005)
s.add(var_1DC == 16323)
s.add(var_1D8 == 43964)
s.add(var_1D4 == 34670)
s.add(var_1D0 == 54889)
s.add(var_1CC == 6141)
s.add(var_1C8 == 35427)
s.add(var_1C4 == 61977)
s.add(var_1C0 == 28134)
s.add(var_1BC == 43186)
s.add(var_1B8 == 59676)
s.add(var_1B4 == 15578)
s.add(var_1B0 == 50082)
s.add(var_1AC == 40760)
s.add(var_1A8 == 22014)
s.add(var_1A4 == 13608)
s.add(var_1A0 == 4946)
s.add(var_19C == 26750)
s.add(var_198 == 31708)
s.add(var_194 == 39603)
s.add(var_190 == 13602)
s.add(var_18C == 59055)
s.add(var_188 == 32738)
s.add(var_184 == 29341)
s.add(var_180 == 10305)
s.add(var_17C == 15650)
s.add(var_178 == 47499)
s.add(var_174 == 57856)
s.add(var_170 == 13477)
s.add(var_16C == 10219)
s.add(var_168 == 5032)
s.add(var_164 == 21039)
s.add(var_160 == 29607)
s.add(var_15C == 55241)
s.add(var_158 == 6065)
s.add(var_154 == 16047)
s.add(var_150 == 4554)
s.add(var_14C == 2262)
s.add(var_148 == 18903)
s.add(var_144 == 65419)
s.add(var_140 == 17175)
s.add(var_13C == 9410)
s.add(var_138 == 22514)
s.add(var_134 == 52377)
s.add(var_130 == 9235)
s.add(var_12C == 53309)
s.add(var_128 == 47909)
s.add(var_124 == 59111)
s.add(var_120 == 41289)
s.add(var_11C == 24422)
s.add(var_118 == 41178)
s.add(var_114 == 23447)
s.add(var_110 == 1805)
s.add(var_10C == 4135)
s.add(var_108 == 16900)
s.add(var_104 == 33381)
s.add(var_100 == 46767)
s.add(var_FC == 58551)
s.add(var_F8 == 34118)
s.add(var_F4 == 44920)
s.add(var_F0 == 11933)
s.add(var_EC == 20530)
s.add(var_E8 == 15699)
s.add(var_E4 == 36597)
s.add(var_E0 == 18231)
s.add(var_DC == 42941)
s.add(var_D8 == 61056)
s.add(var_D4 == 45169)
s.add(var_D0 == 41284)
s.add(var_CC == 1722)
s.add(var_C8 == 26423)
s.add(var_C4 == 47052)
s.add(var_C0 == 42363)
s.add(var_BC == 15033)
s.add(var_B8 == 18975)
s.add(var_B4 == 10788)
s.add(var_B0 == 33319)
s.add(var_AC == 63680)
s.add(var_A8 == 37085)
s.add(var_A4 == 51590)
s.add(var_A0 == 17798)
s.add(var_9C == 10127)
s.add(var_98 == 52388)
s.add(var_94 == 12746)
s.add(var_90 == 12587)
s.add(var_8C == 58786)
s.add(var_88 == 8269)
s.add(var_84 == 22613)
s.add(var_80 == 30753)
s.add(var_7C == 20853)
s.add(var_78 == 32216)
s.add(var_74 == 36650)
s.add(var_70 == 47566)
s.add(var_6C == 33282)
s.add(var_68 == 59180)
s.add(var_64 == 65196)
s.add(var_60 == 9228)
s.add(var_5C == 59599)
s.add(var_58 == 62888)
s.add(var_54 == 48719)
s.add(var_50 == 47348)
s.add(var_4C == 37592)
s.add(var_48 == 57612)
s.add(var_44 == 40510)
s.add(var_40 == 51735)
s.add(var_3C == 35879)
s.add(var_38 == 63890)
s.add(var_34 == 4102)
s.add(var_30 == 59511)
s.add(var_2C == 21386)
s.add(var_28 == 20769)
s.add(var_24 == 26517)
s.add(var_20 == 28153)
s.add(var_1C == 25252)
s.add(var_18 == 43789)
s.add(var_14 == 25633)
s.add(var_10 == 7314)

s.add(user_input_0x30 * 0xd5e5 + user_input_0x2c * 0x99ae + user_input_0x28 * var_288 + user_input_0x24 * 0x3922 + user_input_0x20 * 0xe15d + user_input_0x1c * var_294 + user_input_0x18 * var_298 + user_input_0x14 * 0xa89e + ( var_2B0 * user_input_0x00 - user_input_0x4 * var_2AC - user_input_0x8 * var_2A8 - user_input_0xc * 0xb4c1) + user_input_0x10 * var_2A0 == 0x1468753)
s.add(user_input_0x30 * 0xd5e5 + user_input_0x2c * 0x99ae + user_input_0x28 * var_288 + user_input_0x24 * 0x3922 + user_input_0x20 * 0xe15d + user_input_0x1c * var_294 + user_input_0x18 * var_298 + user_input_0x14 * 0xa89e + ( var_2B0 * user_input_0x00 - user_input_0x4 * var_2AC - user_input_0x8 * var_2A8 - user_input_0xc * 0xb4c1) + user_input_0x10 * var_2A0 == 0x1468753)
s.add(user_input_0x30 * 0xcfec + (user_input_0x14 * var_268 + user_input_0x10 * 0x39ca + ( var_27C * user_input_0x00 + user_input_0x4 * var_278 - user_input_0x8 * 0x1783) + user_input_0xc * 0x9832 - user_input_0x18 * 0x345 - user_input_0x1c * var_260 - user_input_0x20 * 0xc5a0 - user_input_0x24 * 0x2e35 - user_input_0x28 * 0x4e4e - user_input_0x2c * var_250) == 0x162f30)
s.add(user_input_0x30 * 0x2ccd + user_input_0x2c * var_21C + (((-var_248 * user_input_0x00 + user_input_0x4 * var_244 - user_input_0x8 * var_240) + user_input_0xc * 0x691b - user_input_0x10 * 0xad9e - user_input_0x14 * var_234 - user_input_0x18 * 0xfec5 - user_input_0x1c * var_22C) + user_input_0x20 * 0x4526 - user_input_0x24 * 0x8476) + user_input_0x28 * 0xa69e == 0xffb2939c)
s.add((user_input_0x1c * var_1F8 + ((var_214 * user_input_0x00 - user_input_0x4 * var_210 - user_input_0x8 * var_20C - user_input_0xc * 0x6252) + user_input_0x10 * 0xd42d - user_input_0x14 * 0x7e51) + user_input_0x18 * var_1FC - user_input_0x20 * var_1F4 - user_input_0x24 * var_1F0) + user_input_0x28 * var_1EC - user_input_0x2c * var_1E8 - user_input_0x30 * 0x2e58 == 0xffac90e3)
s.add(user_input_0x30 * 0xc3a2 + (user_input_0x24 * 0xa8b2 + (user_input_0x10 * 0xd669 + user_input_0xc * 0x876e + user_input_0x8 * var_1D8 + -0x36b5 * user_input_0x00 + user_input_0x4 * 0x3fc3 - user_input_0x14 * var_1CC - user_input_0x18 * var_1C8 - user_input_0x1c * 0xf219) + user_input_0x20 * var_1C0 - user_input_0x28 * 0xe91c) + user_input_0x2c * var_1B4 == 0x76d288)
s.add(user_input_0x2c * var_180 + (user_input_0x1c * var_190 + ((-var_1AC * user_input_0x00 - user_input_0x4 * 0x55fe) + user_input_0x8 * 0x3528 - user_input_0xc * var_1A0 - user_input_0x10 * var_19C - user_input_0x14 * 0x7bdc) + user_input_0x18 * var_194 - user_input_0x20 * 0xe6af - user_input_0x24 * var_188) + user_input_0x28 * var_184 - user_input_0x30 * 0x3d22 == 0xff78bf99)
s.add(user_input_0x30 * 0x49d7 + (((user_input_0x8 * 0x34a5 + -var_178 * user_input_0x00 + user_input_0x4 * 0xe200 - user_input_0xc * var_16C - user_input_0x10 * var_168 - user_input_0x14 * var_164 - user_input_0x18 * var_160) + user_input_0x1c * var_15C - user_input_0x20 * var_158) + user_input_0x24 * var_154 - user_input_0x28 * var_150 - user_input_0x2c * 0x8d6) == 0xfff496e3)
s.add((user_input_0x1c * var_128 + (-var_144 * user_input_0x00 + user_input_0x4 * var_140 - user_input_0x8 * var_13C - user_input_0xc * 0x57f2 - user_input_0x10 * var_134 - user_input_0x14 * var_130) + user_input_0x18 * 0xd03d - user_input_0x20 * 0xe6e7 - user_input_0x24 * var_120 - user_input_0x28 * 0x5f66) + user_input_0x2c * 0xa0da - user_input_0x30 * 0x5b97 == 0xff525e90)
s.add(user_input_0x30 * 0x4737 + ((user_input_0x14 * 0xe4b7 + user_input_0x10 * var_100 + (var_110 * user_input_0x00 + user_input_0x4 * var_10C - user_input_0x8 * 0x4204) + user_input_0xc * var_104 - user_input_0x18 * 0x8546 - user_input_0x1c * var_F4 - user_input_0x20 * 0x2e9d - user_input_0x24 * var_EC) + user_input_0x28 * var_E8 - user_input_0x2c * var_E4) == 0xfffd7704)
s.add(user_input_0x30 * 0xf8c0 + (user_input_0x28 * 0x2a24 + user_input_0x24 * var_B8 + user_input_0x20 * var_BC + user_input_0x1c * 0xa57b + ((-var_DC * user_input_0x00 + user_input_0x4 * 0xee80 - user_input_0x8 * 0xb071) + user_input_0xc * 0xa144 - user_input_0x10 * 0x6ba - user_input_0x14 * var_C8) + user_input_0x18 * var_C4 - user_input_0x2c * var_B0) == 0x897cbb)
s.add(user_input_0x30 * var_78 + (user_input_0x28 * var_80 + (user_input_0x1c * 0xe5a2 + user_input_0x18 * 0x312b + (-var_A8 * user_input_0x00 - user_input_0x4 * var_A4 - user_input_0x8 * 0x4586 - user_input_0xc * var_9C - user_input_0x10 * var_98) + user_input_0x14 * 0x31ca - user_input_0x20 * var_88) + user_input_0x24 * var_84 - user_input_0x2c * var_7C) == 0xffc05f9f)
s.add(user_input_0x30 * 0x9e3e + (user_input_0x24 * 0xb8f4 + (user_input_0x14 * var_60 + (var_74 * user_input_0x00 + user_input_0x4 * var_70 - user_input_0x8 * 0x8202 - user_input_0xc * var_68) + user_input_0x10 * var_64 - user_input_0x18 * var_5C - user_input_0x1c * var_58) + user_input_0x20 * var_54 - user_input_0x28 * 0x92d8) + user_input_0x2c * 0xe10c == 0x3e4761)
s.add(user_input_0x30 * var_10 + (user_input_0x24 * var_1C + user_input_0x20 * var_20 + (user_input_0x10 * 0xe877 + (var_40 * user_input_0x00 + user_input_0x4 * 0x8c27 - user_input_0x8 * 0xf992) + user_input_0xc * var_34 - user_input_0x14 * 0x538a - user_input_0x18 * var_28) + user_input_0x1c * var_24 - user_input_0x28 * 0xab0d) + user_input_0x2c * var_14 == 0x1b4945)
print(s.check())
print(s.model())
