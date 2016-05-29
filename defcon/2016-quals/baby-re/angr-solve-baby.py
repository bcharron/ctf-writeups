#!/usr/bin/env python2
#
# Author: Benjamin Charron <bcharron@pobox.com
# CTF: Defcon Quals 2016
# Challenge: baby-re
#
# Code based on https://github.com/angr/angr-doc/blob/master/examples/google2016_unbreakable_1/solve.py

import angr

START_ADDR = 0x4006c6 	# Start of CheckSolution
FIND_ADDR  = 0x4025cc 	# address of function that prints correct
AVOIDS = (0x401693, 0x4017db, 0x401927, 0x40192b, 0x401a72, 0x401bbe, 0x401d0d, 0x401e59, 0x401fa7, 0x4020ef, 0x40223b, 0x40237f, 0x4024a0, 0x004025C5)

# User input array ptr is at $rbp-696, the actual array is somewhere on the stack
#INPUT_ADDR = 0x6042c0 # location in memory of user input

INPUT_LENGTH = 13	# There are 13 bytes (but used as dwords) to identify

def dword(state, n):
    """Returns a symbolic BitVector and contrains it to byte values"""
    vec = state.se.BVS('c{}'.format(n), 32, explicit_name=True)
    return vec

p = angr.Project('baby-re')

print('adding BitVectors and constraints')
state = p.factory.blank_state(addr=0x4006c6)

user_input_array_addr = state.regs.rsp + 100
state.regs.rbp = state.regs.rsp
state.regs.rdi = user_input_array_addr

# Return address
state.stack_push(0x4028e5)

# state.memory.store(state.regs.rsp, 0)

for i in range(INPUT_LENGTH):
	d = dword(state, i)
	state.memory.store(user_input_array_addr + i * 4, d)
	##state.add_constraints(cond)

print('Creating path')
path = p.factory.path(state)

print('Creating explorer')
ex = p.surveyors.Explorer(start=path, find=(FIND_ADDR,), avoid=AVOIDS)

print('running explorer')
ex.run()

print('got something')
print ex.found
#print ex._f.state
#import IPython; IPython.embed()

for found in ex.found:
	for i in range(13):
		addr = found.state.regs.rdi + i * 4
		d = found.state.se.any_int(found.state.memory.load(addr, 1))

		print "0x%x (%c)" % ( d, chr(d) )

