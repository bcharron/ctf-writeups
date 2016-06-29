#!/usr/bin/env python2
#
# Author: Benjamin Charron <bcharron@pobox.com
# CTF: Defcon Quals 2016
# Challenge: amadhj
#
# Code based on https://github.com/angr/angr-doc/blob/master/examples/google2016_unbreakable_1/solve.py

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

import IPython; IPython.embed()

