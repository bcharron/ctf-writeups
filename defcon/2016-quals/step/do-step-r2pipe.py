#!/usr/bin/python2

import IPython
import json
import r2pipe
import sys

BREAK_ADDR = 0x00400952

class Step:
	def __init__(self):
		self.r2 = r2pipe.open("dbg://./step", ["-e dbg.profile=step.dbg_profile"])
		self.pid = self.get_pid()
		self.prev_rip = 0x00
		self.fd = open("trace.asm", "w+")

	def get_pid(self):
		dpj = self.r2.cmdj("dpj")
		current = filter(lambda d: d['path'] == "(current)", dpj)[0]
		current_pid = current["pid"]

		return(current_pid)

	def get_reg(self, reg):
		val = int(self.r2.cmd("dr?%s" % reg), 16)

		return(val)

	def get_rip(self):
		rip = self.get_reg("rip")

		return(rip)

	def show_rip(self):
		rip = self.get_rip()

		print "RIP: %s" % rip

	def deliver_trap(self):
		#print "Skip trap (dck 5 %s)" % self.pid
		self.r2.cmd("dck 5 %s" % self.pid)

	def close(self):
		self.fd.close()

	def handle_break(self):
		#rip = int(core.cmd_str("dr?rip"), 16)
		rip = self.get_rip()
		di = self.r2.cmdj("dij")

		#print "\n\n"
		#print "** Break at 0x%08x, reason = %s, type = %s, signum = %d" % ( rip, di["stopreason"], di["type"], di["signum"] )
		#print "RAX: %s" % self.r2.cmd("dr?rax")

		#print di
		#print "INBP: %s" % di["inbp"]

		if rip == BREAK_ADDR:
			print "-- show_trap_addr"
			#rdx = self.get_reg("rdx")
			#addr = self.r2.cmd("pxQ 8 @ %s + 0xa8" % rdx).strip().split()[1]
			addr = self.r2.cmd("pxQ 8 @ rdx + 0xa8").strip().split()[1]
			print "addr: %s" % addr

			#print self.r2.cmd("pd 10 @ %s" % BREAK_ADDR)
			#print self.r2.cmd("px 8 @ %s" % BREAK_ADDR)

			print "Continue (dc)"
			self.r2.cmd("dc")
		elif rip == 0x00400a20:
			print "-- leave bp"
			print step.r2.cmd("pd 10 @ 0x00400e96")

			print "Continue (dc)"
			print step.r2.cmd("dc")
		else:
			if self.prev_rip > 0:
				x = self.r2.cmd("pd 1 @ 0x%08X" % self.prev_rip)
				self.fd.write(x)

			self.prev_rip = rip

			self.deliver_trap()

step = Step()
step.r2.cmd("dc")

for x in range(70000):
	step.handle_break()

step.close()

IPython.embed()
sys.exit(0)



