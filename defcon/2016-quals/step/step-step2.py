#!/usr/bin/python

TARGET = "Please, may I have the flag now"

MASKS = [
	4, # bit 0 becomes bit 4
	2, # bit 1 becomes bit 2
	3, # bit 2 becomes bit 3
	7, # bit 3 becomes bit 7
	1, # bit 4 becomes bit 1
	6, # bit 5 becomes bit 6
	5, # bit 6 becomes bit 5
	0, # bit 7 becomes bit 0
]

reverse_masks = [None] * 8

for idx in range(len(MASKS)):
	new_bit = MASKS[idx]
	reverse_masks[new_bit] = idx

result = ""
for c in TARGET:
	i = ord(c)

	out = 0

	for bit in range(8):
		byte = 1 << bit

		if i & byte:
			out |= 1 << reverse_masks[bit]

	result = result + chr(out)

print result

