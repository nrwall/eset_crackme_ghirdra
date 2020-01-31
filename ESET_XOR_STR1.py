#@narwhal
#@category ESET_Crackme
#@keybinding 
#@menupath 
#@toolbar 


import struct

print("[*] Finding References to XOR_FUNCTION_1")
listing = currentProgram.getListing()
loc = 0x4013a0 # decode function
#Get References to XOR Function 1
refs = getReferencesTo(toAddr(loc))
print("[+] Success: Found %d References to XOR_FUNCTION_1" % len(refs))
#List of addresses we have decoded already
alreadyDecoded = []
#iterates through each callee and attempts to decrypt string.
for r in refs:

	callee = r.getFromAddress()
	inst = getInstructionAt(callee)
	
	# The parameters we care about passed to the decode function
	# are on the stack
	# iterate through max 15 instructions
	# to search for values pushed onto stack

	i = 0 			#counter
	pushCount = 0	#Indicates which stack position to store value
	stack = {'sBuff':0,'sLen':0,'XorStart':0,'XorInc':0} 	#dictionary w/ stack values
	svNames = ['sBuff','sLen','XorStart','XorInc']			#list w/ dictionary info for push count
	
	#Grabs the stack arguments and puts them in stack dictionary
	while((i < 15) and (pushCount < 4)):
		inst = getInstructionBefore(inst)
		if "PUSH" in inst.toString():
			#print(inst.toString())
			stack[svNames[pushCount]] = int(inst.toString().split(' ')[1],16)
			pushCount += 1
		elif "POP" in inst.toString():
			pushCount -= 1
		i += 1
	
	#Check to see if we have decoded this address yet, then decode if not
	if stack['sBuff'] not in alreadyDecoded:
		try:	
			bytes = getBytes(toAddr(hex(stack['sBuff'])),stack['sLen'])
			decodedString = ''
			for i2 in range(len(bytes)):
				decodedString += chr((bytes[i2] & 0xff) ^ ((stack['XorStart'] + (stack['XorInc'] * i2) & 0xff)))
			print("[+] Successfully Decoded String: ")
			print(decodedString)
			alreadyDecoded.append(stack['sBuff'])
		except:
			print("[-] Failed To Decode String: ")
	
