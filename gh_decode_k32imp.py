#@narwhal
#@category ESET_Crackme
#@keybinding 
#@menupath 
#@toolbar 

#Markup for Wrapper
listing = currentProgram.getListing()
loc = 0x401c79 
# get all code references made to the function
refs = getReferencesTo(toAddr(loc))
for r in refs:
	callee = r.getFromAddress()
	inst = getInstructionAt(callee)
	if "CALL" in inst.toString():
	    while "PUSH" not in inst.toString():
	        inst = getInstructionBefore(inst)
	    hash = inst.toString().lstrip("PUSH ")
            with open("C:\Users\user\Desktop\hashed_exports.txt") as elist:
                for line in elist:
                    if hash in line:
						codeUnit = listing.getCodeUnitAt(inst.getAddress())
						codeUnit.setComment(codeUnit.EOL_COMMENT,line.rstrip('\n'))

#Markup without Wrapper
loc = 0x401c03
# get all code references made to the function
refs = getReferencesTo(toAddr(loc))
for r in refs:
	callee = r.getFromAddress()
	inst = getInstructionAt(callee)
	if ("CALL" in inst.toString()) & (inst.address.toString() != "00401c95"):
	    while "PUSH" not in inst.toString():
	        inst = getInstructionBefore(inst)
	    hash = inst.toString().lstrip("PUSH ")
            with open("C:\Users\user\Desktop\hashed_exports.txt") as elist:
                for line in elist:
                    if hash in line:
						codeUnit = listing.getCodeUnitAt(inst.getAddress())
						codeUnit.setComment(codeUnit.EOL_COMMENT,line.rstrip('\n'))