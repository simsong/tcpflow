def myFunction(packetContents):

	#assume variable buffer includes message data
	#message=packetContents


	"""
	#message="header data\r\n\r\nthis is the start of the message..."
	key = "01101011101"
	newKey = ""
	keyLen = len(key)

	dataStart = message.find("\r\n\r\n")+4
	httpData = message[dataStart:]
	binaryData=''.join(format(ord(x), 'b') for x in httpData)
	
	while len(newKey) + keyLen <= len(binaryData):
		newKey+=key

	i=0	
	while len(newKey) < len(binaryData):
		if i == keyLen:
			i = 0
		newKey+=key[i]
		i+=1

	xorRes = int(binaryData,2) ^ int(newKey,2)

	#print newKey
	#print binaryData
	#return '{0:b}'.format(xorRes)
	"""

	return "This is an altered buffer."


