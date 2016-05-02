## This a demo of a simple plugin package which consists of a two functions.

## The first function takes a string (packet contents from tcpflow's buffer) and returns the first and last 10 characters of the packet.

def sampleFunction(packetContents):
	return packetContents[:10]+"..."+packetContents[-10:]

## The second function takes a string (packet contents from tcpflow's buffer) and returns the binary result of taking the HTTP message (without headers) and performing a bitwise xor operation with a sample key (defined inside the function).

def xorOp(packetContents):

	#assume variable buffer includes message data
	
	key = "01101011101"
	newKey = ""
	keyLen = len(key)

	dataStart = packetContents.find("\r\n\r\n")+4
	httpData = packetContents[dataStart:]
	binaryData=''.join(format(ord(x), 'b') for x in httpData)
	if len(binaryData)<1:
		return 0
	else:
		while len(newKey) + keyLen <= len(binaryData):
			newKey+=key

		i=0	
		while len(newKey) < len(binaryData):
			if i == keyLen:
				i = 0
			newKey+=key[i]
			i+=1

		xorRes = int(binaryData,2) ^ int(newKey,2)

		return '{0:b}'.format(xorRes)

