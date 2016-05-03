## This a demo of a simple plugin package which consists of a two functions.

## The first function takes a string (application data from tcpflow's buffer) returns a sample message.

def sampleFunction(appData):
	return "This message appears in the report.xml file under the 'plugindata' tag."

## The second function takes a string (application data from tcpflow's buffer) and writes the application (HTTP) header data to myOutput.txt in the python director. This function does not return and simply prints to stdout.

def headerWriter(appData):
	fName = "myOutput.txt"
	f = open("python/"+fName,'a')
	headerFinish = appData.find("\r\n\r\n")+4
	headerData = appData[:headerFinish+1]
	f.write(headerData)
	f.close()
	print "Wrote data to "+fName

## The third function takes a string (application datafrom tcpflow's buffer) and returns the binary result of taking the HTTP message (without headers) and performing a bitwise xor operation with a sample key (defined inside the function).

def xorOp(appData):

	#assume variable buffer includes message data
	
	key = "01101011101"
	newKey = ""
	keyLen = len(key)

	dataStart = appData.find("\r\n\r\n")+4
	httpData = appData[dataStart:]
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

