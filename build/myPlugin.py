
#assume variable buffer includes message data

key = "01101011101"
newKey = ""
keyLen = len(key)

dataStart = message.find("\r\n\r\n")+4
httpData = message[dataStart:]
binaryData=''.join(format(ord(x), 'b') for x in st)

while len(newKey) + keyLen <= len(binaryData):
	newKey+=key

i=0
while len(newKey) < len(binaryData):
	if i == keyLen:
		i = 0
	newKey+=key[i]
	i+=1

return (binaryData) ^ int(key)
