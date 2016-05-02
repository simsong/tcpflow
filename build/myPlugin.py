## This is a demo of a simple plugin which consists of a single function.

## This function takes a string (packet contents from tcpflow's buffer) and returns the first and last 10 characters of the packet.
def myFunction(packetContents):
	return packetContents[:10]+"..."+packetContents[-10:]


