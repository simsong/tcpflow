## Example of a python plugin for tcpflow.
## This sample contains three functions.

## The first function takes a string and returns a sample message.
## The input string contains the application data from tcpflow's buffer.

def sampleFunction(appData):
    return "This message appears in the XML tag 'tcpflow:result' of report.xml (DFXML)."

## The second function takes a string (application data)
## and writes the application (HTTP) header data to the file
## myOutput.txt located in the python director.
## This function does not return and simply prints to stdout.

def headerWriter(appData):
    fName = "myOutput.txt"
    f = open("python/" + fName, 'a')
    headerFinish = appData.find("\r\n\r\n") + 4
    headerData = appData[:headerFinish+1]
    f.write(headerData)
    f.close()
    print "Wrote data to " + fName

## The third function takes a string (application data)
## parses the HTTP message (without headers)
## performs a bitwise xor operation with a key defined in the function
## and returns the text corresponding to this binary result.

def xorOp(appData):
    # Assume variable buffer includes message data.
    dataStart = appData.find("\r\n\r\n") + 4
    httpData = appData[dataStart:]
    binaryData = ''.join(format(ord(x), 'b') for x in httpData)
    if len(binaryData) < 1:
        return 0

    key = "01101011101"
    keyLen = len(key)
    newKey = ""
    while len(newKey) + keyLen <= len(binaryData):
        newKey += key
    i = 0
    while len(newKey) < len(binaryData):
        if i == keyLen:
            i = 0
        newKey += key[i]
        i += 1
    xorRes = int(binaryData,2) ^ int(newKey,2)
    return '{0:b}'.format(xorRes)
