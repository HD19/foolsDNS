#!/usr/bin/python

#do this using built-in socketserver

import SocketServer
import struct
import sys

class DNSHandler(SocketServer.BaseRequestHandler):
    """
    Takes in DNS requests, processes them and gives an anwer. If DNS forwarding is enabled, will attempt to forward the request.
    TODO: Implement pars-able settings file
    """
    masterDict = {} #Master dictionary containing DNS records to IPs -> a dictionary of dictionaries for each subdirectory
    def processFlags(self, flags):
        #give a list of flags that describe what's wanted
        #first bit is request or response
        toRet = []
        queryBit = (flags & 1)
        if queryBit:
            toRet.append("RESPONSE")
        else:
            toRet.append("QUERY")
        opCode = (flags >> 1) & 31
        if opCode == 0:
            toRet.append("STANDARD")
        if opCode == 4:
            toRet.append("INVERSE")

        authAnswerBit = (flags >> 5) & 1

        if authAnswerBit:
            toRet.append("AUTHORATIVE")

        truncBit = (flags >> 6) & 1
        if truncBit:
            toRet.append("TRUNC")

        recurse = (flags >> 7) & 1
        if recurse:
            toRet.append("RECURSE")

        recurseSupport = (flags >> 8) & 1
        if recurseSupport:
            toRet.append("RECURSESUPPORT")


        respCode = (flags >> 9) & 31
        if respCode == 1:
            toRet.append("FORMATERROR")
        if respCode == 2:
            toRet.append("SERVERFAILURE")
        if respCode == 3:
            toRet.append("NAMEERROR")
        if respCode == 4:
            toRet.append("NOTIMPLEMENTED")
        if respCode == 5:
            toRet.append("REFUSED")


    def getNames(self, data, queryCount):
        names = []
        for x in range(0, queryCount):
        #We should have the beginning of the question recrods
        #The format for the qName is [len][string of len bytes][len]../[0]
            tmpName = []
            tmpLen = struct.unpack("<B", data[0])[0]+1
            tmpName.append(data[1:tmpLen])
            lastPos = tmpLen
            while tmpLen:
                tmpLen = struct.unpack("<B", data[lastPos])[0]
                lastPos += 1
                if tmpLen:
                    tmpName.append(data[lastPos:lastPos+tmpLen])
                    lastPos = lastPos+tmpLen
            names.append(tmpName)
        return names


    def processHeader(self, data):
            #first two bytes should be an ID field
            transID = struct.unpack(">H", data[0:2])[0] #short
            flags   = struct.unpack(">H", data[2:4])[0]
            qCount  = struct.unpack(">H", data[4:6])[0]
            aCount  = struct.unpack(">H", data[6:8])[0]
            nsCount = struct.unpack(">H", data[8:10])[0]
            resCount= struct.unpack(">H", data[10:12])[0] #additional records section

            return (transID, flags, qCount, aCount, nsCount, resCount)

    def lookupNames(self, nameRecordes):
        for name in nameRecords:
            #look through our record list and match names for addresses
            if name[-1] in self.masterDict:
                curDict = self.masterDict[name[-1]]
            for x in range(len(name), 0, -1):
                if name[x] in curDict and x != 0:
                    curDict = curDict[name[x]]
                elif x == 0:
                    return curDict[name[x]]
                else:
                    return None


    def processQuery(self, data):
        """
        Processes a DNS query, if it's valid. Blows up in your face otherwise
        """
        try:
            transID, flags, qCount, aCount, nsCount, resCount = self.processHeader(data)
            flagList = self.processFlags(flags)

            if "QUERY" in flagList:
                #this is a query
                nameRecords = self.getNames(data[12:], qCount)




        except Exception, ex:
            print "[-] Error attempting to process query"
            print "====================================="
            print ex
            print "====================================="
            sys.exit()
    
    def handle(self):
        """
        Where the party starts.
        """
        data = self.request[0].strip() #Do we need to strip this?
        socket = self.request[1]
        
        toSend = self.processQuery(data)

def readConfig(filePath):
    #Open a specified file path and read the DNS configuration
    try:
        config = {}
        with open(filePath, 'r') as inFile:
            for line in inFile:
                    if line[0] == '[':
                        config['sections'].append(line.strip('[]'))



if __name__ == "__main__":
        HOST, PORT = "0.0.0.0", 53
        server = SocketServer.UDPServer((HOST, PORT), DNSHandler)
        print "[+] Telling server to serve forever!"
        server.serve_forever()