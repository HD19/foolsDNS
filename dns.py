#!/usr/bin/python


import SocketServer
import socket
import struct
import sys

MASTER_DICT = {} #Master dictionary containing DNS records to IPs -> a dictionary of dictionaries for each subdirectory

class DNSHandler(SocketServer.BaseRequestHandler):
    """
    Takes in DNS requests, processes them and gives an answer. If DNS forwarding is enabled, will attempt to forward the request.
    """
    global MASTER_DICT

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
            toRet.append("AUTHORITATIVE")

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
        return toRet

    def buildFlags(self, flagList):
        toRet = 0
        #For each flag, we need to set the appropriate bits in an integer
        if 'RESPONSE' in flagList:
            toRet |= (1 << 15)
        if 'INVERSE' in flagList:
            toRet |= (4 << 14)
        if 'AUTHORITATIVE' in flagList:
            toRet |= (1 << 10)
        if 'TRUNC' in flagList:
            toRet |= (1 << 9)
        if 'RECURSE' in flagList:
            toRet |= (1 << 8)
        if 'RECURSESUPPORT' in flagList:
            toRet |= (1 << 7)
        if 'FORMATERROR' in flagList:
            toRet |= (1 << 6)
        if 'SERVERFAILURE' in flagList:
            toRet |= (2 << 6)
        if 'NAMEERROR' in flagList:
            toRet |= (3 << 6)
        if 'NOTIMPLEMENTED' in flagList:
            toRet |= (4 << 6)
        if 'REFUSED' in flagList:
            toRet |= (5 << 6)



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

    def buildHeader(self, transID, flags, qCount, aCount, nsCount, resCount):
        header = struct.pack(">H", transID)
        header += struct.pack(">H", flags)
        header += struct.pack(">H", qCount)
        header += struct.pack(">H", aCount)
        header += struct.pack(">H", nsCount)
        header += struct.pack(">H", resCount)
        return header

    def processHeader(self, data):
            #first two bytes should be an ID field
            transID = struct.unpack(">H", data[0:2])[0] #short
            flags   = struct.unpack(">H", data[2:4])[0]
            qCount  = struct.unpack(">H", data[4:6])[0]
            aCount  = struct.unpack(">H", data[6:8])[0]
            nsCount = struct.unpack(">H", data[8:10])[0]
            resCount= struct.unpack(">H", data[10:12])[0] #additional records section

            return (transID, flags, qCount, aCount, nsCount, resCount)

    def lookupNames(self, nameRecords):
        foundList = []
        badList = []
        for name in nameRecords:
            #look through our record list and match names for addresses
            wholeName = '.'.join(name)
            name.reverse()
            curDict = MASTER_DICT
            for part in name:
                if part in curDict:
                    curDict = curDict[part]
                else:
                    print "[-] Couldnt record for %s request" % (wholeName)
                    badList.append(wholeName)
                    break

            foundList.append((wholeName),curDict['lld'])
        return (foundList, badList)

    def buildAnswers(self, type, answerList):
        answers = []
        #build a query response containing only type A answers for now
        name = "\xc0\x0c" #\xc means pointer, 00c is the offset
        #type is already defined by caller
        dnsClass = 1 #Internet Address
        ttl = 10 # Seconds valid, TODO: Make this configurable
        #Keep in mind, we already have the integer representing the IP in the answer list
        for answer in answerList:
            data = name
            data += struct.pack(">H", type)
            data += struct.pack(">H", dnsClass)
            data += struct.pack(">H", ttl)
            data += struct.pack(">H", 4) #Length of an IP address, will vary with other types
            data += struct.pack(">H", answer[1]) # Should be the IP, not the bundled hostname
            answers.append(data)
        return answers

    def processQuery(self, data):
        """
        Processes a DNS query, if it's valid. Blows up in your face otherwise
        """
        try:
            transID, flags, qCount, aCount, nsCount, resCount = self.processHeader(data)
            flagList = self.processFlags(flags)
            if "QUERY" in flagList:
                #this is a query
                origQuery = data[12:]
                nameRecords = self.getNames(origQuery, qCount) #Apparantly, this shouldn't be more than 1, ever.
                found, notFound = self.lookupNames(nameRecords)
                #We should decide what to do with not found queires, send a NXDOMAIN?
                answerData = self.buildAnswers(1, found) #build answer data for each found record
                print '[=] Debug print!'



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
    #Warning: User controlled input.
    #Open a specified file path and read the DNS configuration
    try:
        config = {}
        dnsRecords = {}
        config['global'] = []
        curSection = 'global'
        with open(filePath, 'r') as inFile:
            for line in inFile:
                if line[0] == '\n' or line[0] == '#':
                    continue
                if '[' in line:
                    curSection = ''.join(c for c in line if c not in '[]\n')
                    continue
                if curSection not in config:
                    config[curSection] = []
                config[curSection].append(line.strip())
            if 'global' in config:
                for entry in config['global']:
                    tmpOpt = entry.split(':')
                    config[tmpOpt[0]] = tmpOpt[1]
            if 'dns' in config:
                for entry in config['dns']:
                    '''
                    This is the important section, we need to create all the mappings here.
                    If this section doesn't exist, we should bail.
                    format should be like so:
                        some.addr.tld\tipaddress
                    '''
                    #First get the two main parts
                    chunks = entry.split()
                    name = chunks[0]
                    intAddr = struct.unpack(">L", socket.inet_aton(chunks[1]))[0]
                    #Get ip integer
                    parts = name.split('.')
                    parts.reverse() #reverse() doesn't return anything, wth?
                    curDict = dnsRecords
                    x = 0
                    while x != len(parts):
                        if parts[x] in curDict:
                            curDict = curDict[parts[x]]
                        else:
                            curDict[parts[x]] = {}
                            curDict = curDict[parts[x]]
                        x += 1
                    curDict['lld'] = intAddr #There might be a request for a lower domain.
            config['records'] = dnsRecords
            return config
    except Exception, ex:
        print "[-] Error trying to parse configuration file at %s" % filePath
        print "==============================================="
        print ex
        sys.exit()

if __name__ == "__main__":
        if len(sys.argv) < 2:
            print 'Usage: %s <Configuration File>' % sys.argv[0]
            sys.exit(1)

        config = readConfig(sys.argv[1])
        MASTER_DICT = config['records']
        HOST, PORT = "0.0.0.0", 53
        server = SocketServer.UDPServer((HOST, PORT), DNSHandler)
        print "[+] Telling server to serve forever!"
        server.serve_forever()