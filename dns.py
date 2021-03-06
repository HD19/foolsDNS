#!/usr/bin/python


import SocketServer
import socket
import struct
import sys
import traceback

MASTER_DICT = {} #Master dictionary containing DNS records to IPs -> a dictionary of dictionaries for each subdirectory

class DNSSocketServer(SocketServer.ThreadingMixIn, SocketServer.UDPServer):
    # Ctrl-C will cleanly kill all spawned threads
    daemon_threads = True
    # much faster rebinding
    allow_reuse_address = True

    def __init__(self, server_address, RequestHandlerClass, **kwargs):
        if 'config' not in kwargs:
            raise Exception("[!] No configuration passed!")
            sys.exit(1)
        self.config = kwargs['config']
        SocketServer.UDPServer.__init__(self, server_address, RequestHandlerClass)
        

#TODO: Implement what happens with queries we don't know the answer to. Also make that configurable.
# We should actually just use dns libs to do the lookup.
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
        return toRet



    def getNames(self, data, queryCount):
        names = []
        tdata = data[12:]
        for x in range(0, queryCount):
        #We should have the beginning of the question recrods
        #The format for the qName is [len][string of len bytes][len]../[0]
            tmpName = []
            tmpLen = struct.unpack("<B", tdata[0])[0]+1
            if tmpLen > 90: #Something's wrong here, usually we cut the data a byte too far
                tdata = data[11:]
                tmpLen = struct.unpack("<B", tdata[0])[0]+1
            tmpName.append(tdata[1:tmpLen])
            lastPos = tmpLen
            while tmpLen:
                tmpLen = struct.unpack("<B", tdata[lastPos])[0]
                lastPos += 1
                if tmpLen:
                    tmpName.append(tdata[lastPos:lastPos+tmpLen])
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
                    #print "[-] Couldn't find record for %s request" % (wholeName)
                    badList.append(wholeName)
                    break
            if wholeName not in badList:
                foundList.append(((wholeName),curDict['lld']))
        return (foundList, badList)

    def buildQueryResponse(self, transID, query, qCount, answers, flags):
        #We need to build the whole response, header and all.
        resp = self.buildHeader(transID, flags, qCount, len(answers), 0, 0)
        resp += query
        for answer in answers:
            resp += answer
        return resp

    def buildAnswers(self, answerList, type=1):
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
            data += struct.pack(">I", ttl) #TTL field is NOT limited to 2 bytes
            data += struct.pack(">H", 4) #Length of an IP address, will vary with other types
            data += struct.pack(">I", answer[1]) # Should be the IP, not the bundled hostname
            answers.append(data)
        return answers

    def processQuery(self, data):
        """
        Processes a DNS query, if it's valid. Blows up in your face otherwise
        """
        try:
            transID, flags, qCount, aCount, nsCount, resCount = self.processHeader(data)
            flagList = self.processFlags(flags)
            resp = None
            #Might need to change this flow if we're doing different types of queries
            if "QUERY" in flagList:
                origQuery = data[12:] # why is this 12?
                nameRecords = self.getNames(data, qCount) #Apparantly, this shouldn't be more than 1, ever.
                found, notFound = self.lookupNames(nameRecords)
                if len(notFound) > 0 and self.server.config['forward']:
                    forFound, forNotFound = self.forwardResolve(notFound)
                    found.extend(forFound)
                    notFound.extend([x for x in forNotFound if x not in notFound])     
                #We should decide what to do with not found queires, send a NXDOMAIN?
                answerData = self.buildAnswers(answerList=found) #build answer data for each found record
                respFlagList = ['RESPONSE', 'AUTHORITATIVE', 'RECRUSE', 'RECURSESUPPORT']
                respFlags = self.buildFlags(respFlagList)
                resp = self.buildQueryResponse(transID, query=origQuery, qCount=qCount, answers=answerData, flags=respFlags)
                return resp
        except Exception, ex:
            print "====================================="
            print "[-] Error attempting to process query"
            print "====================================="
            print traceback.format_exc()
            print "[-] Query data: %s" % data
            print "====================================="
            sys.exit()
    
    def handle(self):
        """
        Where the party starts.
        """
        try:
            data = self.request[0].strip() #Do we need to strip this?
            #print "[=] Processing request: %s" % data
            socket = self.request[1]
            toSend = self.processQuery(data)
            socket.sendto(toSend, self.client_address)
        except Exception, ex:
            print "========================================"
            print "[-] Critical failure in handling request"
            print ex
            print "========================================"
            sys.exit()
            
    def forwardResolve(self, nameList):
        #take the list of names, and ask the OS, which would resolve normally.
        retList = []
        badList = []
        for name in nameList:
            try:
                res = socket.gethostbyname(name)
                intAddr = struct.unpack(">L", socket.inet_aton(res))[0]
                retList.append((name, intAddr))
            except Exception, ex:
                print "[!] Couldn't find host for %s" % name
                badList.append(name)
        return (retList, badList)

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
        print "==============================================="
        print "[-] Error trying to parse configuration file at %s" % filePath
        print "==============================================="
        print ex
        sys.exit()

if __name__ == "__main__":
        if len(sys.argv) < 2:
            print 'Usage: %s <Configuration File> (host) (port)' % sys.argv[0]
            sys.exit(1)
        
        if len(sys.argv) == 3:
            HOST = sys.argv[2]
        elif len(sys.argv) == 4:
            HOST = sys.argv[2]
            PORT = int(sys.argv[3])
        else:
            HOST, PORT = "localhost", 53
        

        config = readConfig(sys.argv[1])
        MASTER_DICT = config['records']
        #HOST, PORT = "0.0.0.0", 53
        server = DNSSocketServer((HOST, PORT), DNSHandler, config=config)
        print "[=] Got host and port: (%s, %d)" % (HOST, PORT)
        print "[+] We shall serve, FOREVER!"
        server.serve_forever()  
