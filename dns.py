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
    def prcoessFlags(self, flags):
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





    def processQuery(self, data):
        """
        Processes a DNS query, if it's valid. Blows up in your face otherwise
        """
        try:
            #first two bytes should be an ID field
            transID = struct.unpack(">H", data[0:2]) #short
            flags   = struct.unpack("<H", data[2:4])
            qCount  = struct.unpack(">H", data[4:6])
            aCount  = struct.unpack(">H", data[6:8])
            nsCount = struct.unpack(">H", data[8:10])
            resCount= struct.unpack(">H", data[10:12]) #additional records section

            flagList = self.parseFlags(flags)

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

if __name__ == "__main__":
        HOST, PORT = "0.0.0.0", 53
        server = SocketServer.UDPServer((HOST, PORT), DNSHandler)
        print "[+] Telling server to serve forever!"
        server.serve_forever()