#!/usr/bin/python

from copy import copy
from optparse import OptionParser, OptionValueError
import pprint
from random import seed, randint
import struct
from socket import *
from sys import exit, maxint as MAXINT
from time import time, sleep

from libs.collections_backport import OrderedDict
from libs.dnslib.RR import *
from libs.dnslib.Header import Header
from libs.dnslib.QE import QE
from libs.inetlib.types import *
from libs.util import *


# timeout in seconds to wait for reply
TIMEOUT = 5

# domain name and internet address of a root name server
ROOTNS_DN = "f.root-servers.net."
ROOTNS_IN_ADDR = "192.5.5.241"


# cache objects (not mandatory to use)
class RR_A_Cache:
    def __init__(self):
        self.cache = dict()     # domain_name -> [(ip_address, expiration_time, authoritative)]

    def put(self,domain_name,ip_addr,expiration,authoritative=False):
        if domain_name not in self.cache:
            self.cache[domain_name] = dict()
        self.cache[domain_name][ip_addr] = (expiration,authoritative)

    def contains(self,domain_name):
        return domain_name in self.cache
    
    def getIpAddresses(self,domain_name):
        return self.cache[domain_name].keys()

    def getExpiration(self,domain_name,ip_address):
        return self.cache[domain_name][ip_address][0]
    
    def getAuthoritative(self,domain_name,ip_address):
        return self.cache[domain_name][ip_address][1]

    def __str__(self):
        return str(self.cache)

class CN_Cache:
    def __init__(self):
        self.cache = dict()     # domain_name -> (cname, expiration_time)

    def put(self,domain_name,canonical_name,expiration):
        self.cache[domain_name] = (canonical_name,expiration)

    def contains(self,domain_name):
        return domain_name in self.cache

    def getCanonicalName(self, domain_name):
        return self.cache[domain_name][0]

    def getCanonicalNameExpiration(self,domain_name):
        return self.cache[domain_name][1]

    def __str__(self):
        return str(self.cache)

class RR_NS_Cache:
    def __init__(self):
        self.cache = dict()     # domain_name -> (NS_record,expiration_time, authoritative)
        
    def put(self,zone_domain_name,name_server_domain_name,expiration,authoritative):
        if zone_domain_name not in self.cache:
            self.cache[zone_domain_name] = OrderedDict()
        self.cache[zone_domain_name][name_server_domain_name] = (expiration,authoritative)

    def get(self,zone_domain_name):
        list_name_servers = []
        for name_server in self.cache[zone_domain_name]:
            list_name_servers += [(name_server,self.cache[zone_domain_name][name_server][0],self.cache[zone_domain_name][name_server][1])]
        return list_name_servers

    def contains(self,zone_domain_name):
        return zone_domain_name in self.cache

    def __str__(self):
        return str(self.cache)



def recurser(question, ipQuerried) :
    print "The IP that i've called was:", str(ipQuerried)
    try:
        cs.sendto(str(question), (str(ipQuerried), 53))
        (nsreply, server_address,) = cs.recvfrom(2048)  # some queries require more space
    except timeout:
        # Try a different one here
        print "This guy is empty!"
        return "empty"

    queryHeader = Header.fromData(nsreply)
    queryQE = QE.fromData(nsreply, queryHeader.__len__())

    originalQ = str(queryQE).split("IN")[0].strip()
    print "question was: ", originalQ

    offset = queryHeader.__len__() + queryQE.__len__()

    minRRLineLen = len(nsreply) - offset - 1
    rrCounter = 0
    nsTuples = []
    queryRRTuples = []
    addressCounter = 0
    cNameCounter = 0
    soaCounter = 0

    # Parsing all returned RRs
    while minRRLineLen < len(nsreply) - offset:
        # Get next glue line
        auxRRline = RR.fromData(nsreply, offset)

        # Append to RR list, update offset
        queryRRTuples.append(auxRRline)
        offset += queryRRTuples[rrCounter][1]

        queryRR = queryRRTuples[rrCounter][0]
        if queryRR.__class__ == RR_NS:
            # Not useful now
            print "This is a NS"
            parts = queryRR.__str__().split("NS")
            authorityAddr = parts[len(parts) - 1].strip()
            domain = parts[0].split("  ")[0].strip()
            nsTuples.append((domain, authorityAddr))
            print domain, authorityAddr
        elif queryRR.__class__ == RR_A:
            print "This is an RR_A"
            addressCounter = 1
            parts = queryRR.__str__().split("A")
            authorityAdditional = parts[0].split("  ")[0].strip()
            ip = parts[len(parts) - 1].strip()
            print authorityAdditional, ip, originalQ

            # Found required answer
            if authorityAdditional == originalQ: return nsreply
            else:
                reply = recurser(question, ip)
                if reply != "empty": return reply
        elif queryRR.__class__ == RR_CNAME:
            cname = str(queryRR).split("CNAME")[1].strip()
            reply = recurser(cname, ipQuerried)
            cNameCounter = 1
            if reply != "empty": return reply
            else: return "empty"
        elif queryRR.__class__ == RR_SOA:
            soa = str(queryRR).split("SOA")[1].strip().split(" ")[0]
            soaCounter = 1
            


        # Print everything else that might be relevant
        elif queryRR.__class__ != RR_AAAA:
            print queryRR, queryRR.__class__

        # Update minimum line length for safety stop
        if minRRLineLen > auxRRline[1]: minRRLineLen = auxRRline[1]
        rrCounter += 1

    if addressCounter == 0 & cNameCounter == 0 & soaCounter == 0:
        for tuple in nsTuples:
            reply = recurser(question, tuple[1])
            if reply != "empty": return reply


# >>> entry point of ncsdns.py <<<

# Seed random number generator with current time of day:
now = int(time())
seed(now)

# Initialize the pretty printer:
pp = pprint.PrettyPrinter(indent=3)

# Initialize the cache data structures
acache = RR_A_Cache()
acache.put(DomainName(ROOTNS_DN),InetAddr(ROOTNS_IN_ADDR),expiration=MAXINT,authoritative=True)

nscache = RR_NS_Cache()
nscache.put(DomainName("."),DomainName(ROOTNS_DN),expiration=MAXINT,authoritative=True)

cnamecache = CN_Cache()

# Parse the command line and assign us an ephemeral port to listen on:
def check_port(option, opt_str, value, parser):
    if value < 32768 or value > 61000:
        raise OptionValueError("need 32768 <= port <= 61000")
    parser.values.port = value

parser = OptionParser()
parser.add_option("-p", "--port", dest="port", type="int", action="callback",
                  callback=check_port, metavar="PORTNO", default=0,
                  help="UDP port to listen on (default: use an unused ephemeral port)")
(options, args) = parser.parse_args()

# Create a server socket to accept incoming connections from DNS
# client resolvers (stub resolvers):
ss = socket(AF_INET, SOCK_DGRAM)
ss.bind(("127.0.0.1", options.port))
serveripaddr, serverport = ss.getsockname()

# NOTE: In order to pass the test suite, the following must be the
# first line that your dns server prints and flushes within one
# second, to sys.stdout:
print "%s: listening on port %d" % (sys.argv[0], serverport)
sys.stdout.flush()

# Create a client socket on which to send requests to other DNS
# servers:
setdefaulttimeout(TIMEOUT)
cs = socket(AF_INET, SOCK_DGRAM)

# This is a simple, single-threaded server that takes successive
# connections with each iteration of the following loop:
while 1:
    (data, client_address,) = ss.recvfrom(512)  # DNS limits UDP msgs to 512 bytes
    if not data:
        log.error("client provided no data")
        continue
    else:
        question = data
        ip = ROOTNS_IN_ADDR
        # Final response back to client
        reply = recurser(question, ip)
        print "Found it!!!!! - ", reply

        address = (str(client_address[0]), 33333)
        print "Client is", client_address
        logger.log(DEBUG2, "our reply in full:")
        logger.log(DEBUG2, hexdump(reply))

        ss.sendto(reply, client_address)


