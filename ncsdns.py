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

# globals
answers = []
auths = []
additionals = []


# cache objects (not mandatory to use)
class RR_A_Cache:
    def __init__(self):
        self.cache = dict()  # domain_name -> [(ip_address, expiration_time, authoritative)]

    def put(self, domain_name, ip_addr, expiration, authoritative=False):
        if domain_name not in self.cache:
            self.cache[domain_name] = dict()
        self.cache[domain_name][ip_addr] = (expiration, authoritative)

    def contains(self, domain_name):
        return domain_name in self.cache

    def getIpAddresses(self, domain_name):
        return self.cache[domain_name].keys()

    def getExpiration(self, domain_name, ip_address):
        return self.cache[domain_name][ip_address][0]

    def getAuthoritative(self, domain_name, ip_address):
        return self.cache[domain_name][ip_address][1]

    def __str__(self):
        return str(self.cache)


class CN_Cache:
    def __init__(self):
        self.cache = dict()  # domain_name -> (cname, expiration_time)

    def put(self, domain_name, canonical_name, expiration):
        self.cache[domain_name] = (canonical_name, expiration)

    def contains(self, domain_name):
        return domain_name in self.cache

    def getCanonicalName(self, domain_name):
        return self.cache[domain_name][0]

    def getCanonicalNameExpiration(self, domain_name):
        return self.cache[domain_name][1]

    def __str__(self):
        return str(self.cache)


class RR_NS_Cache:
    def __init__(self):
        self.cache = dict()  # domain_name -> (NS_record,expiration_time, authoritative)

    def put(self, zone_domain_name, name_server_domain_name, expiration, authoritative):
        if zone_domain_name not in self.cache:
            self.cache[zone_domain_name] = OrderedDict()
        self.cache[zone_domain_name][name_server_domain_name] = (expiration, authoritative)

    def get(self, zone_domain_name):
        list_name_servers = []
        for name_server in self.cache[zone_domain_name]:
            list_name_servers += [(name_server, self.cache[zone_domain_name][name_server][0],
                                   self.cache[zone_domain_name][name_server][1])]
        return list_name_servers

    def contains(self, zone_domain_name):
        return zone_domain_name in self.cache

    def __str__(self):
        return str(self.cache)


def recurser(question, ipQuerried):
    print "\n"
    print "The IP that i've called was:", str(ipQuerried)


    queryHeader = Header.fromData(question)
    queryQE = QE.fromData(question, queryHeader.__len__())
    if acache.contains(queryQE._dn):
        ips = acache.getIpAddresses(queryQE._dn)
        flag = 0
        for ip in ips:
            ttl = acache.getExpiration(queryQE._dn, ip) - int(time())
            if ttl < 0:
                # too late for this record
                acache.cache.pop(queryQE._dn)
            else:
                answers.append(RR_A(queryQE._dn, ttl, inet_aton(ip)))
                flag = 1

        if flag is 1:
             newHeader = Header(queryHeader._id, 0, 0, 1, ancount=len(answers))
             newQE = QE(dn=queryQE._dn)
             print newHeader.pack()
             print newQE.pack()
             return newHeader.pack() + newQE.pack()

    try:
        cs.sendto(question, (ipQuerried, 53))
        (nsreply, server_address,) = cs.recvfrom(2048)  # some queries require more space
    except timeout:
        return "empty"
    if len(nsreply) < 33: return "empty" # handle case where there is an empty response

    queryHeader = Header.fromData(nsreply)
    queryQE = QE.fromData(nsreply, queryHeader.__len__())

    originalQ = str(queryQE).split("IN")[0].strip()
    print "question was: ", originalQ

    offset = queryHeader.__len__() + queryQE.__len__()

    minRRLineLen = len(nsreply) - offset - 1
    rrCounter = 0
    nsAuthorities = []
    rra = []
    cnames = []
    queryRRTuples = []

    # Parsing all returned RRs
    while minRRLineLen < len(nsreply) - offset:
        # Get next glue line
        auxRRline = RR.fromData(nsreply, offset)

        # Append to RR list, update offset
        queryRRTuples.append(auxRRline)
        offset += queryRRTuples[rrCounter][1]

        queryRR = queryRRTuples[rrCounter][0]
        if queryRR.__class__ == RR_NS:
            nsAuthorities.append(queryRR)
        elif queryRR.__class__ == RR_A:
            rra.append(queryRR)
        elif queryRR.__class__ == RR_CNAME:
            cnames.append(queryRR)

        # Update minimum line length for safety stop
        if minRRLineLen > auxRRline[1]: minRRLineLen = auxRRline[1]
        rrCounter += 1

    if len(rra) == 0 and len(cnames) == 0:
        for auth in nsAuthorities:
            # newNsHeader = Header(randint(1, 65000), Header.OPCODE_QUERY, Header.RCODE_NOERR, qdcount=1)
            # newNsQE = QE(dn=auth._nsdn)
            # newNsQuery = newNsHeader.pack() + newNsQE.pack()
            reply = recurser(question, str(auth._nsdn))
            if reply != "empty" and reply != None:
                return reply
            else:
                return "empty"

    if len(cnames) > 0:
        for queryRR in cnames:
            answers.append(queryRR)
            print queryRR._cname

            newHeader = Header(randint(1, 65000), Header.OPCODE_QUERY, Header.RCODE_NOERR, qdcount=1)
            newQE = QE(dn=queryRR._cname)
            newQuery = newHeader.pack() + newQE.pack()

            reply = recurser(newQuery, ROOTNS_IN_ADDR)
            if reply != "empty" and reply != None:
                return reply
            else:
                return "empty"


    if len(rra) > 0:
        for queryRR in rra:
            if acache.contains(queryRR._dn) == False:
                timeNow = int(time())
                acache.put(queryRR._dn, inet_ntoa(queryRR._addr), queryRR._ttl+timeNow, authoritative=True)
            parts = queryRR.__str__().split("A")
            ip = parts[len(parts) - 1].strip()

            # Found required answer
            if queryRR._dn == originalQ:

                # Add all answers
                counter = 0
                while counter < len(rra):
                    if rra[counter]._dn == originalQ:
                        answers.append(rra[counter])
                        rra.pop(counter)
                    counter += 1

                # Add found authority records
                auths.extend(nsAuthorities)
                additionals.extend(rra)

                return nsreply
            else:
                reply = recurser(question, ip)
                if reply != "empty" and reply != None: return reply



# >>> entry point of ncsdns.py <<<

# Seed random number generator with current time of day:
now = int(time())
seed(now)

# Initialize the pretty printer:
pp = pprint.PrettyPrinter(indent=3)

# Initialize the cache data structures
acache = RR_A_Cache()
acache.put(DomainName(ROOTNS_DN), InetAddr(ROOTNS_IN_ADDR), expiration=MAXINT, authoritative=True)

nscache = RR_NS_Cache()
nscache.put(DomainName("."), DomainName(ROOTNS_DN), expiration=MAXINT, authoritative=True)

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
    answers = []
    auths = []
    additionals = []
    if not data:
        log.error("client provided no data")
        continue
    else:
        question = data
        ip = ROOTNS_IN_ADDR
        initialHeader = Header.fromData(data)
        initialQE = QE.fromData(data, initialHeader.__len__())
        initialId = initialHeader._id
        # Final response back to client
        nsreply = recurser(question, ip)

        # Recreate the response using the initialID
        receivedHeader = Header.fromData(nsreply)
        queryHeader = Header(initialId, 0, 0, 1, ancount=len(answers), nscount=len(auths), arcount=len(additionals), qr=True, aa=True,
                             rd=False, ra=True)
        offset = queryHeader.__len__() + initialQE.__len__()

        response = queryHeader.pack() + initialQE.pack()

        for ans in answers:
            response += ans.pack()
        for auth in auths:
            response += auth.pack()
        for adds in additionals:
            response += adds.pack()

        print "Finished!", response.__str__()

        print "Caching incoming", acache.__str__()

        address = (str(client_address[0]), 33333)

        logger.log(DEBUG2, "our reply in full:")
        logger.log(DEBUG2, hexdump(response))

        ss.sendto(response, client_address)
