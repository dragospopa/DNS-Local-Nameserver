#!/usr/bin/python

from copy import copy
from optparse import OptionParser, OptionValueError
import pprint
from random import seed, randint
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

# Globals used for convenience
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


# Main recursive function to solve querries
def recurser(question, ipQuerried):
    queryHeader = Header.fromData(question)
    queryQE = QE.fromData(question, queryHeader.__len__())
    if acache.contains(queryQE._dn):
        ips = acache.getIpAddresses(queryQE._dn)
        foundRRA = 0
        for ip in ips:
            ttl = acache.getExpiration(queryQE._dn, ip) - int(time())
            if ttl < 0:
                # too late for this record
                acache.cache.pop(queryQE._dn)
            else:
                answers.append(RR_A(queryQE._dn, ttl, inet_aton(ip)))
                foundRRA = 1

        if foundRRA is 1:
             newHeader = Header(queryHeader._id, 0, 0, 1, ancount=len(answers))
             newQE = QE(dn=queryQE._dn)
             return newHeader.pack() + newQE.pack()

    elif cnamecache.contains(queryQE._dn):
        cn = cnamecache.getCanonicalName(queryQE._dn)
        ttl = cnamecache.getCanonicalNameExpiration(queryQE._dn) - int(time())
        if ttl < 0:
            cnamecache.cache.pop(queryQE._dn)
        else:
            newHeader = Header(queryHeader._id, 0, 0, 1)
            newQE = QE(dn=cn)
            reply = recurser(newHeader.pack() + newQE.pack(), ROOTNS_IN_ADDR)
            if reply != None:
                answers.append(RR_CNAME(queryQE._dn, ttl, cn))
                return reply

    try:
        cs.sendto(question, (ipQuerried, 53))
        (nsreply, server_address,) = cs.recvfrom(2048)  # some queries require more space
    except timeout:
        return None
    if len(nsreply) < 43: return None # handle case where there is an empty response

    # Store these for later use when we want to solve CNAMEs or NSs
    queryHeader = Header.fromData(nsreply)
    queryQE = QE.fromData(nsreply, queryHeader.__len__())
    originalQ = str(queryQE).split("IN")[0].strip()

    offset = queryHeader.__len__() + queryQE.__len__()

    # We'll need these for parsing, trust me
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

    # Start the handling of RRs

    # Case where we only got NS back
    if len(rra) == 0 and len(cnames) == 0:
        for auth in nsAuthorities:
            reply = recurser(question, str(auth._nsdn))
            return reply

    # Cache NS for later
    if len(nsAuthorities) > 0:
        for ns in nsAuthorities:
            nscache.put(ns._dn, ns._nsdn, ns._ttl + int(time()),authoritative=True)

    # Cache CNAMEs for later and querry them
    if len(cnames) > 0:
        for queryRR in cnames:
            if cnamecache.contains(queryRR._dn) == False:
                cnamecache.put(queryRR._dn, queryRR._cname, queryRR._ttl + int(time()))
            answers.append(queryRR)

            newHeader = Header(randint(1, 65000), Header.OPCODE_QUERY, Header.RCODE_NOERR, qdcount=1)
            newQE = QE(dn=queryRR._cname)
            newQuery = newHeader.pack() + newQE.pack()

            reply = recurser(newQuery, ROOTNS_IN_ADDR)
            return reply

    # Cache all RR_As for later, look if we got the one we are looking for
    if len(rra) > 0:
        for queryRR in rra:
            if acache.contains(queryRR._dn) == False:
                acache.put(queryRR._dn, inet_ntoa(queryRR._addr), queryRR._ttl+ int(time()), authoritative=True)
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
                return nsreply
            else:
                reply = recurser(question, ip)
                return reply


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

    # Making sure those globals are ready to be used
    answers = []
    auths = []
    additionals = []

    if not data:
        log.error("client provided no data")
        continue
    else:

        # Saving all this data for response reconstrucion later
        question = data
        ip = ROOTNS_IN_ADDR
        initialHeader = Header.fromData(data)
        initialQE = QE.fromData(data, initialHeader.__len__())
        initialId = initialHeader._id

        # The call to solve the main query
        nsreply = recurser(question, ip)

        if nsreply == None:
            # Respond with name error
            newHeader = Header(initialId, 0,Header.RCODE_NAMEERR, 1)
            response = newHeader.pack() + initialQE.pack()
        else:
            # Save these because we were using globals (never a good practice - too late now, sue me)
            finalAns = []
            finalAns.extend(answers)

            responseRRA = ""
            for ans in finalAns:
                responseRRA += ans.pack()
                foundParent = 0
                parent = ans._dn

                # Finding the NS most highly-qualified domain parent for returned DomainNames
                # These are definitely found in cache as we already parsed them in the main query
                while foundParent == 0:
                    parent = parent.parent()
                    if nscache.contains(parent):
                        foundParent = 1
                        cached_zone_ns = nscache.get(str(parent))
                        for tuple in cached_zone_ns:
                            cachedNS = RR_NS(parent, tuple[1] - int(time()), tuple[0])
                            auths.append(cachedNS)

            # Save these because we were using globals (never a good practice - too late now, sue me)
            finalAuths = []
            finalAuths.extend(auths)

            # Populating the Authority section
            for auth in auths:
                responseRRA += auth.pack()
                if acache.contains(auth._nsdn):
                    ips = acache.getIpAddresses(auth._nsdn)
                    for ip in ips:
                        ttl = acache.getExpiration(auth._nsdn, ip) - int(time())
                        if ttl < 0:
                            # Too late for this record
                            acache.cache.pop(auth._nsdn)

                            # Cache did not help, we have to query it the cool way
                            answers = []
                            newNsHeader = Header(randint(1, 65000), Header.OPCODE_QUERY, Header.RCODE_NOERR, qdcount=1)
                            newNsQE = QE(dn=auth._nsdn)
                            newNsQuery = newNsHeader.pack() + newNsQE.pack()
                            reply = recurser(newNsQuery, ROOTNS_IN_ADDR)

                            # "answers" will now hold the glue records we were looking for
                            additionals.extend(answers)
                        else:
                            additionals.append(RR_A(auth._nsdn, ttl, inet_aton(ip)))
                else:
                    # Nothing in cache about the current NS, we have to query it the cool way
                    answers = []
                    newNsHeader = Header(randint(1, 65000), Header.OPCODE_QUERY, Header.RCODE_NOERR, qdcount=1)
                    newNsQE = QE(dn=auth._nsdn)
                    newNsQuery = newNsHeader.pack() + newNsQE.pack()
                    reply = recurser(newNsQuery, ROOTNS_IN_ADDR)

                    # "answers" will now hold the glue records we were looking for
                    additionals.extend(answers)

            for adds in additionals:
                responseRRA += adds.pack()

            # Building final response using acquired information
            receivedHeader = Header.fromData(nsreply)
            queryHeader = Header(initialId, 0, 0, 1, ancount=len(finalAns), nscount=len(finalAuths),
                                 arcount=len(additionals), qr=True, aa=True, rd=False, ra=True)
            response = queryHeader.pack() + initialQE.pack() + responseRRA

        address = (str(client_address[0]), 33333)

        logger.log(DEBUG2, "our reply in full:")
        logger.log(DEBUG2, hexdump(response))

        ss.sendto(response, client_address)
