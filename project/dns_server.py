from dnslib.server import DNSServer
# from dnslib.client import DNSQuestion
from dnslib.dns import RR
import sys, argparse

# Parse the command

parser = argparse.ArgumentParser()
parser.add_argument('cha')

args = parser.parse_args(sys.argv[1:])

dns_response = '_acme-challenge.{0}. 300 IN TXT "{1}"'.format(challenge_domain, keyAuthDigest)

class DNSResolver:
    def resolve(self,request,handler):
        reply = request.reply()
        reply.add_answer(*RR.fromZone(dns_response))
        return reply

                    
resolver = DNSResolver()

myDNSserver = DNSServer(resolver,port=10053,address='localhost')
myDNSserver.start_thread()
