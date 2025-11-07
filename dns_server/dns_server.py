# Simple DNS server that logs queries (does not forward to internet) using dnslib
from dnslib.server import DNSServer, DNSHandler, BaseResolver
from dnslib import DNSRecord, QTYPE, RR, A, TXT
import logging, time

logging.basicConfig(level=logging.INFO, format='%(message)s')

class LoggerResolver(BaseResolver):
    def resolve(self, request, handler):
        qname = request.q.qname
        qtype = QTYPE[request.q.qtype]
        logging.info(f"{time.ctime()} DNS_QUERY {handler.client_address[0]} {qname} {qtype}")
        reply = request.reply()
        # respond with a harmless TXT record echoing the qname (limited length)
        reply.add_answer(RR(qname, QTYPE.TXT, rdata=TXT(str(qname)) , ttl=60))
        return reply

if __name__ == '__main__':
    resolver = LoggerResolver()
    server = DNSServer(resolver, port=5353, address='0.0.0.0')
    server.start_thread()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
