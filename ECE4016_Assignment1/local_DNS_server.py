# Local DNS Server for ECE4016 Assignment 1
# Python 3.9, uses dnslib (no dnspython)

# flag = 0 : use public DNS (forwarding)
# flag = 1 : use iterative resolution from root servers

import socket
import time
from dnslib import DNSRecord, QTYPE, RR, A, DNSHeader, RCODE

# Config / 配置
LISTEN_ADDR = "127.0.0.1"
LISTEN_PORT = 1234

# flag: 0 => public DNS forwarding, 1 => iterative from root
flag = 1

# public DNS to use when flag == 0 or as helper
PUBLIC_DNS = ("8.8.8.8", 53)

# simple cache: domain -> (ip_str, expiry_time)
cache = {}

# root servers list (some well-known root server IPs)
ROOT_SERVERS = [
    "198.41.0.4",    # a.root-servers.net
    "199.9.14.201",  # b.root-servers.net
    "192.33.4.12",   # c.root-servers.net
    "199.7.91.13",   # d.root-servers.net
    "192.203.230.10",# e.root-servers.net
    "192.5.5.241",   # f.root-servers.net
    "192.112.36.4",  # g.root-servers.net
    "198.97.190.53", # h.root-servers.net
    "192.36.148.17", # i.root-servers.net
    "192.58.128.30", # j.root-servers.net
    "193.0.14.129",  # k.root-servers.net
    "199.7.83.42",   # l.root-servers.net
    "202.12.27.33"   # m.root-servers.net
]

# timeout for UDP queries to upstream servers (seconds)
UPSTREAM_TIMEOUT = 3.0

# TTL used when adding answers ourselves (seconds)
DEFAULT_TTL = 300

# Utilities
def now():
    return int(time.time())

def cache_get(qname):
    """Return cached IP or None"""
    entry = cache.get(qname)
    if not entry:
        return None
    ip, expiry = entry
    if expiry is None or expiry > now():
        return ip
    else:
        # expired
        del cache[qname]
        return None

def cache_set(qname, ip, ttl=DEFAULT_TTL):
    expiry = now() + ttl if ttl else None
    cache[qname] = (ip, expiry)

# DNS network helpers
def send_udp_query(server_ip, server_port, dns_packet_bytes, timeout=UPSTREAM_TIMEOUT):
    """Send UDP DNS query to server_ip:server_port and return response bytes or None"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(dns_packet_bytes, (server_ip, server_port))
        data, _ = sock.recvfrom(4096)
        sock.close()
        return data
    except Exception:
        return None

def make_query_bytes(qname, qtype=QTYPE.A, recursion_desired=False, txid=None):
    """Build DNS query bytes with dnslib"""
    if txid is None:
        q = DNSRecord.question(qname, qtype)
        q.header.rd = 1 if recursion_desired else 0
        return q.pack()
    else:
        # create custom with given txid
        header = DNSHeader(id=txid, qr=0, aa=0, ra=0, rd=1 if recursion_desired else 0)
        rec = DNSRecord(header, q=DNSRecord.question(qname, qtype).q)
        return rec.pack()

# Public DNS forwarding
def query_public_dns(qname):
    """Query PUBLIC_DNS with recursion (simple forwarding). Returns (ip, ttl) or (None, None)"""
    try:
        q = DNSRecord.question(qname, qtype="A")
        # set recursion desired
        q.header.rd = 1
        data = send_udp_query(PUBLIC_DNS[0], PUBLIC_DNS[1], q.pack())
        if not data:
            return None, None
        reply = DNSRecord.parse(data)
        # extract first A record in answer
        for rr in reply.rr:
            if QTYPE[rr.rtype] == "A":
                return str(rr.rdata), rr.ttl
            # handle CNAME: follow target by another query
            if QTYPE[rr.rtype] == "CNAME":
                target = str(rr.rdata)
                # recursive follow
                return query_public_dns(target)
        return None, None
    except Exception:
        return None, None

# Iterative resolver
def extract_ips_from_additional(record_section):
    """From additional section, extract A records mapping (name -> ip)"""
    ips = {}
    for rr in record_section:
        if QTYPE[rr.rtype] == "A":
            ips[str(rr.rname).rstrip('.')] = str(rr.rdata)
    return ips

def extract_ns_names_from_authority(auth_section):
    """From authority section, extract NS names"""
    nsnames = []
    for rr in auth_section:
        if QTYPE[rr.rtype] == "NS":
            nsnames.append(str(rr.rdata).rstrip('.'))
    return nsnames

def iterative_resolve(qname, qtype="A", depth=0, max_depth=20):
    """
    Iterative resolution starting from ROOT_SERVERS.
    Returns (ip_str, ttl) or (None, None)
    Also prints visited server IPs during the search.
    """
    if depth > max_depth:
        return None, None

    # If cached, return quickly
    cached = cache_get(qname)
    if cached:
        print(f"[Cache hit] {qname} -> {cached}")
        return cached, DEFAULT_TTL

    # start with root servers
    current_servers = list(ROOT_SERVERS)
    visited = []

    # iterative loop
    while current_servers:
        next_round_servers = []
        for server in current_servers:
            visited.append(server)
            print(f"[Iterative] Querying server {server} for {qname}")
            q = DNSRecord.question(qname, qtype)
            # iterative -> recursion desired = 0
            q.header.rd = 0
            resp_bytes = send_udp_query(server, 53, q.pack())
            if not resp_bytes:
                continue
            try:
                reply = DNSRecord.parse(resp_bytes)
            except Exception:
                continue

            # 1) If answer exists -> return
            if reply.rr:
                # find A or CNAME
                for rr in reply.rr:
                    if QTYPE[rr.rtype] == "A":
                        ip = str(rr.rdata)
                        ttl = rr.ttl or DEFAULT_TTL
                        print(f"[Answer] Found {qname} -> {ip} from {server}")
                        # cache and return
                        cache_set(qname, ip, ttl)
                        # print path
                        print("[Path] " + " -> ".join(visited))
                        return ip, ttl
                    if QTYPE[rr.rtype] == "CNAME":
                        cname = str(rr.rdata).rstrip('.')
                        print(f"[CNAME] {qname} -> {cname}")
                        # recursively resolve the CNAME target iteratively (increase depth)
                        return iterative_resolve(cname, qtype, depth+1, max_depth)

            # 2) If additional section contains A records for next name servers
            add_ips = extract_ips_from_additional(reply.ar)
            if add_ips:
                # prefer IPs from additional: create list of IPs
                for name, ip in add_ips.items():
                    next_round_servers.append(ip)
                # break to query next round servers
                break

            # 3) If authority section contains NS records, but no A in additional
            ns_names = extract_ns_names_from_authority(reply.auth)
            if ns_names:
                # we need to resolve these NS names to IPs (iteratively)
                for ns in ns_names:
                    print(f"[Referral] NS: {ns} (need to resolve its IP)")
                    # resolve NS name itself by iterative_resolve (this may call root again)
                    ns_ip, _ = iterative_resolve(ns, "A", depth+1, max_depth)
                    if ns_ip:
                        next_round_servers.append(ns_ip)
                # if we got some next servers, break to outer loop
                if next_round_servers:
                    break
            # otherwise, try next server in current_servers
        # end for current_servers

        if not next_round_servers:
            # nothing new found, give up
            print("[Iterative] No further referrals; stopping")
            print("[Path] " + " -> ".join(visited))
            return None, None

        # set current to next round servers and continue
        current_servers = list(dict.fromkeys(next_round_servers))  # unique
        # continue loop

    # if exit loop without answer
    return None, None

# Build DNS response for client
def build_reply_from_request(request_bytes, client_query):
    """
    client_query: DNSRecord parsed from request_bytes
    Returns bytes to send back to client
    """
    qname = str(client_query.q.qname)
    qtype = QTYPE[client_query.q.qtype]

    # check cache
    cached = cache_get(qname)
    if cached:
        ip = cached
        reply = client_query.reply()
        reply.add_answer(RR(qname, QTYPE.A, rdata=A(ip), ttl=DEFAULT_TTL))
        return reply.pack()

    # Not cached: branch by flag
    if flag == 0:
        print(f"[Mode] Public DNS forwarding for {qname}")
        ip, ttl = query_public_dns(qname)
        if ip:
            cache_set(qname, ip, ttl or DEFAULT_TTL)
            reply = client_query.reply()
            reply.add_answer(RR(qname, QTYPE.A, rdata=A(ip), ttl=ttl or DEFAULT_TTL))
            return reply.pack()
        else:
            # build SERVFAIL
            r = DNSRecord(DNSHeader(id=client_query.header.id, qr=1, ra=1, rcode=RCODE.SERVFAIL))
            return r.pack()
    else:
        print(f"[Mode] Iterative resolution for {qname}")
        ip, ttl = iterative_resolve(qname)
        if ip:
            cache_set(qname, ip, ttl or DEFAULT_TTL)
            reply = client_query.reply()
            reply.add_answer(RR(qname, QTYPE.A, rdata=A(ip), ttl=ttl or DEFAULT_TTL))
            return reply.pack()
        else:
            # fallback: try public DNS once
            print("[Fallback] Iterative failed, trying public DNS once")
            ip, ttl = query_public_dns(qname)
            if ip:
                cache_set(qname, ip, ttl or DEFAULT_TTL)
                reply = client_query.reply()
                reply.add_answer(RR(qname, QTYPE.A, rdata=A(ip), ttl=ttl or DEFAULT_TTL))
                return reply.pack()
            # SERVFAIL if still nothing
            r = DNSRecord(DNSHeader(id=client_query.header.id, qr=1, ra=1, rcode=RCODE.SERVFAIL))
            return r.pack()

# Server main loop
def start_server():
    print(f"Starting local DNS server on {LISTEN_ADDR}:{LISTEN_PORT} (flag={flag})")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((LISTEN_ADDR, LISTEN_PORT))

    try:
        while True:
            data, addr = sock.recvfrom(4096)
            # parse incoming request
            try:
                request = DNSRecord.parse(data)
            except Exception as e:
                print("Failed to parse request:", e)
                continue
            qname = str(request.q.qname)
            print(f"\n[Request] From {addr} : {qname} (id={request.header.id})")

            # create reply bytes
            reply_bytes = build_reply_from_request(data, request)

            # send back
            sock.sendto(reply_bytes, addr)
            print(f"[Response] Sent to {addr}")
    except KeyboardInterrupt:
        print("Shutting down.")
    finally:
        sock.close()

# Entry point
if __name__ == "__main__":
    # optionally allow quick flag override by editing variable above
    # Example: set flag = 0 to use public DNS forwarding
    # flag = 0
    start_server()
