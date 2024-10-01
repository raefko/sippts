#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__author__ = "Nabih Benazzouz"
__version__ = "4.2"
__license__ = "GPL"
__copyright__ = "Copyright (C) 2015-2024, SIPPTS"
__email__ = "nabih@fuzzinglabs.com"

import os
import sys
import socket
import signal
import threading
import time
import ssl
import random
import string
import logging
import ipaddress
from tqdm import tqdm
import fcntl

from .lib.color import Color
from .lib.functions import (
    create_message,
    get_free_port,
)
from .lib.logos import Logo


class SipFuzz:
    """
    SipFuzz is a SIP protocol fuzzer that sends arbitrary SIP messages to a target.
    """

    def __init__(self, args):
        """
        Initializes the SipFuzz instance with parameters from command-line arguments.
        """
        self.ip = args.ip
        self.rport = args.rport
        self.proto = args.proto.upper()
        self.method = args.method.upper()
        self.nthreads = args.nthreads
        self.number = args.number
        self.verbose = args.verbose
        self.bad = args.bad
        self.proxy = args.proxy
        self.route = args.route
        self.domain = args.domain
        self.contact_domain = args.contact_domain
        self.from_user = args.from_user
        self.from_name = args.from_name
        self.from_domain = args.from_domain
        self.to_user = args.to_user
        self.to_name = args.to_name
        self.to_domain = args.to_domain
        self.user_agent = args.user_agent
        self.digest = args.digest
        self.alphabet = args.alphabet
        self.min = args.min_length
        self.max = args.max_length

        self.c = Color()

        self.run = True
        self.stop_event = threading.Event()
        self.count = 0
        self.count_lock = threading.Lock()
        self.supported_methods = [
            "REGISTER",
            "SUBSCRIBE",
            "NOTIFY",
            "PUBLISH",
            "MESSAGE",
            "INVITE",
            "OPTIONS",
            "ACK",
            "CANCEL",
            "BYE",
            "PRACK",
            "INFO",
            "REFER",
            "UPDATE",
        ]
        if self.bad:
            self.supported_methods.append("FUZZ")

    def start(self):
        """
        Starts the fuzzing process.
        """
        # Validate inputs
        print("self.bad", self.bad)
        if self.method not in self.supported_methods:
            logging.error(f"Method {self.method} is not supported.")
            sys.exit(1)

        if self.proto not in ["UDP", "TCP", "TLS"]:
            logging.error(f"Protocol {self.proto} is not supported.")
            sys.exit(1)

        # Adjust default port for TLS
        if self.rport == 5060 and self.proto == "TLS":
            self.rport = 5061

        logo = Logo("sipfuzz")
        logo.print()

        signal.signal(signal.SIGINT, self.signal_handler)
        logging.info("Press Ctrl+C to stop")

        logging.info(f"Target: {self.ip}:{self.rport}/{self.proto}")
        if self.proxy:
            logging.info(f"Outbound Proxy: {self.proxy}")
        logging.info(f"Method: {self.method}")
        logging.info(f"Used threads: {self.nthreads}")

        if self.number == 0:
            logging.info("Number of requests: INFINITE")
        else:
            logging.info(f"Number of requests: {self.number}")

        if self.bad:
            logging.info(f"Alphabet: {self.alphabet}")
            logging.info(f"Min length: {self.min}")
            logging.info(f"Max length: {self.max}")

        threads = []
        for i in range(self.nthreads):
            if not self.stop_event.is_set():
                t = threading.Thread(target=self.fuzz)
                threads.append(t)
                t.start()

        # Use tqdm for progress bar
        total_requests = self.number if self.number > 0 else float("inf")
        with tqdm(
            total=total_requests, desc="Sending messages", unit="msg"
        ) as pbar:
            while any(t.is_alive() for t in threads):
                if self.count_lock.acquire(False):
                    pbar.update(self.count - pbar.n)
                    self.count_lock.release()
                time.sleep(0.1)

        for t in threads:
            t.join()

        logging.info(f"Sent {self.count} messages")

    def signal_handler(self, sig, frame):
        """
        Handles the interrupt signal to gracefully shutdown.
        """
        logging.info("Received interrupt signal, shutting down...")
        self.stop_event.set()

    def fuzz(self):
        """
        Performs the fuzzing by sending SIP messages to the target.
        """
        sock = None
        try:
            # Initialize socket
            host = self.get_host()
            while not self.stop_event.is_set() and (
                self.count < self.number or self.number == 0
            ):
                sock = self.initialize_socket()
                msg, method_label = self.generate_message()
                self.send_message(sock, msg, host, method_label)
                if sock:
                    sock.close()
        except Exception as e:
            logging.error(f"An error occurred in FUZZ thread: {e}")
        finally:
            if sock:
                sock.close()

    def initialize_socket(self):
        """
        Initializes and returns a socket based on the protocol.
        """
        try:
            if self.proto == "UDP":
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            elif self.proto == "TCP":
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            elif self.proto == "TLS":
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            else:
                raise ValueError(f"Unsupported protocol: {self.proto}")
            fcntl.fcntl(sock, fcntl.F_SETFL, os.O_NONBLOCK)

            # Bind to a free port
            bind_ip = "0.0.0.0"
            lport = get_free_port()
            sock.bind((bind_ip, lport))
            sock.settimeout(1)
            if self.proto == "TCP":
                sock.connect(self.get_host())
            elif self.proto == "TLS":
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(sock, server_hostname=self.ip)
                sock.connect(self.get_host())
            return sock
        except Exception as e:
            logging.error(f"Failed to initialize socket: {e}")
            raise

    def get_host(self):
        """
        Returns the host tuple (ip, port) to connect to.
        """
        if self.proxy:
            proxy_ip, proxy_port = self.parse_proxy(self.proxy)
            return (proxy_ip, proxy_port)
        else:
            return (self.ip, self.rport)

    @staticmethod
    def parse_proxy(proxy):
        """
        Parses the proxy string and returns (ip, port).
        """
        if ":" in proxy:
            proxy_ip, proxy_port = proxy.split(":")
            return (str(proxy_ip), int(proxy_port))
        else:
            return (proxy, 5060)

    def generate_message(self):
        """
        Generates a SIP message to be sent.
        """
        if self.bad:
            # Generate random values
            method = random.choice(self.supported_methods)
            if method == "FUZZ":
                method = self.random_string()
            message_params = {
                "method": method,
                "ip_sdp": self.random_string(),  # Added missing parameter
                "contactdomain": self.random_string(),
                "fromuser": self.random_string(),
                "fromname": self.random_string(),
                "fromdomain": self.random_string(),
                "touser": self.random_string(),
                "toname": self.random_string(),
                "todomain": self.random_string(),
                "proto": self.random_string(),
                "domain": self.random_string(),
                "useragent": self.random_string(),
                "fromport": random.randint(self.min, self.max),
                "branch": self.random_string(),
                "callid": self.random_string(),
                "tag": self.random_string(),
                "cseq": self.random_string(),
                "totag": self.random_string(),
                "digest": self.random_string(),
                "auth_type": random.randint(1, 2),
                "referto": self.random_string(),
                "withsdp": random.randint(1, 2),
                "via": self.random_string(),
                "rr": self.random_string(),
                "ppi": self.random_string(),  # Added missing parameter
                "pai": self.random_string(),  # Added missing parameter
                "header": self.random_string(),  # Added missing parameter
                "withcontact": random.randint(1, 2),  # Added missing parameter
            }
            msg = create_message(**message_params)
            method_label = method
        else:
            # Use specified values
            message_params = {
                "method": self.method,
                "ip_sdp": "",  # Added missing parameter
                "contactdomain": self.contact_domain or self.ip,
                "fromuser": self.from_user or "100",
                "fromname": self.from_name or "",
                "fromdomain": self.from_domain or self.domain or self.ip,
                "touser": self.to_user or "100",
                "toname": self.to_name or "",
                "todomain": self.to_domain or self.domain or self.ip,
                "proto": self.proto,
                "domain": self.domain or self.ip,
                "useragent": self.user_agent or "SipFuzz",
                "fromport": get_free_port(),
                "branch": "",
                "callid": "",
                "tag": "1",
                "cseq": "",
                "totag": "",
                "digest": self.digest,
                "auth_type": 1,
                "referto": "",
                "withsdp": 0,
                "via": "",
                "rr": self.route or "",
                "ppi": "",  # Added missing parameter
                "pai": "",  # Added missing parameter
                "header": "",  # Added missing parameter
                "withcontact": 0,  # Added missing parameter
            }
            msg = create_message(**message_params)
            method_label = self.method
        return msg, method_label

    def send_message(self, sock, msg, host, method_label):
        """
        Sends a SIP message over the socket to the specified host.
        """
        try:
            if self.verbose:
                logging.info(
                    f"Sending {method_label} to {self.ip}:{self.rport}/{self.proto}"
                )
                logging.debug(msg)
            else:
                logging.debug(
                    f"Sending {method_label} to {self.ip}:{self.rport}/{self.proto}"
                )
            if self.proto in ["TCP", "TLS"]:
                sock.sendall(msg.encode("utf-8"))
            elif self.proto == "UDP":
                sock.sendto(msg.encode("utf-8"), host)
            with self.count_lock:
                self.count += 1
        except Exception as e:
            logging.error(f"Failed to send message: {e}")

    def is_valid_ip(self, address):
        """
        Validates the IP address.
        """
        try:
            ipaddress.ip_address(address)
            return True
        except ValueError:
            return False

    def random_string(self):
        """
        Generates a random string based on the specified alphabet and length.
        """
        length = random.randint(self.min, self.max)
        if self.alphabet == "printable":
            chars = string.printable
        elif self.alphabet == "ascii_letters":
            chars = string.ascii_letters
        else:
            chars = self.alphabet  # Use custom alphabet
        return "".join(random.choices(chars, k=length))
