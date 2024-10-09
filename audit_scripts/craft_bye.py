import pyshark
import socket


def extract_sip_info(interface, ip, port):
    # Capture live traffic from the specified interface
    cap = pyshark.LiveCapture(
        interface=interface,
        display_filter=f"sip && ip.src=={ip} && tcp.port=={port}",
    )

    invite_info = {}

    # Iterate over the packets to find the INVITE and 200 OK message
    for packet in cap.sniff_continuously():
        if "sip" in packet:
            sip_layer = packet.sip
            print(sip_layer.field_names)
            if sip_layer.has_field("cseq_method"):
                # Capture INVITE information
                if (
                    sip_layer.cseq_method == "INVITE"
                    and sip_layer.get_field_value("status_code") == "200"
                ):
                    invite_info["to"] = sip_layer.get_field_value(
                        "to"
                    )  # Update 'To' with tag
                    # Once we have both INVITE and 200 OK, we can stop
                    break
                elif sip_layer.cseq_method == "INVITE":
                    invite_info["call_id"] = sip_layer.get_field_value(
                        "call_id"
                    )
                    invite_info["via"] = sip_layer.get_field_value("via")
                    invite_info["from"] = sip_layer.get_field_value("from")
                    invite_info["to"] = sip_layer.get_field_value("to")
                    invite_info["cseq"] = sip_layer.get_field_value("cseq")
                # Capture 200 OK after INVITE (to get tag in To header)
    cap.close()
    return invite_info


def craft_bye_message(invite_info):
    if not invite_info:
        print("No INVITE information found.")
        return None

    # Craft the BYE message
    bye_message = (
        f"BYE sip:{invite_info['to']} SIP/2.0\r\n"
        f"Via: {invite_info['via']}\r\n"
        f"From: {invite_info['from']}\r\n"
        f"To: {invite_info['to']}\r\n"
        f"Call-ID: {invite_info['call_id']}\r\n"
        f"CSeq: {invite_info['cseq'].split(' ')[0]} BYE\r\n"
        f"Content-Length: 0\r\n\r\n"
    )
    return bye_message


def send_bye_message(sip_message, sip_server_ip, sip_server_port):
    try:
        # Create a TCP socket
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp_socket:
            # Connect to the SIP server
            tcp_socket.connect((sip_server_ip, sip_server_port))

            # Send the SIP message over TCP
            tcp_socket.sendall(sip_message.encode("utf-8"))

            # Optionally, receive and print the server's response (e.g., 200 OK)
            response = tcp_socket.recv(4096)  # Adjust buffer size as necessary
            print("Received response from server:\n", response.decode("utf-8"))

    except Exception as e:
        print(f"An error occurred: {e}")


# Example usage
interface = "any"  # e.g., 'eth0' or 'en0'
source_ip = "10.213.57.102"
source_port = "5060"
destination_ip = "10.213.57.101"
destination_port = 5060

# Step 1: Extract information from INVITE and 200 OK
invite_info = extract_sip_info(interface, source_ip, source_port)

# Step 2: Craft the BYE message
bye_message = craft_bye_message(invite_info)

# Step 3: Send the BYE message to terminate the call
send_bye_message(bye_message, destination_ip, destination_port)
