![logo](http://blog.pepelux.org/wp-content/uploads/logo-de-sippts.png)


# What is Sippts? #

Sippts is a set of tools to audit VoIP servers and devices using SIP protocol. Sippts is programmed in Python and it allows us to check the security of a VoIP server using SIP protocol.

# Is it free? #

Yes. You can freely use, modify and distribute. If modified, please put a reference to this site.

# Can be use sippts for illegal purposes? #

The purpose of this tool is to audit your own systems or to perform penetration tests on systems for which you have received express authorisation. I am not responsible for the misuse of this tool.

# Usage #

Show help:

```
sippts -h
usage: sippts [-h] [-up] {scan,exten,rcrack,send,wssend,enumerate,leak,ping,invite,dump,dcrack,flood,sniff,spoof,tshark,rtpbleed,rtcpbleed,rtpbleedflood,rtpbleedinject} ...


⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣀⣀⣀⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣄⣀⣀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣤⠤⠶⠒⠛⠉⠉⠉⠉⠀⠀⢀⣀⣀⣀⣤⣤⣤⣤⣤⣤⣤⣤⣬⣍⣙⣳⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣤⠴⠒⠋⠉⠀⠀⠀⢀⣀⣠⡤⠴⠖⠚⠛⠉⠉⠉⠀⣠⡶⠖⠲⣄⠀⠀⠀⠀⠀⠀⠀⠈⠉⢷⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⡤⠖⠋⠁⠀⠀⠀⣀⣤⠴⠖⣛⣉⣁⠀⠀⠀⠀⠀⠀⠀⣀⣀⣠⡇⢹⡄⠀⠸⡆⠀⠀⠀⠀⠀⠀⠀⠀⠈⢿⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⣀⡤⠞⠋⠀⠀⠀⢀⣠⠴⠚⠋⠁⠀⠀⡿⡏⠀⠈⣧⣤⠴⠖⠚⠛⠉⠉⠳⢄⡀⠀⣧⠀⠀⢷⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣷⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⢠⡞⠧⣄⠀⢀⣠⠴⠚⠉⠀⠀⠀⠀⠀⢀⣴⠇⢹⠀⠀⢸⡆⠀⠀⠀⠀⠀⠀⠀⠀⠉⣲⣿⣀⣠⣼⣦⣤⣀⣀⣀⡀⠀⢀⣀⣠⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⢀⡿⠀⠀⠈⣿⠉⠀⠀⠀⠀⠀⠀⠙⢄⣰⠏⠀⠀⠘⡇⠀⠀⣇⢀⣀⡤⠤⠖⠒⠛⠉⠉⠉⣁⣀⠀⠀⠀⠉⠙⠛⢿⣿⡛⠛⠛⢻⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⣸⣧⣄⠀⠀⡇⠀⠀⠀⠀⠀⠀⠀⠀⢈⣿⡄⠀⠀⠀⣷⠴⠚⠋⠉⠀⠀⢀⣠⣴⡖⠛⠉⠿⢻⣿⣉⡉⠙⠓⢲⠦⢤⣈⠙⢶⣶⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⣰⡟⠿⡍⢷⢀⡇⠀⠀⠀⠀⠀⠀⠀⣠⣾⠏⣧⠀⢀⡞⠁⠀⠀⠀⠀⢠⡴⠋⠛⠻⣧⣤⡶⢿⡹⡟⠛⢯⣉⣿⢾⣧⣄⡈⠙⠲⢝⣷⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⢠⣏⠙⢦⣹⣼⠀⠀⠀⠀⠀⠀⢀⣴⣾⠟⠁⢀⡏⢀⡞⠀⠀⠀⠀⠀⣰⣯⡟⡀⠀⣼⡏⢘⡢⢠⣷⣾⡿⠿⠿⣷⣤⣞⠀⠙⢦⡀⠀⠙⢿⣷⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣿⣍⡓⣄⣿⣧⣤⣤⣤⣶⣶⠿⠟⠋⠀⠀⣠⣎⣠⠎⠘⢄⠀⠀⠀⢀⡏⠛⠙⠋⢸⠋⠧⠤⠗⣾⢻⠁⠀⠀⠀⠀⠈⠻⡳⡀⠀⠙⢦⠀⣠⡹⡟⣦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣷⣤⣙⢾⣿⣭⡉⠉⠉⠁⠀⠀⣀⣠⠴⠚⠉⠉⠀⠀⠀⠈⠳⡀⠀⠘⣧⣤⢀⠀⢸⡶⣏⠙⣦⠹⡜⢦⡀⠀⠀⠀⠀⢀⡇⣿⣶⣶⣾⣿⣥⡇⠹⡌⠻⣄⠀⠀⠀⠀⠀⠀⠀⠀
⣿⠤⢬⣿⣇⠈⢹⡟⠛⠛⠛⠉⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⢆⠀⢻⡹⡎⠃⠀⠳⡄⣽⠛⠦⠉⠲⣍⣓⣒⢒⣒⣉⡴⠋⣟⠙⢲⣿⠘⠃⠀⣷⠀⠙⢧⡀⠀⠀⠀⠀⠀⠀
⣿⠶⠒⠺⣿⡀⢸⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢣⡀⠳⡄⢀⡀⠀⠙⠮⣗⠚⢠⡖⠲⣌⣉⡭⣍⡡⣞⠓⣾⠉⣽⠃⢠⡄⣼⣿⠀⠀⠈⠳⡄⠀⠀⠀⠀⠀
⠸⡟⠉⣉⣻⣧⣼⠿⣦⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⣄⠙⢮⡿⢿⡃⠀⠈⠑⠶⢽⣒⣃⣘⣲⣤⣗⣈⣹⠵⠛⠁⠀⠀⡴⣻⠃⠀⠀⠀⠀⠹⣆⠀⠀⠀⠀
⠀⠹⣯⣁⣠⠼⠿⣿⡲⠿⠷⣤⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢦⠀⠙⠳⣄⡀⠀⣄⣶⣄⠀⠉⠉⠉⣉⡉⠉⠀⠀⠘⣶⣴⣦⠞⠁⠀⠀⠀⠀⠀⠀⠘⣧⠀⠀⠀
⠀⠀⠘⣧⡤⠖⢋⣩⠿⣶⣤⣈⣙⣷⣤⣀⣠⣤⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢳⡀⠀⠀⠉⠓⠶⢽⣼⣆⡀⠀⠀⢿⣿⣶⣀⣀⡬⠷⠚⠁⣀⣀⣀⠀⢰⣿⠿⡇⠀⠘⣧⠀⠀
⠀⠀⠀⠀⠙⠾⣏⣤⠞⢁⡞⠉⣿⠋⣹⠉⢹⠀⣿⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠹⡄⠀⠀⠀⠀⠀⠀⠉⠉⠉⠉⠉⠉⠉⠉⠀⣤⣤⣄⠀⣿⠙⢻⠆⠀⠓⢒⣁⡤⠴⠺⡆⠀
⠀⠀⠀⠀⠀⠀⠀⠙⠒⠻⠤⣴⣇⣀⣿⣀⣾⡤⠿⢷⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣆⠀⠀⠀⠀⠀⣀⣀⡀⠀⢸⠿⢷⡄⠀⣿⣀⡿⠀⢈⣉⡭⠴⠒⠋⠉⠀⠀⠀⠀⢻⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠻⣦⣀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢆⠀⠀⠀⠰⣟⠛⡇⠀⠘⠧⠞⢁⣀⡤⠴⠒⠋⠉⠀⠀⠀⠀⠀⠀⠀⠀⣀⣠⣼⠃
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠳⣦⣀⠀⠀⠀⠀⠀⠀⠈⢧⠀⠀⠀⠉⢋⣁⡤⠴⠚⠋⠉⠀⠀⠀⠀⠀⠀⠀⢀⣀⣠⣴⠶⠚⠛⠉⢉⣽⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠙⠷⣤⡀⠀⠀⠀⠀⠘⡆⠴⠒⠋⠉⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣤⠴⠖⠛⠉⠉⠉⠉⠙⠛⠋⠉⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢛⠷⠦⠀⠀⠀⣿⠀⠀⠀⠀⠀⠀⠀⠀⢠⠴⡖⠛⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
                                                               SIPPTS version 4.0 (last version 3.4)
                                                                  CVE version 0.1 (updated)
                                                https://github.com/Pepelux/sippts
                                        by Pepelux - https://twitter.com/pepeluxx

 -= SIPPTS is a set of tools for auditing VoIP systems based on the SIP protocol =-

Commands:
  {scan,exten,rcrack,send,wssend,enumerate,leak,ping,invite,dump,dcrack,flood,sniff,spoof,tshark,rtpbleed,rtcpbleed,rtpbleedflood,rtpbleedinject}
    scan                                          Fast SIP scanner
    exten                                         Search SIP extensions of a PBX
    rcrack                                        Remote password cracker
    send                                          Send a customized message
    wssend                                        Send a customized message over WS
    enumerate                                     Enumerate methods of a SIP server
    leak                                          Exploit SIP Digest Leak vulnerability
    ping                                          SIP ping
    invite                                        SIP INVITE attack
    dump                                          Dump SIP digest authentications from a PCAP file
    dcrack                                        SIP digest authentication cracking
    flood                                         Flood a SIP server
    sniff                                         SIP network sniffing
    spoof                                         ARP Spoofing tool
    tshark                                        Filter data from a PCAP file with TShark
    rtpbleed                                      Detect RTPBleed vulnerability (send RTP streams)
    rtcpbleed                                     Detect RTPBleed vulnerability (send RTCP streams)
    rtpbleedflood                                 Exploit RTPBleed vulnerability (flood RTP)
    rtpbleedinject                                Exploit RTPBleed vulnerability (inject WAV file)

Options:
  -h, --help                                      show this help message and exit
  -up                                             Update scripts

Command help:
  sippts <command> -h

Commands usage help:
  sippts -up
  sippts scan -h
  sippts rtpbleed -h
```
Show help for command sipscan:

```
sippts scan -h
usage: sippts scan [-i IP|HOST] [-f FILE] [-r REMOTE_PORT] [-p PROTOCOL] [-proxy IP:PORT] [-m METHOD] [-d DOMAIN] [-cd CONTACT_DOMAIN] [-fn FROM_NAME] [-fu FROM_USER] [-fd FROM_DOMAIN] [-tn TO_NAME] [-tu TO_USER] [-td TO_DOMAIN]
                   [-ua USER_AGENT] [-ppi PPI] [-pai PAI] [-v] [-vv] [-nocolor] [-o FILE] [-cve] [-th THREADS] [-ping] [-fp] [-random] [-local-ip IP] [-h]


┏┓┳┏┓  ┏┓┏┓┏┓┳┓
┗┓┃┃┃  ┗┓┃ ┣┫┃┃
┗┛┻┣┛  ┗┛┗┛┛┗┛┗

  Module scan is a fast SIP scanner using multithread that can check several IPs and port ranges. It works with UDP, TCP and TLS protocols.

Target:
  -i IP|HOST          Host/IP address/network (ex: mysipserver.com | 192.168.0.10 | 192.168.0.0/24)
  -f FILE             File with several IPs or network ranges
  -r REMOTE_PORT      Ports to scan. Ex: 5060 | 5070,5080 | 5060-5080 | 5060,5062,5070-5080 | ALL for 1-65536 (default: 5060)
  -p PROTOCOL         Protocol: udp|tcp|tls|all (default: udp)
  -proxy IP:PORT      Use an outbound proxy (ex: 192.168.1.1 or 192.168.1.1:5070)

Headers:
  -m METHOD           Method used to scan: options, invite, register (default: options)
  -d DOMAIN           SIP Domain or IP address. Ex: my.sipserver.com (default: target IP address)
  -cd CONTACT_DOMAIN  Domain or IP address for Contact header. Ex: 10.0.1.2
  -fn FROM_NAME       From Name. Ex: Bob
  -fu FROM_USER       From User (default: 100)
  -fd FROM_DOMAIN     From Domain. Ex: 10.0.0.1
  -tn TO_NAME         To Name. Ex: Alice
  -tu TO_USER         To User (default: 100)
  -td TO_DOMAIN       To Domain. Ex: 10.0.0.1
  -ua USER_AGENT      User-Agent header (default: pplsip)
  -ppi PPI            P-Preferred-Identity
  -pai PAI            P-Asserted-Identity

Log:
  -v                  Increase verbosity
  -vv                 Increase more verbosity
  -nocolor            Show result without colors
  -o FILE             Save data into a log file
  -cve                Show possible CVEs

Other options:
  -th THREADS         Number of threads (default: 200)
  -ping               Ping host before scan
  -fp                 Try to fingerprinting
  -random             Randomize target hosts
  -local-ip IP        Set local IP address (by default try to get it)
  -h, --help          Show this help

Usage examples:
  Searching for SIP services and devices with default ports (5060/udp) on the local network
     sippts scan -i 192.168.0.0/24
  Extend the port range from 5060 to 5080 and look for UDP, TCP and TLS services
     sippts scan -i 192.168.0.0/24 -r 5060-5080 -p all
  Load several target IP addresses from a file
     sippts scan -f targets.txt
  Random scanning for non-sequential scanning of IP ranges
     sippts scan -f targets.txt -random
  Establishing an unidentified user agent as an attack tool
     sippts scan -ua Grandstream
  Scan all ports and protocols of an address range using 500 threads (slow)
     sippts scan -f targets.txt -r all -p all -th 500 -ua Grandstream
  Typical scanning for large ranges
     sippts scan -f targets.txt -r 5060-5080 -p all -th 500 -ua Grandstream -v -fp -o output.txt
```
Update scripts:

```
sippts -up
```

# Set of tools for penetration test over SIP protocol #

Sippts is a set of tools for auditing VoIP servers and devices using the SIP protocol. Sippts is programmed in Python and consists of the following commands or modules:
  * _**Sipscan**_ is a fast scanner for SIP services that uses multithread. Sipscan can check several IPs and port ranges and it can work over UDP or TCP.

[Click here to read more about SIPscan](https://github.com/Pepelux/sippts/wiki/SIPscan)

  * _**Sipexten**_ identifies extensions on a SIP server. Also tells you if the extension line requires authentication or not. Sipexten can check several IPs and port ranges.

[Click here to read more about SIPexten](https://github.com/Pepelux/sippts/wiki/SIPexten)

  * _**Siprcrack**_ is a remote password cracker. Siprcrack can test passwords for several users in different IPs and port ranges.

[Click here to read more about SIPRcrack](https://github.com/Pepelux/sippts/wiki/SIPRCrack)

  * _**Sipinvite**_ checks if a server allow us to make calls without authentication. If the SIP server has a bad configuration, it will allow us to make calls to external numbers. Also it can allow us to transfer the call to a second external number.

[Click here to read more about SIPinvite](https://github.com/Pepelux/sippts/wiki/SIPinvite)

  * _**SipDigestLeak**_ Exploits the SIP digest leak vulnerability discovered by Sandro Gauci that affects a large number of hardware and software devices.

[Click here to read more about SIPDigestLeak](https://github.com/Pepelux/sippts/wiki/SIPDigestLeak)

  * _**SipFlood**_ Send unlimited messages to the target.

[Click here to read more about SIPFlood](https://github.com/Pepelux/sippts/wiki/SIPFlood)

  * _**SipSend**_ Allow us to send a customized SIP message and analyze the response.

[Click here to read more about SIPSend](https://github.com/Pepelux/sippts/wiki/SIPSend)

  * _**WsSend**_ Allow us to send a customized SIP message over WebSockets and analyze the response.

[Click here to read more about WsSend](https://github.com/Pepelux/sippts/wiki/WsSend)

  * _**SipEnumerate**_ Enumerate available methods of a SIP service/server.

[Click here to read more about SIPEnumerate](https://github.com/Pepelux/sippts/wiki/SIPEnumerate)

  * _**SipPCAPDump**_ Extracts SIP Digest authentications from a PCAP file.

[Click here to read more about SIPPCAPDump](https://github.com/Pepelux/sippts/wiki/SIPDump)

  * _**SipDigestCrack**_ Cracking tool to crack the digest authentications within the SIP protocol.

[Click here to read more about SIPDigestCrack](https://github.com/Pepelux/sippts/wiki/SIPCrack)

  * _**SipTshark**_ Extract data of SIP protocol from a PCAP file.

[Click here to read more about SIPTshark](https://github.com/Pepelux/sippts/wiki/SIPTshark)

  * _**SipPing**_ SIP ping.

[Click here to read more about SIPPing](https://github.com/Pepelux/sippts/wiki/SIPPing)

  * _**RTPBleed**_ to exploit RTPBleed vulnerability sending data to RTP ports.

[Click here to read more about RTPBleed](https://github.com/Pepelux/sippts/wiki/RTPBleed)

  * _**RTCPBleed**_ to exploit RTPBleed vulnerability sending data to RTCP ports.

[Click here to read more about RTCPBleed](https://github.com/Pepelux/sippts/wiki/RTCPBleed)

  * _**RTPBleedFlood**_ to exploit RTPBleed vulnerability flooding a RTP port with an active dialog.

[Click here to read more about RTPBleedFlood](https://github.com/Pepelux/sippts/wiki/RTPBleedFlood)

* _**RTPBleedInject**_ to exploit RTPBleed vulnerability injecting RTP traffic.

[Click here to read more about RTPBleedInject](https://github.com/Pepelux/sippts/wiki/RTPBleedInject)

## Operating System ##
Sippts has been tested on:
  * Linux
  * MacOS
  * Windows

## Requirements ##
  * Python 3
  
## Instalation ##
  Installing via git:
  * $ git clone https://github.com/Pepelux/sippts.git
  * $ cd sippts
  * $ pip3 install .

## MacOS ##
  Edit requirements.txt and comment next line before install:
  
  \# pyradamsa

