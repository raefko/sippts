from lib.functions import calculateHash

username = "550214025190"
realm = "siptrunk2.ver.sul.t-online.de"
nonce = "de28c8183fbece7fde28c8189a27c818d673ae9df7fa9b506b221e55a6a0d789"
uri = "sip:siptrunk2.ver.sul.t-online.de"
response = "c4fe032c07d30402d06fdcfb3f8d84bd"
algorithm = "MD5"
method = "REGISTER"
password = "Tel2TasJd202409181"

msg = calculateHash(
    username, realm, password, method, uri, nonce, algorithm, "", "", "", 0, ""
)

if msg == response:
    print("The response is correct")
