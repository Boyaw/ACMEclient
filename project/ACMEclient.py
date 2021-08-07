
# Parse command
import sys, argparse
# ACME client requests through https
import requests 
# Run cmd command line
import subprocess
# Encode string as base64 as required in ACME
import base64
# Convert payload
import json
# Generate key: ES256 - ECDSA using P-256 and SHA-256
# import Cryptodome
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
# Generate jwk thumbprint
import hashlib
# DNS server starts here
from dnslib.server import DNSServer, DNSRecord
from dnslib.dns import RR
# For challenge response sleep time
import time 
# For dns server
from dnslib.server import DNSServer
from dnslib.dns import RR





def _base64(text):
    # text in byte
    """Encodes string as base64 as specified in the ACME RFC."""
    # text64 string
    text64 = base64.urlsafe_b64encode(text).decode("utf8").rstrip("=")
    return text64

def zero_pad(data, bs):
	data = data.lstrip(b'\0')
	if len(data) < bs: data = b'\0'*(bs - len(data)) + data
	assert len(data) == bs
	return data

def _keyGen():
    # https://stackoverflow.com/questions/59525079/python-create-ecc-keys-from-private-and-public-key-represented-in-raw-bytes
    private_key = ec.generate_private_key(ec.SECP256R1, default_backend())
    public_key = private_key.public_key()

    return public_key, private_key

def _signed_request(url, payload, nonce, private_key, signature_algorithm, x_jwk, y_jwk): 
    # Convert payload
    if payload == "":
        payload64 = ""
    else: 
        payload64 = _base64(json.dumps(payload).encode('utf8'))

    # Generate protected header
    protected = {}
    protected['alg'] = 'ES256'
    protected['nonce'] = nonce
    protected['url'] = url
    protected['jwk'] = {'kty':'EC', 'crv':'P-256', 'x':x_jwk, 'y':y_jwk}
    
    # Convert string to byte then pass to _base64
    protected64 = _base64(json.dumps(protected).encode("utf8"))
    signature = private_key.sign(("{0}.{1}".format(protected64, payload64).encode('utf8')), signature_algorithm)
    
    # Convert DER signature object to R||S format
    rs_len, rn, r_len = signature[1], 4, signature[3]
    sn, s_len = rn + r_len + 2, signature[rn + r_len + 1]
    assert signature[0] == 0x30 and signature[rn-2] == signature[sn-2] == 0x02
    assert rs_len + 2 == len(signature) == r_len + s_len + 6
    # Signature length depends on private key length, P-256 needs 64 bytes signature
    r, s = zero_pad(signature[rn:rn+r_len], 32), zero_pad(signature[sn:sn+s_len], 32)
    
   
    jose = {"protected": protected64, 
            "payload": payload64, 
            "signature": _base64(r+s)}
    return jose


# This function is for signed order or authentication or replying challenge
# It uses kid instead of x, y value of jwk
def _signed_order(url, payload, nonce, private_key, signature_algorithm, kid): 
    # Convert payload
    if payload == "":
        payload64 = ""
    else: 
        payload64 = _base64(json.dumps(payload).encode('utf8'))

    # Generate protected header
    protected = {}
    protected['alg'] = 'ES256'
    protected['nonce'] = nonce
    protected['url'] = url
    protected['kid'] = kid

    # Convert string to byte then pass to _base64
    protected64 = _base64(json.dumps(protected).encode("utf8"))
    signature = private_key.sign(("{0}.{1}".format(protected64, payload64).encode('utf8')), signature_algorithm)
    
    # Convert DER signature object to R||S format
    rs_len, rn, r_len = signature[1], 4, signature[3]
    sn, s_len = rn + r_len + 2, signature[rn + r_len + 1]
    assert signature[0] == 0x30 and signature[rn-2] == signature[sn-2] == 0x02
    assert rs_len + 2 == len(signature) == r_len + s_len + 6
    # Signature length depends on private key length, P-256 needs 64 bytes signature
    r, s = zero_pad(signature[rn:rn+r_len], 32), zero_pad(signature[sn:sn+s_len], 32)
    
   
    jose = {"protected": protected64, 
            "payload": payload64, 
            "signature": _base64(r+s)}
    return jose



def _newNonce(session, newNonce_url, myheader):
    # Must be called inside a session
    nonce = session.head(newNonce_url, headers=myheader).headers['Replay-Nonce']
    return nonce

    

def main(argv):
    # Parse the command
    parser = argparse.ArgumentParser()
    parser.add_argument('cha')
    parser.add_argument('dir')
    parser.add_argument('dns')
    parser.add_argument('dom')
    parser.add_argument('rev')
    args = parser.parse_args(argv)



    # Tell which record http server should run on
    dnsRecfile = open('dnsrec.txt', 'w')
    dnsRecfile.write(args.dns+'\n')
    dnsRecfile.close()


    # Parse the domains
    domain_list = str(args.dom).split('+')
    domains = []
    for dom in domain_list:
        if dom != '':
            domains.append(dom)


        
    # Send ACME server certificate request over HTTPS
    # Authenticated by root certificate
    client_header = {'User-Agent': 'Boya-ACME'}
    with requests.Session() as s:
        s.verify = 'pebble.minica.pem'
        pebble_response = s.get(args.dir, headers=client_header).json()
        

        # Set a bunch of url
        newAccount_url = pebble_response['newAccount']
        newNonce_url = pebble_response['newNonce']
        newOrder_url = pebble_response['newOrder']
        revokeCert_url = pebble_response['revokeCert']

        # Get a new nonce in string
        newNonce = _newNonce(s, newNonce_url, client_header)
        
        
        
        # Generate account key 
        public_key, private_key = _keyGen()
        # Define hash algorithm
        signature_algorithm = ec.ECDSA(hashes.SHA256())

        # Derive x y value
        # Value is binary in byte type
        value= public_key.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        x_jwk = _base64(value[1:33])
        y_jwk = _base64(value[33:65])
        # Generate key thumbprint
        # Notice the order in dict is defined in RFC
        thumbprint = _base64(hashlib.sha256(json.dumps({'crv':'P-256','kty':'EC','x':x_jwk,'y':y_jwk},separators=(',',':')).encode('utf8')).digest())



      
        # Ask for new account
        account_request_payload = {}
        # Add term of service
        account_request_payload["termsOfServiceAgreed"] = True
        # newAccountHeader will be reused for order and authentication and challenge fetch
        newAccountHeader = {'Content-Type': 'application/jose+json'}
        newAccountHeader.update(client_header)
        jose = _signed_request(newAccount_url, account_request_payload, newNonce, private_key, signature_algorithm, x_jwk, y_jwk)
        newAccount = s.post(newAccount_url, json=jose, headers=newAccountHeader)

        # Check the response value and assign kid, nonce 
        if newAccount.status_code == 201:
            account_url = newAccount.headers['Location']
            newNonce = newAccount.headers['Replay-Nonce']
        elif newAccount.status_code == 200:
            print('This key already exists!')
            account_url = newAccount.headers['Location']
            newNonce = newAccount.headers['Replay-Nonce']
        else:
            raise ValueError("Error registering account: {0} {1}"
                         .format(newAccount.status_code, newAccount.json()))
        
        # Start new order 
        # DNS wildcard is here TODO
        newOrderPayload = {"identifiers": [{"type": "dns", "value": domain} for domain in domains]}
        newOrderJose = _signed_order(newOrder_url, newOrderPayload, newNonce, private_key, signature_algorithm, account_url)
        newOrder = s.post(newOrder_url, json=newOrderJose, headers=newAccountHeader)
        if newOrder.status_code == 201:
            order_location = newOrder.headers['Location']
            order_finalize = newOrder.json()['finalize']
            newNonce = newOrder.headers['Replay-Nonce']
            if newOrder.json()['status'] != 'pending':
                raise ValueError('Order status is not pending!')
        else: 
            raise ValueError('New order failed!')

        # Download authentication resource 
        newAuthPayload = ''
        newAuth_url_list = newOrder.json()['authorizations']

        # Separate dns01 challenge with http01 challenge
        if args.cha == 'dns01':
            # Fulfill all authorization urls
            dns_response_list = []
            challenge_url_list = []
            for newAuth_url in newAuth_url_list:
                newAuthJose = _signed_order(newAuth_url, newAuthPayload, newNonce, private_key, signature_algorithm, account_url)
                newAuth = s.post(newAuth_url, json=newAuthJose, headers=newAccountHeader)

                
                if newAuth.status_code == 200:
                    newNonce = newAuth.headers['Replay-Nonce'] 
                    # TODO Should check if this responce domain name from server is actually what we asked for
                    challenge_domain = newAuth.json()["identifier"]['value']
                else: 
                    raise ValueError('New authorization status is not right! We cannot fetch the challenges!')

                # Choose the first challenge dict
                newChall = [c for c in newAuth.json()["challenges"] if c["type"] == "dns-01"][0]
                # Update challenge url list
                challenge_url_list.append(newChall['url'])
                # Construct dns_response
                keyAuth = newChall['token']+'.'+thumbprint
                keyAuthDigest = _base64(hashlib.sha256(keyAuth.encode('utf8')).digest())
                dns_response = '_acme-challenge.{0}. 300 IN TXT "{1}"'.format(challenge_domain, keyAuthDigest)
                # dns_response_list update
                dns_response_list.append(dns_response)

            # DNS server add all dns responses in dns_response_list
            class DNSResolver:
                def resolve(self,request,handler):
                    reply = request.reply()
                    for dns_res in dns_response_list:
                        reply.add_answer(*RR.fromZone(dns_res))
                    return reply

                    
            resolver = DNSResolver()

            myDNSserver = DNSServer(resolver,port=10053,address=args.dns)
            myDNSserver.start_thread()
            time.sleep(3)

            # Let server challenge dns responses
            for challenge_url in challenge_url_list: 
                challengeValideJose = _signed_order(challenge_url, {}, newNonce, private_key, signature_algorithm, account_url)
                challengeValide= s.post(challenge_url, json=challengeValideJose, headers=newAccountHeader)

                if challengeValide.status_code != 200:
                    raise ValueError("Challenge trigger error!")
                else: 
                    newNonce = challengeValide.headers['Replay-Nonce']
                while True: 
                    challengeStatusJose = _signed_order(challenge_url, '', newNonce, private_key, signature_algorithm, account_url)
                    challengeStatus = s.post(challenge_url, json=challengeStatusJose, headers=newAccountHeader)
                        
                    if challengeStatus.status_code != 200:
                        raise ValueError('Challenge responce is not HTTP 200!')
                    if challengeStatus.json()['status'] == 'pending':
                        time.sleep(3)
                        newNonce = challengeStatus.headers['Replay-Nonce']
                    elif challengeStatus.json()['status'] == 'valid':
                        newNonce = challengeStatus.headers['Replay-Nonce']
                        break
                    elif challengeStatus.json()['status'] == 'invalid':
                        print('nooooooo invalid challenge!')
                        break
                    else:
                        raise ValueError("Challenge response status is not pending nor valid nor invalid...")       




        elif args.cha == 'http01':
            dns_response_list = []
            keyAuth_list = '+'
            challenge_url_list = []
            # Fulfill all authorization urls
            for newAuth_url in newAuth_url_list:
                newAuthJose = _signed_order(newAuth_url, newAuthPayload, newNonce, private_key, signature_algorithm, account_url)
                newAuth = s.post(newAuth_url, json=newAuthJose, headers=newAccountHeader)
                if newAuth.status_code == 200:
                    newNonce = newAuth.headers['Replay-Nonce'] 
                    # TODO Should check if this responce domain name from server is actually what we asked for
                    challenge_domain = newAuth.json()["identifier"]['value']
                else: 
                    raise ValueError('New authorization status is not right! We cannot fetch the challenges!') 

                # Choose the first challenge dict
                newChall = [c for c in newAuth.json()["challenges"] if c["type"] == "http-01"][0]
                # Update challenge url list
                challenge_url_list.append(newChall['url'])
                # Construct http response
                keyAuth = newChall['token']+'.'+thumbprint
                keyAuth_list= keyAuth+'+'+keyAuth_list
                # Construct dns response
                dns_response = '{0}. 300 IN A {1}'.format(challenge_domain, args.dns)
                dns_response_list.append(dns_response)

            # Start http server for all authorization challenges
            http_server_process = subprocess.Popen(["python3", "http_server.py", str(keyAuth_list), str(args.dns)])
            print('http server up!--------')
            # DNS server add all dns responses in dns_response_list
            class DNSResolver:
                def resolve(self,request,handler):
                    reply = request.reply()
                    for dns_res in dns_response_list:
                        reply.add_answer(*RR.fromZone(dns_res))
                    return reply

                    
            resolver = DNSResolver()

            myDNSserver = DNSServer(resolver,port=10053,address=args.dns)
            myDNSserver.start_thread()
            print('DNS server up!-----------')


            
            time.sleep(4)
            # Let server challenge dns responses
            for challenge_url in challenge_url_list: 
                challengeValideJose = _signed_order(challenge_url, {}, newNonce, private_key, signature_algorithm, account_url)
                challengeValide= s.post(challenge_url, json=challengeValideJose, headers=newAccountHeader)

                if challengeValide.status_code != 200:
                    raise ValueError("Challenge trigger error!")
                else: 
                    newNonce = challengeValide.headers['Replay-Nonce']
                while True: 
                    challengeStatusJose = _signed_order(challenge_url, '', newNonce, private_key, signature_algorithm, account_url)
                    challengeStatus = s.post(challenge_url, json=challengeStatusJose, headers=newAccountHeader)
                        
                    if challengeStatus.status_code != 200:
                        raise ValueError('Challenge responce is not HTTP 200!')
                    if challengeStatus.json()['status'] == 'pending':
                        time.sleep(3)
                        newNonce = challengeStatus.headers['Replay-Nonce']
                    elif challengeStatus.json()['status'] == 'valid':
                        newNonce = challengeStatus.headers['Replay-Nonce']
                        break
                    elif challengeStatus.json()['status'] == 'invalid':
                        print('nooooooo invalid challenge!')
                        break
                    else:
                        raise ValueError("Challenge response status is not pending nor valid nor invalid...")       


        else:
            raise ValueError('Challenge type is neither dns nor http!')

 
           
        # Construct CSR and finalize
        time.sleep(3)
        from cryptography import x509
        from cryptography.x509.oid import NameOID

        # Need new key pair for each certification
        cert_public_key, cert_private_key = _keyGen()
            
        # serializing into PEM
        sk_pem = cert_private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption())
        # Write new key to the pem for certificate installation
        cert_sk_file = open('privatekey.pem', 'wb')
        cert_sk_file.write(sk_pem)
        cert_sk_file.close()

        '''
            csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([ 
                x509.NameAttribute(NameOID.COMMON_NAME, challenge_domain), 
                ])).add_extension( 
                    x509.SubjectAlternativeName([ 
                        x509.DNSName(challenge_domain), 
                        ]), 
                critical=False, 
                # Sign the CSR with our private key. 
                ).sign(cert_private_key, hashes.SHA256())
        '''
        # Create csr for (potentially multiple) domain name
        csr_builder = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([ 
                x509.NameAttribute(NameOID.COMMON_NAME, domains[0]), 
                ]))
        dns_name_list = []
        for name in domains:
            dns_name_list.append(x509.DNSName(name))
        
        csr_builder = csr_builder.add_extension( 
                                    x509.SubjectAlternativeName(dns_name_list), 
                                    critical=False,)
        
        csr = csr_builder.sign(cert_private_key, hashes.SHA256())


        CSR_DER = _base64(csr.public_bytes(serialization.Encoding.DER))
        finalizeJose = _signed_order(order_finalize, {'csr':CSR_DER}, newNonce, private_key, signature_algorithm, account_url)
        finalize = s.post(order_finalize, json=finalizeJose, headers=newAccountHeader)
        newNonce = finalize.headers['Replay-Nonce']
            
        while True:
            if finalize.status_code != 200:
                raise ValueError('CSR response is not HTTP 200, check the error field!')
            else:                   
                orderCheckJose = _signed_order(order_location, '', newNonce, private_key, signature_algorithm, account_url)
                order_check = s.post(order_location, json=orderCheckJose, headers=newAccountHeader)
                if order_check.json()['status'] == 'processing':
                    newNonce = order_check.headers['Replay-Nonce']
                    print('Will retry after 5s...')
                    time.sleep(5)
                elif order_check.json()['status'] == 'valid':
                    print('Certificate is reeeeeeady!')
                    certURL = order_check.json()['certificate']
                    newNonce = order_check.headers['Replay-Nonce']
                    break
                else:
                    raise ValueError('Order status is neither processing nor valid, but HTTP is 200...')

        # Download certificate
        certJose = _signed_order(certURL, '', newNonce, private_key, signature_algorithm, account_url)
        cert = s.post(certURL, json=certJose, headers=newAccountHeader)

    if cert.status_code != 200:
        raise ValueError('Certification download failed!')
    else: 
       
        certificate_file = open('certificate.pem', 'w')
        certificate_file.write(cert.text)
        certificate_file.close()

        # Check revoke parameter
        newNonce = cert.headers['Replay-Nonce']
        if args.rev == 'revoke':
            cert_data = x509.load_pem_x509_certificate(cert.content, default_backend())
            cert_der = cert_data.public_bytes(serialization.Encoding.DER)
            print('type of cer_der')
            print(type(cert_der))
            print('cert_der---------')
            print(cert_der)
            revPayload = {'certificate':_base64(cert_der)}
            revJose = _signed_order(revokeCert_url, revPayload, newNonce, private_key, signature_algorithm, account_url)
            revCert = s.post(revokeCert_url, json=revJose, headers=newAccountHeader)
            if revCert.status_code == 200:
                print('Certificate is revoked!')
            else:
                raise ValueError('Certificate cannot be revoked!')
        
        return cert, args.dns






if __name__== "__main__":
    certi, cert_address = main(sys.argv[1:])
    
    print('ACME client works! You have your certification now!')
    print('----------')
    print(certi.text)
    # Kill the http_server
    # subprocess.run("kill `ps -ef |grep http_server.py |awk '{print $2}'`", shell=True)
    # print('http_server is killed!')

    # Start the certification server
    # Start HTTP server                 
    from http.server import BaseHTTPRequestHandler, HTTPServer, SimpleHTTPRequestHandler
    from socketserver import BaseServer
    import ssl
    '''
    class RequestHandler(BaseHTTPRequestHandler):
        def do_GET(self):

            self.protocol_version = "HTTP/1.1"
            self.send_response(200)
            self.send_header('Content-Type', 'application/octet-stream')
            self.end_headers()

            self.wfile.write(bytes(certi, "utf8"))
    '''
    
            

    cert_server_add = (cert_address, 5001)
    cert_server = HTTPServer(cert_server_add, SimpleHTTPRequestHandler)
    cert_server.socket = ssl.wrap_socket(cert_server.socket, certfile='certificate.pem', keyfile='privatekey.pem', server_side=True)
    cert_server.serve_forever()
    
