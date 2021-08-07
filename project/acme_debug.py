# Testing command
# python3 ACMEclient.py dns01 https://localhost:14000/dir 1.2.3.4 netsec.ethz.ch


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
from cryptography.hazmat.primitives.asymmetric import ec, utils


def _base64(text):
    # text in byte
    """Encodes string as base64 as specified in the ACME RFC."""
    # text64 string
    text64 = base64.urlsafe_b64encode(text).decode("utf8").rstrip("=")
    return text64


def _accountKeyGen():
    # https://stackoverflow.com/questions/59525079/python-create-ecc-keys-from-private-and-public-key-represented-in-raw-bytes
    private_key = ec.generate_private_key(ec.SECP256R1, default_backend())
    public_key = private_key.public_key()
    
    # serializing into PEM
    # rsa_pem = public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
    return public_key, private_key

def zero_pad(data, bs):
	data = data.lstrip(b'\0')
	if len(data) < bs: data = b'\0'*(bs - len(data)) + data
	assert len(data) == bs
	return data

def _signed_request(url, payload, nonce, private_key, signature_algorithm, x_jwk, y_jwk): 
    # Convert payload
    if payload == "":
        payload64 = ""
    else: 
        payload64 = _base64(json.dumps(payload).encode('utf8'))

    protected = {}
    protected['alg'] = 'ES256'
    protected['nonce'] = nonce
    protected['url'] = url
    protected['jwk'] = {'kty':'EC', 'crv':'P-256', 'x':x_jwk, 'y':y_jwk}
    # Convert string to byte then pass to _base64
    protected64 = _base64(json.dumps(protected).encode("utf8"))
    signature = private_key.sign(("{0}.{1}".format(protected64, payload64).encode('utf8')), signature_algorithm)
    rs_len, rn, r_len = signature[1], 4, signature[3]
    sn, s_len = rn + r_len + 2, signature[rn + r_len + 1]
    assert signature[0] == 0x30 and signature[rn-2] == signature[sn-2] == 0x02
    assert rs_len + 2 == len(signature) == r_len + s_len + 6
    r, s = zero_pad(signature[rn:rn+r_len], 32), zero_pad(signature[sn:sn+s_len], 32)
    jose = {"protected": protected64, 
            "payload": payload64, 
            "signature": _base64(r+s)}

    return jose

    '''
        {     "protected": base64url({       
            "alg": "ES256",       
            "jwk": {...},       
            "nonce": "6S8IqOGY7eL2lsGoTZYifg",       
            "url": "https://example.com/acme/new-account"     }),     
            
            "payload": base64url({       
                "termsOfServiceAgreed": true,       
                "contact": [         "mailto:cert-admin@example.org",         
                "mailto:admin@example.org"       ]     }),     
                
            "signature": "RZPOnYoPs1PhjszF...-nh6X1qtOFPB519I"   }
    '''

def _newNonce(session, newNonce_url, myheader):
    # Must be called inside a session
    nonce = session.head(newNonce_url, headers=myheader).headers['Replay-Nonce']
    return nonce

    

def main():   
    dir = 'https://localhost:14000/dir'

    # Send ACME server certificate request over HTTPS
    # Authenticated by root certificate
    client_header = {'User-Agent': 'Boya-ACME'}
    with requests.Session() as s:
        s.verify = 'pebble.minica.pem'
        pebble_response = s.get(dir, headers=client_header).json()
        

        # Set a bunch of url
        newAccount_url = pebble_response['newAccount']
        newNonce_url = pebble_response['newNonce']
        newOrder_url = pebble_response['newOrder']
        revokeCert_url = pebble_response['revokeCert']

        # Get a new nonce in string
        newNonce = _newNonce(s, newNonce_url, client_header)
        
        
        
        # Generate RSA account key 
        public_key, private_key = _accountKeyGen()
        # Define hash algorithm
        signature_algorithm = ec.ECDSA(hashes.SHA256())

        # Derive x y value
        # Value is binary in byte type
        value= public_key.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        x_jwk = _base64(value[1:33])
        y_jwk = _base64(value[33:65])
        # print('xxxxxx')
        # print(_base64(public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)))
 


        
        
        


        
        # Ask for new account
        account_request_payload = {}
        # Add term of service
        account_request_payload["termsOfServiceAgreed"] = True
        # Not sure if user-agent header is needed
        newAccountHeader = {'Content-Type': 'application/jose+json'}
        newAccountHeader.update(client_header)
        jose = _signed_request(newAccount_url, account_request_payload, newNonce, private_key, signature_algorithm, x_jwk, y_jwk)
        # print(jose)
        # print('--------')
        
        newAccount = s.post(newAccount_url, json=jose, headers=newAccountHeader)
        print(newAccount.json())




    

if __name__== "__main__":
    main()
    

    print('ACME client works!')

