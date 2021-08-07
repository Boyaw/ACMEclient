### Current Stage
- both dns and http multiple passed

- revokation is needed


### TODOs
##### Try to revise the directory to get scored
- use parsing to get dns server and http server domain. Keep reading and writing on text file is not efficient, also leads to error becuase of reading and writing conflict
##### Multiple domain and revoke
- change all the nonce to the same name newNonce, keep updating it
##### DNS Challenge
- move the directory to pass the test for testbed
- to test dns response, I need to check where pebble sends the dns queries and change that setting to have my own dns server---done
- i need to tell the server which challenge i chose---done
- keyauthorization should be checked, that is the bug I think
- keyauth seems to be correct, is dns cache a problem?
    - research more on DNS cache
    - print intermediate results to see if DNS server behaves correctly

### Done with follow-up


### Package Installed
- ` pip3 install pycryptodomex` 
- `pip3 install cryptography`

### Package Whitelist
- cryptography: for crypto scheme
- dnslib: dns server
- Flask: server build
- requests: http connection
- PyCryptodome: crypto scheme
- Django: format transfer
- dacite: format transfer

