import random
import string
import json
from iota import Address
from ciphers import Ed25519Cipher
from mam_lite import MAML_Ed25519



class MAM_Writer(object):

    MAMChannel = None

    pubkey = None

    prikey = None

    def __init__(self, _adr, _psw ):
        
        self.MAMChannel = MAML_Ed25519(root_address=Address(_adr), channel_password=_psw)

        prikey, pubkey = Ed25519Cipher.generate_keys()

        self.pubkey = pubkey
        self.prikey = prikey

        self.MAMChannel.add_trusted_pubkey('test_entity', pubkey)


    def Write(self, _data):

        try:
            write_res = self.MAMChannel.write(_data, self.pubkey, self.prikey)
        except:
            write_res = None
            print ("--IOTA---DOWN--")

        return write_res

    def getKey(self):
         return self.pubkey.to_ascii(encoding="base64").decode()


    
