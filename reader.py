import random
import string
import json
import time
from iota import Address
from ciphers import Ed25519Cipher
from mam_lite import MAML_Ed25519
import logging


class MAM_Reader(object):

    MAMChannel = None


    def __init__(self, _adr, _psw, _key ):
        
        self.MAMChannel = MAML_Ed25519(root_address=Address(_adr), channel_password=_psw)

        key = Ed25519Cipher.key_from_string(_key)

        self.MAMChannel.add_trusted_pubkey('test_entity', key)

    def Read(self):

        read_res = self.MAMChannel.read()
        if read_res != None:
            if read_res.is_trusted == True:
                data_p = read_res.msg.data_payload
                return data_p
            else:
                logging.warning("Data from Untrusted Source!")
                return None
        else:
            return None


