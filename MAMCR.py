import random
import string
import json
import datetime
import hashlib
import time
from Crypto.Hash import SHA256
from iota import Address
from ciphers import Ed25519Cipher
from mam_lite import MAML_Ed25519
from writer import MAM_Writer
from reader import MAM_Reader

class MAMCR():

    Writer = None

    Reader = None

    ToReveal = None

    def __init__(self, _adr, _psw):

        self.Writer = MAM_Writer(_adr, _psw)

        self.Reader = MAM_Reader(_adr, _psw, self.Writer.getKey())


    def Commit(self, _data):

        key = "".join(random.choices(string.ascii_uppercase + '9', k=9))

        dataToCommit = {
            "data" : _data,
            "key": key,
        }

        dataBytes = json.dumps(dataToCommit)

        self.ToReveal = dataBytes

        Commit = hashlib.sha256(dataBytes.encode()).hexdigest()

        result = self.Writer.Write(Commit)

        return result


    def Reveal(self):

        self.Writer.Write(self.ToReveal)

    def CheckAndGetData(self):

        commitData = self.Reader.Read()
        revealData = self.Reader.Read()

        if commitData != None and revealData != None:

            Proven = False

            if commitData ==  hashlib.sha256(revealData.encode()).hexdigest():
                Proven = True

            ToReturn = {
                "msg" : revealData,
                "wasCommited" : Proven,
            }
            
            return ToReturn

        else:
            return None




