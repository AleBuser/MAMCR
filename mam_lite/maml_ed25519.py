from Crypto.Hash import SHA256
from iota import Address, TryteString
from ciphers import Ed25519Cipher, AESCipher
from mam_lite import Message, Response
from tangle_connector import TangleConnector

class MAML_Ed25519:

    def __init__(self, root_address: Address, channel_password = ''):
        self.tangle_con = TangleConnector()
        self.root_address = root_address.__str__()
        self.channel_pwd = channel_password
        self.current_write_addr = root_address.__str__()
        self.current_read_addr = root_address.__str__()
        self.trusted_pubkeys = {}

    @staticmethod
    def tryte_hash(msg: str):
        digest = SHA256.new()
        digest.update(msg.encode())
        hash = digest.hexdigest()
        tryte_hash = TryteString.from_unicode(hash)[0:81]
        return tryte_hash.__str__()

    def _find_empty_addr(self):
        check_addr = self.current_read_addr
        while True:
            previous_addr = check_addr
            check_addr = self.tryte_hash(check_addr + self.channel_pwd)
            response = self._get_MAM_from_address(Address(check_addr))
            if not response:
                self.current_write_addr = previous_addr
                break

    def _get_MAM_from_address(self, address: Address):
        # TODO need refactoring and to be able to handle bundles and validate JSONs for MAML protocol
        hashes_and_trytes = self.tangle_con.get_all_trytes_from_address(address)
        if hashes_and_trytes:
            trytes = hashes_and_trytes[list(hashes_and_trytes.keys())[0]]
            tx_json = self.tangle_con.get_json_from_tryte(trytes)
        else:
            return None

        try:
            if not self.trusted_pubkeys:
                is_trusted = True
            elif tx_json['pubkey'] in self.trusted_pubkeys:
                is_trusted = Ed25519Cipher.verify_signature((tx_json['data_payload'] + address.__str__()).encode(),
                                                            tx_json['signature'].encode(),
                                                            Ed25519Cipher.key_from_string(tx_json['pubkey']))
            else:
                is_trusted = False
            
            if self.channel_pwd:
                tx_json['data_payload'] = AESCipher(self.channel_pwd).decrypt(tx_json['data_payload'])
            
            msg = Message(tx_json['data_payload'], tx_json['pubkey'], tx_json['signature'])
            response = Response(address.__str__(),
                                self.tryte_hash(address.__str__() + self.channel_pwd),
                                msg, True, is_trusted)
        except:
            # empty response
            response = Response(address.__str__(),
                                      self.tryte_hash(address.__str__()+ self.channel_pwd),
                                      Message(), False, False)
        return response

    def write(self, data: str, pubkey, prikey):
        self._find_empty_addr()
        self.current_write_addr = self.tryte_hash(self.current_write_addr + self.channel_pwd)

        if self.channel_pwd:
            data = AESCipher(self.channel_pwd).encrypt(data).decode()

        msg = Message().finalize(data, self.current_write_addr, pubkey, prikey)

        response_tangle = self.tangle_con.send_msg_to_addr(Address(self.current_write_addr),
                                         msg.__str__(),
                                         tag='PYTHONMAML')
        if response_tangle:
            response = Response(self.current_write_addr,
                                self.tryte_hash(self.current_write_addr + self.channel_pwd),
                                msg, True, True)
        else:
            response = None
        return response

    def read(self):
        previous_addr = self.current_read_addr
        self.current_read_addr = self.tryte_hash(self.current_read_addr + self.channel_pwd)
        response = self._get_MAM_from_address(Address(self.current_read_addr))
        if response:
            return response
        else:
            self.current_read_addr = previous_addr
            return None

    def split_channel(self, new_channel_pwd):
        self._find_empty_addr()
        self.channel_pwd = new_channel_pwd
        self.current_read_addr = self.current_write_addr

    def add_trusted_pubkey(self, name: str, pubkey):
        pubkey_str = pubkey.to_ascii(encoding = 'base64').decode()
        if pubkey_str:
            self.trusted_pubkeys[pubkey_str] = name

    def del_trusted_pubkey(self, pubkey_str: str):
        if pubkey_str:
            self.trusted_pubkeys.pop(pubkey_str)

