from unittest import TestCase
from ciphers import Ed25519Cipher
from mam_lite import Message


class TestMessage(TestCase):
    def test_set_pubkey(self):
        msg_obj = Message()
        prikey, pubkey = Ed25519Cipher.generate_keys()
        msg_obj.set_pubkey(pubkey)
        self.assertTrue(msg_obj.pubkey)

    def test_finalize(self):
        msg_obj = Message()
        prikey, pubkey = Ed25519Cipher.generate_keys()
        msg_obj.finalize(data='data_to_be_sent',
                         extra_data ='TESTADDRES',
                         pubkey=pubkey,
                         prikey=prikey)
        is_valid = Ed25519Cipher.verify_signature((msg_obj.data_payload + 'TESTADDRES').encode(),
                                                  msg_obj.signature,
                                                  pubkey=pubkey)
        self.assertTrue(is_valid)
