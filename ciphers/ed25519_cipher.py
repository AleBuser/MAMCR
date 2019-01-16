import ed25519


class Ed25519Cipher:

    @staticmethod
    def generate_keys():
        prikey, pubkey = ed25519.create_keypair()
        return prikey, pubkey

    @staticmethod
    def key_from_string(key_string, encoding = 'base64'):
        return ed25519.VerifyingKey(key_string, encoding=encoding)

    @staticmethod
    def sign_message(msg, prikey, encoding = 'base64'):
        sig = prikey.sign(msg, encoding = encoding)
        return sig

    @staticmethod
    def verify_signature(msg, sig, pubkey, encoding = 'base64'):
        try:
            pubkey.verify(sig, msg, encoding = encoding)
            is_valid = True
        except ed25519.BadSignatureError:
            is_valid = False
        return is_valid



