from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend


class HMAC_Conf:

    # Create the HMAC
    @classmethod
    def integrity_control(cls, message, key):
        h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
        h.update(message)
        return h.finalize()

    # data is the MAC
    # message is the raw text that we used
    @classmethod
    def verify_integrity(cls, data, message, key):
        h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
        h.update(message)
        try:
            h.verify(data)
            return True
        except:
            return False
