from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend
import base64

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
            print(" OMG ITS A MEME ")
            return False

    @classmethod
    def verify_function(cls, target, message_json, sk):
        hm = base64.b64decode(message_json["hmac"])
        cr = message_json[target].encode()
        if not HMAC_Conf.verify_integrity(hm,cr,sk):
            return False
        return True
