import PyKCS11
import pem
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from CitizenCard import CitizenCard
import base64
import datetime


citizen_authentication_priv_key = ""
citizen_authentication_pub_key = ""
citizen_signature_priv_key = ""
citizen_signature_pub_key = ""



lib ='/usr/local/lib/libpteidpkcs11.so'
pkcs11 = PyKCS11.PyKCS11Lib()
pkcs11.load(lib)
slots = pkcs11.getSlotList()
for slot in slots:
    print(pkcs11.getTokenInfo(slot))


all_attr = list(PyKCS11.CKA.keys())
#Filter attributes
all_attr = [e for e in all_attr if isinstance(e, int)]
session = pkcs11.openSession(slot)
for obj in session.findObjects():
    # Get object attributes
    attr = session.getAttributeValue(obj, all_attr)

    # Create dictionary with attributes
    attr = dict(zip(map(PyKCS11.CKA.get, all_attr), attr))
    if attr['CKA_VALUE'] != None:
        vals = attr['CKA_VALUE']
        print('Label:',attr['CKA_LABEL'],attr['CKA_CLASS'],str(vals))



def find_authentication_certificate():
    session = pkcs11.openSession(slot)
    obj = session.findObjects([
       (PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE),
        (PyKCS11.CKA_LABEL, 'CITIZEN AUTHENTICATION CERTIFICATE')
    ])[0]
    all_attributes = [PyKCS11.CKA_VALUE]
    attributes = session.getAttributeValue(obj, all_attributes)[0]
    print(attributes)
    cert = x509.load_der_x509_certificate(bytes(attributes), default_backend())
    return cert

def verify_certificate(cert, issuer_pubkey):
    issuer_pubkey.verify(
        cert.signature,
        cert.tbs_certificate_bytes,
        # Depends on the algorithm used to create the certificate
       # padding.PKCS1v15(),
        cert.signature_hash_algorithm,
     )
    #cert.not_valid_after

def digital_signature(text):
    citizen_authentication_priv_key = session.findObjects([
        (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
        (PyKCS11.CKA_LABEL, 'CITIZEN AUTHENTICATION KEY'),
    ])[0]

    mechanism = PyKCS11.Mechanism(PyKCS11.CKM_SHA1_RSA_PKCS,None)
    signature = bytes(session.sign(citizen_authentication_priv_key, text, mechanism))

cer = find_authentication_certificate()
with open("auth","wb") as f:
    f.write(cer.public_bytes(serialization.Encoding.PEM))




citizen = CitizenCard()
cert = citizen.find_authentication_certificate()
print(citizen.validate_certificate(cert))
