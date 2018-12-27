import PyKCS11
import pem
from cryptography.exceptions import InvalidSignature
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509.oid import NameOID
import base64
import os
import datetime


class CitizenCard:

    def __init__(self):
        lib ='/usr/local/lib/libpteidpkcs11.so'
        self.pkcs11 = PyKCS11.PyKCS11Lib()
        self.pkcs11.load(lib)
        slots = self.pkcs11.getSlotList()
        self.slot = slots[-1]

    def digital_signature(self, text):
        session = self.pkcs11.openSession(self.slot)
        citizen_authentication_priv_key = session.findObjects([
            (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
            (PyKCS11.CKA_LABEL, 'CITIZEN AUTHENTICATION KEY'),
        ])[0]

        mechanism = PyKCS11.Mechanism(PyKCS11.CKM_SHA1_RSA_PKCS,None)
        return bytes(session.sign(citizen_authentication_priv_key, text, mechanism))

    def find_authentication_certificate(self):
        session = self.pkcs11.openSession(self.slot)
        obj = session.findObjects([
            (PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE),
            (PyKCS11.CKA_LABEL, 'CITIZEN AUTHENTICATION CERTIFICATE')
        ])[0]
        all_attributes = [PyKCS11.CKA_VALUE]
        attributes = session.getAttributeValue(obj, all_attributes)[0]
        print(attributes)
        cert = x509.load_der_x509_certificate(bytes(attributes), default_backend())
        return cert

    def validate_certificate(self, cert):
        certificate_path = self.load_trusted_chain(cert)
        # verify certificate_path ocsp
        crl = self.load_crl()
        for certificate in certificate_path:
            if not self.check_crl(certificate,crl):
                return False

        # verify certificate_path
        for i in range(0,len(certificate_path)):
            print(certificate_path[i].subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value)
            # verify purpose

            # verify common name
            # if certificate_path[i].subject.get_attributes_for_oid(NameOID.COMMON_NAME).value == certificate:

            # verify validity
            # if certificate_path[i].not_valid_after < datetime.datetime.now():
            #    return False

            # verifies signature for all intermediates
            if i != len(certificate_path)-1 and \
                    not self.valid_certificate_signature(certificate_path[i], certificate_path[i+1].public_key()):

                return False
            # verifies signature for root (Baltimore which is self-signed)
            if i == len(certificate_path)-1 and \
                    not self.valid_certificate_signature(certificate_path[i], certificate_path[i].public_key()):

                return False
        return True

    def load_trusted_chain(self, cert):
        loaded_certificates = pem.parse_file("/home/user/Downloads/PTEID.pem")
        certificate_path = {}
        for loaded in loaded_certificates:
            certificate = x509.load_pem_x509_certificate(loaded.as_bytes(),default_backend())
            if certificate.not_valid_after > datetime.datetime.now():
                    certificate_path[certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value] = certificate

        # loads ECRaizEstado's issuer
        with open("/home/user/Downloads/Baltimore_CyberTrust_Root.pem","rb") as baltimore:
            certificate = x509.load_pem_x509_certificate(baltimore.read(), default_backend())
            certificate_path[certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value] = certificate

        certificate_path = self.build_trust_chain(cert, certificate_path)
        return certificate_path

    def valid_certificate_signature(self, cert, issuer_pubkey):
        try:
            issuer_pubkey.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm,
            )
            return True
        except InvalidSignature:
            return False

    def build_trust_chain(self,cert, chain, trusted=[]):
        if not self.contains(cert, trusted):
            trusted.append(cert)
            self.build_trust_chain(chain[cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value],chain,trusted)
        return trusted

    def contains(self,cert,l):
        for certificate in l:
            if certificate == cert:
                return True

    def load_crl(self):
        files = [f for f in os.scandir("/home/user/Downloads/crl/")]
        crl = []
        for f in files:
            with open(f, "rb") as file:
                crlist = x509.load_der_x509_crl(file.read(), default_backend())
                crl.append(crlist)
        return crl

    def check_crl(self,certificate, crl):
        for revocation_list in crl:
            if revocation_list.get_revoked_certificate_by_serial_number(certificate.serial_number) != None:
                return False
        return True
