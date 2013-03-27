#!/usr/bin/python
############################################################################
#
# Fcombine - An enterprise grade automounter and file server
# Copyright (C) 2013 George Murdocca
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#############################################################################

import os
import time
from M2Crypto import SSL, RSA, X509, EVP, m2, Rand, Err, BIO, ASN1

def create_csr(keypair, fqdn):
    request = X509.Request()
    request.set_version(request.get_version())
    request.set_pubkey(keypair)

    name = X509.X509_Name()
    name.CN = fqdn
    name.OU = "My big unit"
    name.O = "Fcombine bitch"
    name.L = "Here"
    name.ST = "NSW"
    name.C = "AU"

    request.set_subject_name(name)
    ext1 = X509.new_extension("Comment", "Auto Generated")
    extstack = X509.X509_Extension_Stack()
    extstack.push(ext1)
    request.add_extensions(extstack)
    request.sign(keypair, "sha1")

    return request


def make_keypair():
    # this function creates a keypair and stores the public/private parts
    # in _rsa_
    rsa = RSA.gen_key(1024, m2.RSA_F4)

    # make public key
    keypair = EVP.PKey()
    keypair.assign_rsa(rsa)


    return keypair

def create_ca_cert(ca_cert_path, ca_key_path, days_valid=9125):
    """Create CA certificate.
       Default expiry is 25 years from now"""

    keypair = make_keypair()
    csr = create_csr(keypair, "localhost")

    subject = csr.get_subject()
    ca_cert = X509.X509()
    ca_cert.set_serial_number(0)
    ca_cert.set_version(2)
    ca_cert.set_subject(subject)

    # We avoid a Dave McFudge style denial by making sure we don't
    # reject our certificate due to being a few microseconds too
    # early to use it.
    # So give ourselves an extra 24 hours just in case
    start_timestamp = long(time.time() - 86400)
    end_timestamp = start_timestamp + (days_valid * 24 * 60 * 60)
    start_time = ASN1.ASN1_UTCTIME()
    start_time.set_time(start_timestamp)

    end_time = ASN1.ASN1_UTCTIME()
    end_time.set_time(end_timestamp)

    ca_cert.set_not_before(start_time)
    ca_cert.set_not_after(end_time)

    #issuer = X509.X509_Name()
    #issuer.C = "AU"
    #issuer.CN = "ca.localhost"
    #ca_cert.set_issuer(issuer)
    ca_cert.set_issuer(subject)
    ca_cert.set_pubkey(csr.get_pubkey())

    ext = X509.new_extension("basicConstraints", "CA:TRUE")
    ca_cert.add_ext(ext)
    ca_cert.sign(keypair, "sha1")

    # output certificate file in PEM format
    ca_cert.save(ca_cert_path)
    keypair.save_key(ca_key_path, cipher=None)
    os.chmod(ca_key_path, 0400)


#def sign_csr(csr):



create_ca_cert("/etc/pki/tls/certs/fcombine_xmlrpc.crt", \
        "/etc/pki/tls/private/fcombine_xmlrpc.key")
