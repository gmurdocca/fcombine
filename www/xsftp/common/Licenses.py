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
import base64
import hashlib
import M2Crypto
from Crypto.Cipher import AES

from License import License
import xsftp.common.constants
from xml.dom.minidom import parse, parseString

class Licenses(object):

    # obfuscate the below to deter the crackers, assuming python is not being clever and storing the evaluated versoin in the .pyc
    LICENSE_FREE_USERS = len('len()')**2 / 5 # == 5
    LICENSE_FREE_SERVERLINKS = 23442 % 76 - 29 # == 5
    LICENSE_FREE_JOBS = int(round(93492.324234)) % 45 / 9 + 2 # == 5

    FREE_LICENSES = [   License(type="USER", subtype="", description="Free User License", quantity=LICENSE_FREE_USERS, purchase_date=None, purchase_duration=None),
                        License(type="SERVERLINK", subtype="", description="Free Server Link License", quantity=LICENSE_FREE_SERVERLINKS, purchase_date=None, purchase_duration=None),
                        License(type="JOB", subtype="", description="Free Jobs License", quantity=LICENSE_FREE_JOBS, purchase_date=None, purchase_duration=None), ]


    license_file = ""
    license_file_hash = None
    organisation = ""
    username = ""
    email = ""
    devicename = ""
    licenses = []

    def __init__(self, license_file=xsftp.common.constants.LICENSE_FILE):
        self.license_file = license_file
        self.check_licenses(license_file)

    def check_licenses(self, license_file=None):
        '''Ensures licenses cached in self.licenses are up to date'''
        if not license_file:
            license_file = self.license_file
        if os.path.isfile(license_file):
            license_file_data = open(license_file, 'r').read()
            license_file_hash = hashlib.sha256(license_file_data).digest()
            if license_file_hash != self.license_file_hash:
                self.licenses = self.read_licenses_from_file(license_file)
                self.license_file_hash = license_file_hash
            self.subscribed = True
        else:
            # set default licenses for free version
            self.license_file_hash = None
            self.subscribed = False
            self.licenses = self.FREE_LICENSES

    def read_licenses_from_file(self, license_file):
        '''Reads the license file and returns licence objects'''
        licenses = []
        license_data = self.decrypt_product_key_file(license_file)
        dom = parseString(license_data)
        for node in dom.childNodes:
            if node.nodeName == 'keyfile':
                for node in node.childNodes:
                    if node.nodeName == 'customer':
                        self.organisation = node.getElementsByTagName('organisation')[0].childNodes[0].data
                        self.username = node.getElementsByTagName('username')[0].childNodes[0].data
                        self.email = node.getElementsByTagName('email')[0].childNodes[0].data
                        self.devicename = node.getElementsByTagName('devicename')[0].childNodes[0].data
                    if node.nodeName == "license":
                        type = node.getElementsByTagName('type')[0].childNodes[0].data
                        subtype = node.getElementsByTagName('subtype')[0].hasChildNodes() and node.getElementsByTagName('subtype')[0].childNodes[0].data or ""
                        description = node.getElementsByTagName('description')[0].hasChildNodes() and node.getElementsByTagName('description')[0].childNodes[0].data or ""
                        quantity = node.getElementsByTagName('quantity')[0].hasChildNodes() and int(node.getElementsByTagName('quantity')[0].childNodes[0].data) or 0
                        purchase_date = int(node.getElementsByTagName('purchase_date')[0].childNodes[0].data)
                        purchase_duration = int(node.getElementsByTagName('purchase_duration')[0].childNodes[0].data)
                        l = License(type, subtype, description, quantity, purchase_date, purchase_duration)
                        licenses.append(l)
        for l in self.FREE_LICENSES:
            licenses.append(l)
        return licenses

    def get_licenses(self, type=None, subtype=None):
        self.check_licenses(self.license_file)
        licenses = []
        for l in self.licenses:
            if subtype:
                if (type, subtype) == (l.type, l.subtype):
                    licenses.append(l)
            elif type:
                if type == l.type:
                    licenses.append(l)
            else:
                licenses.append(l)
        licenses.sort(cmp=lambda x,y: cmp(x.type, y.type))
        return licenses

    def get_active_license_count(self, type, subtype=None):
        self.check_licenses(self.license_file)
        quantity = 0
        for l in self.get_licenses(type=type, subtype=subtype):
            if l.is_valid():
                quantity += l.quantity
        return quantity
        

    def has_license(self, type, subtype=None):
        self.check_licenses(self.license_file)
        if subtype and (type, subtype) in [(l.type, l.subtype) for l in self.licenses]:
            return True
        elif type in [l.type for l in self.licenses]:
            return True
        else:
            return False

    def is_subscribed(self):
        self.check_licenses(self.license_file)
        return self.subscribed

    def subscribed_types(self):
        '''Returns a list of license TYPES in current license'''
        subscribed_types = []
        for l in self.licenses:
            if l.type not in subscribed_types:
                subscribed_types.append(l.type)
        return subscribed_types


    def decrypt_product_key_file(self, input_file):
        # 1. To generate the RSA key pair for use here:
        #     openssl genrsa -out privkey.pem 2048
        #     openssl rsa -pubout < privkey.pem > pubkey
        # 2. To generate pubkey_aes256 below:
        #     from Crypto.Cipher import AES
        #     import base64
        #     encrypter = AES.new(('obscure' * 5)[:32])
        #     f = open('pubkey','r')
        #     pubkey = f.read()
        #     f.close()
        #     padded_pubkey = pubkey + (32 - (len(pubkey) % 32)) * chr(0)
        #     encrypted_pubkey = encrypter.encrypt(padded_pubkey)
        #     pubkey_aes256 = base64.b64encode(encrypted_pubkey)
        pubkey_aes256 = '''UWTkIfg8+dF5qoyb7JwvrNIAU6wnzI7Fu7/L+BVci3abl4Z/fkoyesKuQEFKtsG1lQpO48vUdKiOB4zGV8p6i3MKce/xvJ8YQmilEOdnzH3OWKHB3Nd7s+25GNN1EtV57mju6fefzkFumroa9Jn+wLJVFMSlmRAlDGWmcvnpV1YYwwb+yE7PyMMGqxXy/Q8D+3pCq/nfAVW8bwTAaeOYBitARff+OWjvQVU92FI7OYQ8veQjneniS91ONwURpW7khFKozTY3MR1fvyEW1C2c+9Qmt/SFhYEPIpLlMEdsDxpNhF3BMo/SIi9m5ABcZTnYhgWbTBss4FWaUWjSfyE3QFzxxv0SAaPAxGdgKq7QBCIRYkqYzthsHQ1Khembc41b5u6fg3tl/foJSgKCyoTx94RwoHFiQ3eKNxcclQOWrcVqGe24+VCP73jOXmZ1WLGg59InvCn/2OxXxEpgDDCVmxg/hRSExGohP+gNSyQl5JV5P3SnAzYboOl+i7rXwT1bywQ6N7wg0UAHQoJww7mYoqUgXzBdynsdfaDVN5ryVJsEBzi15N5/0veZt923SxaKYzxsGfW+d96PNx9E4qZoX5q5LY23I0XyD4Tv/xoa7IxxBQhdld+5+XFhg5zZge+t'''
        pk_aeskey = ("obscure"*5)[:32]
        # extract the cyphertext from the customer's XML key file
        dom = parse(input_file)
        aes_key = dom.getElementsByTagName('key')[0].childNodes[0].toxml()
        data = dom.getElementsByTagName('data')[0].childNodes[0].toxml()
        # un-base64 the input cyphertext
        aes_key = base64.b64decode(aes_key)
        data = base64.b64decode(data)
        # decrypt the AES encrypted public key pubkey_aes256 using pk_aeskey, store as pubkey
        pk_decrypter = AES.new(pk_aeskey)
        pubkey = pk_decrypter.decrypt(base64.b64decode(pubkey_aes256))
        # decrypt the RSA encrypted AES key aes_key using pubkey, store as aes_key
        pubkey = M2Crypto.BIO.MemoryBuffer(pubkey)
        pubkey = M2Crypto.RSA.load_pub_key_bio(pubkey)
        aes_key = pubkey.public_decrypt(aes_key, M2Crypto.RSA.pkcs1_padding)
        # decrypt the AES encrypted product key data using aes_key, store as cleartext_data
        data_decrypter = AES.new(aes_key)
        cleartext_data = data_decrypter.decrypt(data)
        cleartext_data = cleartext_data.rstrip(chr(0))
        return cleartext_data
