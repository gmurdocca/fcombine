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

import time

class License(object):

    def __init__(self, type, subtype, description, quantity, purchase_date, purchase_duration):
        self.type = type
        self.subtype = subtype
        self.description = description
        self.quantity = quantity
        self.purchase_date = purchase_date
        self.purchase_duration = purchase_duration
        if purchase_date and purchase_duration:
            self.expiry = purchase_date + purchase_duration
        else:
            self.expiry = None

    @property
    def days_remaining(self):
        return self.get_days_remaining()

    def get_purchase_date(self):
        if self.purchase_date:
            return time.strftime("%a %b %d, %Y", time.localtime(self.purchase_date))
        else:
            return "N/A"

    def get_expiry(self):
        if self.expiry:
            return time.strftime("%a %b %d, %Y", time.localtime(self.expiry))
        else:
            return "Never"

    def get_days_remaining(self):
        if self.expiry:
            return int(round((self.expiry - time.time()) / 60 / 60 / 24))
        else:
            # return None if unlimited license (no expiry)
            return None

    def is_valid(self):
        days_remaining = self.get_days_remaining()
        if days_remaining == None or days_remaining > 0:
            return True
        return False
        



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

