#!/usr/bin/env python2
# -*- coding: utf-8 -*-
"""SMail archiver 0.4

Secured mail archiver
All mails are encypted using AES256 and
signed using HMAC-SHA256

requirements: 
  python 2.7 or above
  Pycrypto
"""

import argparse
import base64
import getpass
import imaplib
import json
import os
import sys
import zlib

# pycrypto
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Hash.HMAC import HMAC
from Crypto.Protocol.KDF import PBKDF2

if sys.version < '3':
    # in python 3 raw_input does not exist anymore
    input = raw_input

VERSION = "0.4"
AES_BLOCK_SIZE = AES.block_size # 16
AES_KEY_SIZE = 32 # AES-256 (16, 24, 32)
SIG_SIZE = SHA256.digest_size # 32

def generate_new_keys(key_file="keys", password=None, enc_key_size=AES_KEY_SIZE, sig_key_size=SIG_SIZE):
    """Generate the encryption and signature key

    If a password is specified, will use it to generate the key using PBKDF2 and random salt
    If no password is specified, the key will be random bytes.
    In the second case, the key file is the only secret, it should be protected"""

    rand_bytes = Random.get_random_bytes(enc_key_size + sig_key_size)
    
    # save the salt/secret
    with open(key_file,'wb') as f:
        f.write(base64.b64encode(rand_bytes))
        
    if password:
        # derive the two keys using PBKDF2 and the salt
        enc_key = PBKDF2(password, rand_bytes[:enc_key_size], dkLen=enc_key_size)
        sig_key = PBKDF2(password, rand_bytes[enc_key_size:], dkLen=sig_key_size)
        hash_string = base64.b64encode(SHA256.new(rand_bytes+password.encode()).digest())
        with open(key_file+".sha",'wb') as f:
            f.write(hash_string)

        print("Enc salt: {0}\nSig salt: {1}\nHash: {2}".format(
            base64.b64encode(enc_key).decode(),
            base64.b64encode(sig_key).decode(),
            hash_string.decode()))

    else:
        # the keys are the random bytes
        enc_key = rand_bytes[:enc_key_size]
        sig_key = rand_bytes[enc_key_size:]
        
        print("Enc key: {0}\nSig key: {1}".format(
            base64.b64encode(enc_key).decode(),
            base64.b64encode(sig_key).decode()))
    
    return (enc_key, sig_key)


def load_keys(key_file, password=None, enc_key_size=AES_KEY_SIZE, sig_key_size=SIG_SIZE):
    """ Load the keys from the specified file
    
    If a password is specified, the key file contains the salt that is used to generate the key using PBKDF2 and the password
    If no password is specified, the key will be the content of the key file"""

    with open(key_file,'r') as f:
        content = f.read()
    rand_bytes = base64.b64decode(content)
    
    assert len(rand_bytes) == enc_key_size + sig_key_size, "invalid key"
    
    if password:
        # verifiy the password
        if not os.path.isfile(key_file+".sha"):
            raise Exception("No hash file found, can not guarantee the password")
        else:
            hash_string = base64.b64encode(SHA256.new(rand_bytes+password.encode()).digest())
            with open(key_file+".sha",'r') as f:
                assert f.read().encode() == hash_string, "Hash validation failed"

        # derive the two keys using PBKDF2
        enc_key = PBKDF2(password, rand_bytes[:enc_key_size], dkLen=enc_key_size)
        sig_key = PBKDF2(password, rand_bytes[enc_key_size:], dkLen=sig_key_size)
    else:
        # the keys are the random bytes
        enc_key = rand_bytes[:enc_key_size]
        sig_key = rand_bytes[enc_key_size:]

    return (enc_key, sig_key)


def encrypt(data, aes_key, hmac_key, enc_key_size=AES_KEY_SIZE, enc_block_size=AES_BLOCK_SIZE, sig_key_size=SIG_SIZE):
    """encrypt data with AES-CBC and sign it with HMAC-SHA256"""
    pad = enc_key_size - len(data) % sig_key_size
    data = data + pad * chr(pad).encode()
    iv_bytes = Random.get_random_bytes(enc_block_size)
    cypher = AES.new(aes_key, AES.MODE_CBC, iv_bytes)
    enc_data = iv_bytes + cypher.encrypt(data)
    sig = HMAC(hmac_key, enc_data, SHA256).digest()
    return enc_data + sig

def decrypt(data, aes_key, hmac_key, enc_key_size=AES_KEY_SIZE, enc_block_size=AES_BLOCK_SIZE, sig_key_size=SIG_SIZE):
    """Verify HMAC-SHA256 signature and decrypt data with AES-CBC"""
    #aes_key, hmac_key = keys
    data = base64.b64decode(data)
    sig = data[-sig_key_size:]
    data = data[:-sig_key_size]
    
    assert HMAC(hmac_key, data, SHA256).digest() == sig, "Invalid data signature"

    iv_bytes = data[:enc_block_size]
    data = data[enc_block_size:]
    cypher = AES.new(aes_key, AES.MODE_CBC, iv_bytes)
    data = cypher.decrypt(data)
    
    # eg: data = b'...\x03\x03\x03'
    if sys.version > '3':
        # data[-1] = 3, int
        return data[:-data[-1]]
    else:
        # data[-1]  = '\x03', str
        return data[:-ord(data[-1])]


def decrypt_folder(foldername, key_file, promp):
    """Decrypt the content of foldername

    Each .mbox file in the folder is decrypted using the specified key
    the result is writen in a {foldername}.mbox file"""

    if promp:
        passwd = getpass.getpass("Enter your encryption/signature password: ")
    else:
        passwd = None

    if not os.path.isfile(key_file):
        raise OSError("Keyfile {} does not exists".format(key_file))
    enc_key, sig_key = load_keys(key_file, passwd)
    
    if not os.path.isdir(args.decrypt):
        raise OSError("Folder {} does not exists".format(args.decrypt))
    
    out_file = open(os.path.abspath(foldername)+'.mbox','wb') # foo@bar.com/ -> foo@bar.com.mbox
    for filename in os.listdir(foldername):
        if filename[-5:] == ".mbox":            
            print("Decrypting {}".format(filename))
            with open(os.path.join(foldername,filename),'r') as enc_file:
                clear_text = decrypt(enc_file.read(), enc_key, sig_key)
                
            if filename[-8:] == ".gz.mbox":
                clear_text = zlib.decompress(clear_text)
                    
            out_file.write(clear_text)
            out_file.write(b"\n\n")
    out_file.close()


def load_configs(filename):
    """Load a JSON config file and check the validity

    The format is shown in config.json.example file"""

    if not os.path.isfile(filename):
        raise OSError("{} does not exists".format(filename))

    with open(filename, 'r') as f:
        config_dic = json.load(f)

    if 'verbose' in config_dic:
        config_dic['verbose'] = bool(config_dic['verbose'])
    
    assert 'list' in config_dic, "missing argument 'list', no backup configuration specified "
    
    for config in config_dic['list']:
        assert 'user' in config, "missing argument 'user', no imap username specified"
        assert 'imap' in config, "missing argument 'imap', no imap server specified"
        assert 'passwd' in config, "missing argument 'passwd', no email password specified"
        assert 'folder' in config, "missing argument 'folder', no inbox folder specified"
        assert 'keys' in config, "missing argument 'keys', no keyfile specified"
        assert 'promp' in config, "missing argument 'promp', does the keyfile needs a password ?"
        config['promp'] = bool(config['promp'])
        assert 'compress' in config, "missing argument 'compress', should the data be compressed ?"
        config['compress'] = bool(config['compress'])

    return config_dic

class EmailBackup():

    def __init__(self, user, imap, passwd, verbose=False):
        self.user = user
        self.imap = imap
        self.passwd = passwd
        self.verbose = verbose

        self.m = imaplib.IMAP4_SSL(imap)
        self.m.login(user,passwd)

    def get_mail_list(self,mailbox='INBOX'):
        """Return the list of UID in the mailbox folder"""
        status, msg = self.m.select(mailbox, True)
        if status != 'OK':
            raise Exception(msg[0])
    
        resp, items = self.m.uid('search', None, "ALL")
        self.items = items[0].split()
        if self.verbose: print("Found {0} emails.".format(len(self.items)))

    def get_crypto_keys(self, key_file, promp=False):
        """Load the encryption and signature key

        If no key exists, generate them
        If prop is True, will use a submited password to protect the key"""
        if promp:
            pwd = getpass.getpass("Enter your encryption/signature password: ")
        else:
            pwd = None

        # get aes keys
        if os.path.isfile(key_file):
            self.enc_key, self.sig_key = load_keys(key_file, pwd)
        else:
            self.enc_key, self.sig_key = generate_new_keys(key_file, pwd)

    def get_items(self, compress=False):
        """Fetch and encrypt each email in self.items"""
        # prepare the path
        foldername = self.user
        if os.path.isfile(foldername):
            raise OSError("a file with the same name as the desired dir, '%s', already exists." % newdir)

        if not os.path.isdir(foldername):            
            os.makedirs(foldername,mode=0o777)

        # get the items
        count = len(self.items)
        for email_uid in self.items:

            # compressed file has .gz.mbox extension
            if compress:
                filename = os.path.join(foldername,"{}.gz.mbox".format(email_uid.decode()))
            else:
                filename = os.path.join(foldername,"{}.mbox".format(email_uid.decode()))

            if os.path.isfile(filename):
                if self.verbose: print("Skipping email {0} ({1} remaining)".format(email_uid.decode(),count))

            else:
                if self.verbose: print("Downloading email {0} ({1} remaining)".format(email_uid.decode(),count))
                result, data = self.m.uid('fetch', email_uid, '(RFC822)')
                email_body = data[0][1]
                # We duplicate the From: line to the beginning of the email because mbox format requires it.
                from_line = "from:unknown@unknown"
                try:
                    from_line = [line for line in email_body[:16384].split(b'\n') if line.lower().startswith(b'from:')][0].strip()
                except IndexError:
                    print("  'from:' unreadable.")
            
                email_body = b"From "+from_line[5:].strip()+b"\n"+email_body
                
                if compress:
                    zip_body = zlib.compress(email_body)
                    enc_email_body = base64.b64encode(encrypt(zip_body, self.enc_key, self.sig_key))
                else:
                    enc_email_body = base64.b64encode(encrypt(email_body, self.enc_key, self.sig_key))
                    
                
                with open(filename,'wb') as f:
                    f.write(enc_email_body)

            count -= 1


if __name__ == "__main__":

    parser = argparse.ArgumentParser(prog='smailarchiver')
    parser.add_argument("-u", "--user", help="email username")  # "foo@bar.com"
    parser.add_argument("-i", "--imap", help="IMAP email server") # "imap.bar.com"
    parser.add_argument("-p", "--passwd", help="email password") # "password"
    parser.add_argument("-f", "--folder", help="inbox folder name", default="INBOX") # '"[Gmail]/All Mail"'
    parser.add_argument("-k", "--keys", help="key/salt file", default="keys")
    parser.add_argument("-P", "--promp", help="promp for password of keys", action="store_true")

    parser.add_argument("-c", "--config", help="JSON file containing a list of configuration")
    parser.add_argument("-r", "--restore", help="restore the mails contained in a folder. "\
                            "Extension is used to determine the storage type. "\
                            "Restored in a single .mbox file.")
    
    parser.add_argument("-z", "--compress", help="Compress the mail data before encrypting", action="store_true")

    parser.add_argument("--verbose", help="verbose mode", action="store_true")
    parser.add_argument('--version', action='version', version='%(prog)s {}'.format(VERSION))

    args = parser.parse_args()

    if args.decrypt:
        decrypt_folder(args.decrypt, args.keys, args.promp)
    else:

        if args.config:
            configs = load_configs(str(args.config))
            for config in configs['list']:
                print("Backup for {0}@{1}".format(config['user'],config['imap']))
                eb = EmailBackup(config['user'],config['imap'],config['passwd'],configs['verbose'])
                if configs['verbose']: print("Get mail list")
                eb.get_mail_list(str(config['folder']))
                if configs['verbose']: print("Get crypto keys")
                eb.get_crypto_keys(config['keys'],config['promp'])
                if configs['verbose']: print("Get items")
                eb.get_items(config['compress'])

        else:

            if args.user:
                user = str(args.user)
            else:
                user = input("Enter your email username: ")
            if args.imap:
                imap = str(args.imap)
            else:
                imap = input("Enter your imap server: ")
            if args.passwd:
                pwd = str(args.passwd)
            else:
                pwd = getpass.getpass("Enter your password: ")

            if args.verbose: print("Backup for {0}@{1}".format(user,imap))
            eb = EmailBackup(user,imap,pwd,args.verbose)
            if args.verbose: print("Get mail list")
            eb.get_mail_list(str(args.folder))
            if args.verbose: print("Get crypto keys")
            eb.get_crypto_keys(args.keys, args.promp)
            if args.verbose: print("Get items")
            eb.get_items(args.compress)
    
