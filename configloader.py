#!/usr/bin/env python3

import os
import base64
import configparser
from getpass import getpass
from Crypto.Cipher import AES


BLOCK_SIZE = 16
DEFAULT_INI = 'config.ini'
DEFUALT_KEY = 'config.key'
DEFAULT_IV = 'config.iv'
DEFAULT_PATHS = ('.')


def _pad(string):
    """ Pad a string so that it may be encrypted
    Credi: https://gist.github.com/forkd/168c9d74b988391e702aac5f4aa69e41
    """
    return (string + (BLOCK_SIZE - len(string) % BLOCK_SIZE) *
            chr(BLOCK_SIZE - len(string) % BLOCK_SIZE))


def _unpad(string):
    """ Unpad a string after decyption
    Credit: https://gist.github.com/forkd/168c9d74b988391e702aac5f4aa69e41
    """
    return string[:-ord(string[len(string) - 1:])]


class Config():
    def __init__(self, config_file=DEFAULT_INI, key_file=DEFUALT_KEY,
                 iv_file=DEFAULT_IV, paths=DEFAULT_PATHS, encrypted_keys=None):

        self.config_file = None
        self.key_file = None
        self.iv_file = None
        self._key = None
        self._iv = None

        if type(paths) == 'str':
            paths = (paths)

        if type(encrypted_keys) == 'str':
            encrypted_keys = (encrypted_keys)

        # See if we can find a config file
        for path in paths:
            if not path.endswith('/'):
                path = path + '/'

            if os.path.isfile(path + config_file):
                self.config_file = path + config_file
                break

        if not self.config_file:
            raise OSError("Could not locate config '{}'' using paths: {}"
                          .format(config_file, paths))

        # See if we can find key/iv files
        for path in paths:
            if not path.endswith('/'):
                path = path + '/'

            if os.path.isfile(path + key_file):
                self.key_file = path + key_file
                break

        for path in paths:
            if not path.endswith('/'):
                path = path + '/'

            if os.path.isfile(path + iv_file):
                self.iv_file = path + iv_file
                break

        # Error out if we're expecting to decrypt stuff, but don't have key/iv
        if encrypted_keys and not self.key_file:
            raise OSError("Could not locate key '{}' using paths: {}"
                          .format(key_file, paths))
        elif encrypted_keys and not self.iv_file:
            raise OSError("Could not locate iv '{}' using paths: {}"
                          .format(iv_file, paths))

        # Else if we have keys to decrypt read in the key/iv and decode
        elif encrypted_keys:
            with open(self.key_file) as fh:
                self._key = fh.read()
                self._key = base64.b64decode(self._key)

            with open(self.iv_file) as fh:
                self._iv = fh.read()
                self._iv = base64.b64decode(self._iv)

            self.encrypted_keys = encrypted_keys

        # Finally read in the config itself
        self.config = configparser.ConfigParser()
        self.config.read(self.config_file)
        self.sections = self.config.sections()

    def get(self, section, key=None):
        """ Fetch a section (and optionally a key) with values
        """
        if section not in self.sections:
            raise ValueError("Section '{}' does not exist in config!")

        data = dict()
        for _key in self.config[section]:
            data[_key] = self.config[section][_key]

            if _key in self.encrypted_keys:
                data[_key] = self.decrypt(data[_key])

        if key:
            return data[key]

        return data

    def _encrypt(self, string):
        """ Encrypt a string
        Credit: https://gist.github.com/forkd/168c9d74b988391e702aac5f4aa69e41
        """
        string = _pad(string)
        cipher = AES.new(self._key, AES.MODE_CBC, self._iv)
        return base64.b64encode(cipher.encrypt(string)).decode()

    def _decrypt(self, string):
        """ Decrypt a string
        Creidt: https://gist.github.com/forkd/168c9d74b988391e702aac5f4aa69e41
        """
        string = base64.b64decode(string)
        cipher = AES.new(self._key, AES.MODE_CBC, self._iv)
        return _unpad(cipher.decrypt(string)).decode()


def main():
    """ Provides some utility CLI function for generating key/iv files and
    encrypting strings
    """
    import argparse
    parser = argparse.ArgumentParser(description="Generate key/iv files, "
                                     "or encrypt strings")
    parser.add_argument('-K', '--genkey', help='Generate a new key file')
    parser.add_argument('-I', '--geniv', help='Generate a new iv file')
    parser.add_argument('-e', '--encrypt', help='Encrypt a string',
                        action='store_true')
    parser.add_argument('-k', '--key', help='Specify a key file')
    parser.add_argument('-i', '--iv', help='Specify an iv file')

    args = parser.parse_args()

    # Creating keys and/or iv files ...
    if args.genkey:
        key = base64.b64encode(os.urandom(32)).decode()
        fh = open(args.genkey, 'w')
        fh.write(key)
        fh.close()

    if args.geniv:
        iv = base64.b64encode(os.urandom(16)).decode()
        fh = open(args.geniv, 'w')
        fh.write(iv)
        fh.close()

    # We can end here if the user doesn't want to encrypt a string
    if not args.encrypt:
        return

    # Set some default values
    key_file = DEFUALT_KEY
    iv_file = DEFAULT_IV
    paths = list(DEFAULT_PATHS)

    # Overwrite defaults if args are present
    # (newly created key/iv takes priority over a specified key/iv)
    if args.genkey:
        key_file = args.genkey
    elif args.key:
        key_file = args.key

    if args.geniv:
        iv_file = args.geniv
    elif args.iv:
        iv_file = args.iv

    # obtain path of key and actual key file name
    # add obtained path to paths list
    key_path = os.path.abspath(key_file).split(os.sep)[:-1]
    key_path = os.sep.join(key_path)
    key_file = os.path.abspath(key_file).split(os.sep)[-1:][0]
    paths.append(key_path)

    # obtain path of key and actual key file name
    iv_path = os.path.abspath(iv_file).split(os.sep)[:-1]
    iv_path = os.sep.join(iv_path)
    iv_file = os.path.abspath(iv_file).split(os.sep)[-1:][0]

    # if our key is somewhere other than where key is, add path for iv
    if iv_path != key_path:
        paths.append(iv_path)

    conf = Config(key_file=key_file, iv_file=iv_file,
                  paths=paths, encrypted_keys=1)

    string = getpass("Enter a string to encrypt: ")
    string2 = getpass("Re-enter the string: ")

    if string != string2:
        print("Strings are not the same. Exiting.")
        return

    print("Using key '{}' and iv '{}' in paths: {}"
          .format(key_file, iv_file, paths))
    print("Encrypted string:\n{}".format(conf._encrypt(string)))

    return


if __name__ == '__main__':
    main()
