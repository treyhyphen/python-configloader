#!/usr/bin/env python3

import os
import base64
import configparser


class Config():
    def __init__(self, config_file='config.ini', key_file='config.key',
                 iv_file='config.iv', paths='./', encrypted_keys=None):

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

        # Else, read in the key/iv
        elif encrypted_keys:
            with open(self.key_file) as fh:
                self._key = fh.read()
                self._key = base64.b64decode(self._key)

            with open(self.iv_file) as fh:
                self._iv = fh.read()
                self._iv = base64.b64decode(self._iv)

            self.encrypted_keys = encrypted_keys

        self.config = configparser.ConfigParser()
        self.config.read(self.config_file)
        self.sections = self.config.sections()

    def get(self, section, key=None):
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

    def decrypt(self, string):
        pass

    def encrypt(self, string):
        pass


def main():
    import argparse
    parser = argparse.ArgumentParser(description="")
    parser.add_argument('-K', '--genkey', help='Generate a new key file')
    parser.add_argument('-I', '--geniv', help='Generate a new iv file')

    args = parser.parse_args()

    if args.genkey:
        fh = open(args.genkey, 'w')

        key = base64.b64encode(os.urandom(512)).decode()

        fh.write(key)
        fh.close()

    if args.geniv:
        fh = open(args.geniv, 'w')

        iv = base64.b64encode(os.urandom(16)).decode()

        fh.write(iv)
        fh.close()

    pass


if __name__ == '__main__':
    main()
