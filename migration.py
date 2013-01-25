#!/usr/bin/env python2
# -*- coding: utf-8 -*-
"""SMailArchiver Migration tool

Between versions of SMailArchiver, the file format used may change for diverse
reasons. To ensure you will still be able to encrypt/recieved your emails after
upgrading the script, this tool was developped.

requirements: 
  python 2.7 or above

usage:
  Indicate the version you come from and the folder you want to migrate
  $ python migrate.py -v 0.3 -f foo@bar.com/

If you skipped several versions, run several times the script for each version
eg: if a format change was integrated between version 0.3 and 0.4 and between 
0.5 and 06, you will need to run twice the program
  $ python migrate -v 0.3 -f boo@bar.com
  Migrating from 0.3 to 0.5...
  done.
  $ python migrate -v 0.5 -f boo@bar.com
  Migrating from 0.5 to 0.6...
  done.

Break in compatibility history:
  * 0.3 -> 0.4

"""

import argparse
import json
import os

BREAK_HISTORY = [0.3]
LATEST_VERSION = 0.4


def migrate_folder(from_ver, foldername):
    
    if not os.path.isdir(foldername):
        raise OSError("Folder {} does not exists".format(foldername))

    if from_ver >= LATEST_VERSION:
        print("You have already the latest version")

    if from_ver <= 0.3:
        migrate_03(foldername)

def migrate_03(foldername):
    """Migrate from version 0.3

    In 0.3 the mails where always encrypted and used the following format:
    {UID}.mbox -> encrypted file -> {UID}.mbox.enc
    {UID}.gz.mbox -> compressed & encrypted file -> {UID}.mbox.gz.enc
    """

    print("Migrating from 0.3 to 0.4...")

    for filename in os.listdir(foldername):
        abspath = os.path.join(foldername,filename)
        if filename[-5:] == ".json":
            try:
                with open(abspath,'r') as f:
                    config_dic = json.load(f)
                assert 'list' in config_dic, "missing argument 'list'"
            except:
                # unvalid json skipping
                pass
            
            # now migration
            for config in config_dic['list']:
                config['encrypt'] = 1
                config['compress'] = 1

            with open(abspath,'w') as f:
                json.dump(config,f,sort_keys=True,indent=4)
                
            print("config file {} migrated".format(filename))

        elif filename[-5:] == ".mbox":
            if filename[-8:] == ".gz.mbox":
                destfile = "{}.mbox.gz.enc".format( filename[:-8] )
            else:
                destfile = "{}.enc".format( filename )
            
            if os.path.exists(destfile):
                raise OSError("Conflict for {0}! Destination file {1} already exists".format(filename, destfile))
            else:
                print("{0} -> {1}".format(filename,destfile))
                os.rename(abspath, os.path.join(foldername,destfile))

    print("Done.")


if __name__ == "__main__":

    parser = argparse.ArgumentParser(prog='smailmigrate')
    parser.add_argument("-v", "--version", help="the version you are coming FROM")  # eg: 0.3
    parser.add_argument("-f", "--folder", help="folder to migrate")  # eg: "foo@bar.com/"

    args = parser.parse_args()

    from_ver = float(args.version)
    migrate_folder(from_ver, args.folder)
