SMail Archiver
==============

SMail Archiver 0.4 is a python script to backup an email account with encryption
and compression capabilities.

It can either be used in interactive mode from the command line or fully
programmed using a configuration file (eg: to be used in a cron job). Each email
is saved individually to allow incremental save.

## Version history
0.5 2013-05-20
  * Better wizard mode
  * Allow backup of multiple IMAP folder

0.4 2013-01-26
  * Allow clear text storage
  * More consistant file names
  * Adding a migration script
  * [Presentation (fr)](http://mart-e.be/post/2013/01/26/smailarchiver-v0-4/)

0.3 2012-12-19
 * Initial release
 * [Presentation (fr)](http://mart-e.be/post/2012/12/19/smailarchiver-script-de-backup-securise-demail/)

# Requirements
* python 2.7 or above (compatible python 3)
* [pycrypto](https://pypi.python.org/pypi/pycrypto) (2.4 or above)

## Backup
The emails are fetched using IMAP. UID of emails are used to identify emails.
Each mail is saved in mbox format using the filename format `{user}/{uid}.{ext}`.

The extension of the filename repesents the options enabled, starting with
`.mbox`.

If the option `compress` is used, the email will be compressed using GZip
and the `.gz` extension is added.

If the option `encrypt` is used, the email will be encrypted using AES
and the `.enc` extension is added.

A compressed and encrypted email will then have the extension `.mbox.gz.enc`.
Compression is always realised before encryption for better results.
Running the command several time will not overwrite the files, existing mbox
files are ignored.

## Restore
When restoring a backup, the script read the content of the specified backup
folder and, for each file, applies the adequate operations according the
extension in reverse order.
  * `.enc` extension will apply a decryption of the file
  * `.gz` extension will apply a decompression of the file
  * `.mbox` extension is mandatory to indicate thr file is an email.

The result of all valid restorations is stored in a mbox file using the
format `{foldername}.mbox`, overwritting potential previous restoration.

Files contained in a folder are processsed in an arbitrary order defined by the
IMAP server (not alphabetical).
    
## Security
The script uses AES256 in CBC mode for encryption and HMAC-SHA256 for 
signature. The size of the AES key can be changed with the variable 
AES_KEY_SIZE representing the number of bytes for the key (16, 24 or 32).

Two modes of security are possible : simple or password-protected.
  * In simple mode (the option `promp` is not set), no password from the user
is required, the two (AES and HMAC) keys are generated using a PRNG and are
the secret. The generated file SHOULD be protected in a secure way.
  * In password protected mode (the option `promp` is enabled), a password is
asked and the two keys are generated using this password and random salt
using PBKDF2. The generated file contains the salt and should no longer be
protected. However, the strength of the encryption lies in the strength of 
the password and it could be an additionnal protection to protect the salt
file in case of weak password.

The result of encryption is saved in BASE64 format.

## Usage
```
usage: smailarchiver [-h] [-u USER] [-i IMAP] [-p PASSWD] [-f FOLDER] [-e]
                     [-k KEYS] [-P] [-z] [-c CONFIG] [-r RESTORE] [--verbose]
                     [--version]

optional arguments:
  -h, --help            show this help message and exit
  -u USER, --user USER  email username
  -i IMAP, --imap IMAP  IMAP email server
  -p PASSWD, --passwd PASSWD
                        email password
  -f FOLDER, --folder FOLDER
                        inbox folder name
  -e, --encrypt         enable encryption
  -k KEYS, --keys KEYS  key/salt file (ignored if encryption disabled)
  -P, --promp           promp for password of keys (ignored if encryption
                        disabled)
  -z, --compress        Compress the mail data
  -c CONFIG, --config CONFIG
                        JSON file containing a list of configuration
  -r RESTORE, --restore RESTORE
                        restore the mails contained in a folder. Extension is
                        used to determine the storage type. Restored in a
                        single .mbox file.
  --verbose             verbose mode
  --version             show program's version number and exit
```

The optional `-c CONFIG` uses a JSON file containing the configuration (useful
for cronjob for instance). It can contain the configuration for several 
mail accounts. An example of the format used is present in 
`config.json.example`.

The option `-r RESTORE` requires the name of the folder containing the backup
files. The restored emails will be stored in the `{RESTORE}.mbox` file.

## IMAP folder

The processed folder is specified in the variable `folder`. By default
`"INBOX"` is used which should be available by many email providers.

In the case of Gmail, all emails can be saved easily using the name 
`'"[Gmail]/All Mail"'`. Note that this name can be change depending of the
language of your email account or not available in IMAP. Read the following
page for more information : [Gmail Archiver - Adapting the inbox name](http://www.sebsauvage.net/wiki/doku.php?id=gmail_archiver)

When using a folder name with spaces (like in the Gmail example above), you
may need to double-quote the name (`'"folder name"'` or `"'folder name'"`) in
Python 3.x

To know which IMAP folders are available, open a python promp and use the 
following code :

    >>> import imaplib
    >>> m = imaplib.IMAP4_SSL("imap.bar.com")
    >>> m.login("foo@bar.com","mypasword")
    ('OK', [b'Logged in'])
    >>> m.list()
    ('OK', [b'(\\HasNoChildren) "." "Junk"', b'(\\HasNoChildren) "." "Trash"', b
    '(\\HasNoChildren) "." "Drafts"', b'(\\HasNoChildren) "." "Sent"', b'(\\HasN
    oChildren) "." "INBOX"'])

(or `m.list("foldername")` for the subfolders)

You can specify only one IMAP folder per configuration. However, you can
configure several sites for the same email account in the the config.json
file. Note that the destination folder is specified using the {user} 
variable and emails from the same account will be merged. Emails are
identified with UID which are unique per message. Emails with the same UID
in the destination folder (`{UID}.mbox.{ext}` depending of the options) are
skipped during the save process. At the restauration process, all emails in
the specified folder will be merged in a `{user}.mbox` file.

## Update
When you update SMailArchiver, watch out for incompatibilities.
The file `migration.py` is a script of migration of stored files to new
formats. Look at the content of this file for more explanations how to
migrate your stored emails.
