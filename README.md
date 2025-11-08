Tibco password revealer
================================

Description
-----------
A simple script to decrypt mangled and obfuscated passwords from Tibco EMS

Features
--------
* Support **mangled `"$man$"`** and **obfuscated `"#!"`** passwords
* Standalone Windows executable available

Options
-------
```
$ python tibcopasswordrevealer.py -h
Usage: tibcopasswordrevealer.py [options] '<obfuscated_password>' (on UNIX, do not forget to simple quote the password to avoid bash interpretation)
Version: 1.0

Options:
  -h, --help            show this help message and exit

  Mangled password:
    -m MANGLED_PASSWORD, --mangled-password=MANGLED_PASSWORD
                        mangled password that you want to unmangle. Ex. -m
                        '$man$Dc6rE3mh8giUDcPkQEhEE5CnUKA='

  Obfuscated password:
    -o OBFUSCATED_PASSWORD, --obfuscated-password=OBFUSCATED_PASSWORD
                        obfuscated password that you want to deobfuscate Ex:
                        -o '#!/Zbs+cF+HftERpGvBh03jFtPMJQuLItP'
```

Examples
--------
#### Mangled password
```
$ python tibcopasswordrevealer.py '$man$Dc6rE3mh8giUDcPkQEhEE5CnUKA='
tibcopasswordrevealer.py version 1.0

[+] mangled password:	$man$Dc6rE3mh8giUDcPkQEhEE5CnUKA=
[+] unmangled password:	toto
```

#### Obfuscated password
```
> tibcopasswordrevealer.exe #!/Zbs+cF+HftERpGvBh03jFtPMJQuLItP
tibcopasswordrevealer.py version 1.0

[+] obfuscated password:        #!/Zbs+cF+HftERpGvBh03jFtPMJQuLItP
[+] deobfuscated password:      lolilol
```

Dependencies
------------
* For the `Python` version: PyCrypto (`pip install pycryptodome`)
* For the Windows standalone version: nothing

Changelog
---------
* version 1.0 - 03/06/2016: Initial commit

Greetings
---------
* Tibco for their [clear API](https://docs.tibco.com/pub/enterprise_message_service/8.1.0/doc/html/tib_ems_api_reference/api/javadoc/com/tibco/tibjms/admin/TibjmsAdmin.html) and their [false sense of security](https://docs.tibco.com/pub/runtime_agent/5.8.0_november_2012/html/TIB_TRA_5.8.0_installation/wwhelp/wwhimpl/common/html/wwhelp.htm#context=TIB_TRA_5.8.0_installation&file=install.3.18.htm) with the use of 'obfuscation' as a security measure for credentials storage: '_Passwords encrypted using Obfuscate Utility cannot be decrypted. Ownership is with customers to remember passwords in clear text. There is no utility provided by TIBCO to decrypt passwords encrypted using Obfuscate Utility._'
* [Previous research](http://tibcoworldin.blogspot.fr/2012/08/decrypting-password-data-type-global.html) around decryption
