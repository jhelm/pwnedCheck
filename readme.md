# pwnedCheck

pwnedCheck is a Unix command line tool that performs a binary search
for a password or SHA1 hash in Troy Hunt's [`pwned`](https://www.troyhunt.com/pwned-passwords-v3-is-now-live/)
password file.

While the presence of a password does not mean your account has been
compromised, prudence dictates the password be changed
anyway. Ironically, the stronger the found password is, the more likely
the compromised credentials are yours. Bottom line: passwords
appearing in this file should be changed.

## Hacked Passwords and The Pwned Data File

The security blogger Troy Hunt has compiled the
[`pwned`](https://www.troyhunt.com/pwned-passwords-v3-is-now-live/)
datafile of passwords that have been harvested by hackers and put up
for sale on the dark web. In July of 2018 he released V3 of this
datafile, which contains over 517 million stolen passwords. You can
use this file to check if a password is on this list.

The easiest way is to use the [password
page](https://haveibeenpwned.com/Passwords) on Troy's
[haveibeenpwned.com](https://haveibeenpwned.com/) website. This can
become tedious should the list of passwords be long. Moreover, while
haveibeenpwned.com uses a k-anonymity algorithm to protect your
privacy, you still have to remain vigilant for spoofing attacks.

The next easiest way, if you use the 1Password application, is to use
the Watchtower feature. This will check your entire vault against the
pwned datafile.

Absent being a 1Password user, you can write a script to check
passwords against the [haveibeenpwned.com
api](https://haveibeenpwned.com/API/v2\#PwnedPasswords).

The final option is to download a copy of the pwned file and check
one's passwords locally. The file is available via
[bittorrent](https://downloads.pwnedpasswords.com/passwords/pwned-passwords-ordered-by-hash.7z.torrent)
or (less desirably) as a direct download. For people familiar with
Unix, the following bash command provides one way to check a
password (where the pwned file is `./pwned-passwords-ordered-by-hash.txt`):

```
export TSTPWD=`echo -n "123456" | openssl sha1 | awk '{ print toupper($1) }'` && fgrep $TSTPWD ./pwned-passwords-ordered-by-hash.txt
```
The problem here is fgrep performs a linear search of the entire file, 
which can take several minutes.

Of course you can download the pwned datafile, squirt it into a
small SQL database, and index the SHA1 fields for fast queries. For many
this is a great solution. Others may find the chore hard to justify.

## pwnedCheck Lookup Tool

`pwnedCheck` is a straightforward Unix command line tool that performs a
binary search on a disk resident copy of the pwned file sorted in
ascending SHA1 order. All data processing is on your local
machine. The format of this file is a SHA1 password hash (to protect
passwords containing PII) followed a count of the number of breached
databases that password has appeared in. `pwnedCheck` can accept
either a plaintext password or a SHA1 hash as input, and return the
number of breached databases that password appeared in. Here are some
examples:

```
OK-Computer:pwnedCheck jlh$ pwnedCheck 123456
Sad news, this password has appeared in 22390492 password databases for sale on the Dark Web.
OK-Computer:pwnedCheck jlh$ pwnedCheck password
Sad news, this password has appeared in 3533661 password databases for sale on the Dark Web.
OK-Computer:pwnedCheck jlh$ pwnedCheck kickOffMyShoesAndRun
Good news, this password is not present in the hacked password database.
OK-Computer:pwnedCheck jlh$
OK-Computer:pwnedCheck jlh$ export TSTPWD=`echo -n "123456" | openssl sha1 | awk '{ print toupper($1) }'` && echo $TSTPWD
7C4A8D09CA3762AF61E59520943DC26494F8941B
OK-Computer:pwnedCheck jlh$ pwnedCheck -s 7C4A8D09CA3762AF61E59520943DC26494F8941B
Sad news, this password has appeared in 22390492 password databases for sale on the Dark Web.
OK-Computer:pwnedCheck jlh$ pwnedCheck -t -s 7C4A8D09CA3762AF61E59520943DC26494F8941B
22390492
OK-Computer:pwnedCheck jlh$ echo -n 7C4A8D09CA3762AF61E59520943DC26494F8941B | pwnedCheck -s
Sad news, this password has appeared in 22390492 password databases for sale on the Dark Web.
```

## Getting Started

N.B. This program requires a POSIX Unix environment. It was developed
in the OS X 10.13.6 command line environment (i.e. without Xcode) and
has not been tested elsewhere.

- [ ] Download the pwned-passwords-ordered-by-hash.txt from [here](https://downloads.pwnedpasswords.com/passwords/pwned-passwords-ordered-by-hash.7z.torrent)
- [ ] Pull this repo
- [ ] \(Optional) If desired, edit the Makefile to chage the PWNED_DATA variable for your default pwned datafile filespec
- [ ] \(Optional) If desired, edit the Makefile to change the INST_BIN variable for your default directory for executables
- [ ] Run make
- [ ] Run make install
- [ ] Run make tests

If the tests pass, you're good to go.
