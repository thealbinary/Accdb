# accdbpy

Read and dump Microsoft Access `.accdb` files on Linux, including password-protected ones.

**No Windows. No Java. No ODBC drivers. One Python script.**

## The problem

When you encounter a password-protected `.accdb` during a penetration test or CTF, the usual workflow is:

1. Use `office2john` + hashcat/john to crack the password
2. Spin up a Windows VM just to open the file
3. Manually export the data you need

`accdbpy` is a single script with one dependency that lets you skip step 2. Drop it onto Kali, crack the password, and read the file directly on Linux. It also goes beyond just reading tables. The `vba` command extracts strings from embedded macros, where credentials are sometimes stored instead of in tables.

## Requirements

Python 3.x and `pycryptodome`.

**Kali / Debian:**
```bash
sudo apt install python3-pycryptodome
```

**Other Linux / pip:**
```bash
pip install pycryptodome --break-system-packages
```

## Commands

```
accdbpy.py tables  <file> [-p PASSWORD]
accdbpy.py info    <file> [-p PASSWORD]
accdbpy.py dump    <file> [-p PASSWORD] <table>
accdbpy.py export  <file> [-p PASSWORD] <table> [--format csv|json]
accdbpy.py vba     <file> [-p PASSWORD] [--all] [--min-len N]
```

The `-p` flag can appear anywhere in the command.

## Usage

### Start here: database summary

The best first command on any unfamiliar `.accdb` file. Shows tables, row counts, and automatically flags if the database contains VBA/macro content worth investigating.

```bash
python3 accdbpy.py info database.accdb -p MyPassword
```

```
File:      database.accdb
Format:    ACE (.accdb)
Encrypted: yes
Tables:    2
  StaffMembers (0 rows)
  Resources (1 rows)

[*] This database contains VBA/macro content.
    It may include credentials, queries, or connection strings not visible in tables.
    Run: accdbpy.py vba database.accdb -p MyPassword
```

### List tables

```bash
python3 accdbpy.py tables database.accdb
python3 accdbpy.py tables database.accdb -p MyPassword
```

### Pretty-print a table

```bash
python3 accdbpy.py dump database.accdb -p MyPassword Users
```

```
+----------+------------------+----------+
| Username | Password         | Role     |
+----------+------------------+----------+
| admin    | SuperSecret123   | Admin    |
| jsmith   | Password1!       | User     |
+----------+------------------+----------+
(2 rows)
```

### Export to CSV or JSON

```bash
python3 accdbpy.py export database.accdb -p MyPassword Users --format csv > users.csv
python3 accdbpy.py export database.accdb -p MyPassword Users --format json
```

### Extract strings from VBA modules

Access databases often store credentials, LDAP queries, and connection strings inside VBA macros rather than in tables. These are not visible via normal table queries. The `vba` command scans the database and extracts readable strings, flagging anything that looks credential-like.

```bash
# Show only flagged strings
python3 accdbpy.py vba database.accdb -p MyPassword

# Show all strings with flagged ones marked [!]
python3 accdbpy.py vba database.accdb -p MyPassword --all

# Adjust minimum string length (default: 8)
python3 accdbpy.py vba database.accdb -p MyPassword --min-len 12
```

Example output:
```
[!] Interesting strings (5 found):

    LDAP://OU=staff,DC=corp,DC=local
    corp\svcaccount
    P@ssw0rd123
    ImportUsersFromLDAP
    C:\Program Files\...\VBE7.DLL
```

Note: `vba` does string extraction, not full VBA source decompilation. Function names, string literals, and connection strings are reliably extracted. Some strings from compressed bytecode regions may appear garbled.

## Typical pentest workflow

```bash
# 1. Crack the password
office2john target.accdb > hash.txt
john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt

# 2. Run info first (it tells you what to do next)
python3 accdbpy.py info target.accdb -p crackedpassword

# 3. Dump any tables that look interesting
python3 accdbpy.py dump target.accdb -p crackedpassword Users

# 4. If info flagged VBA content, check it
python3 accdbpy.py vba target.accdb -p crackedpassword
```

## Encryption support

`accdbpy` supports **Agile Encryption** (AES-256-CBC + SHA-512 key derivation), which is the default encryption scheme for Access 2010 and later.

The older CryptoAPI/RC4 encryption used by some Access 2007 databases is not currently supported. The majority of `.accdb` files encountered in practice use Agile Encryption.

## Limitations

- Read-only, no write support
- Access 2007+ (`.accdb`) only, `.mdb` files are not supported
- `.accdt` template files are not supported (ZIP-based XML format, not binary)
- OLE and attachment fields are returned as hex strings
- Multi-value and complex fields are not decoded
- `vba` extracts strings only, it does not fully decompile VBA bytecode

## Credits

**Format references** (used as documentation only, no code copied):

- [mdbtools HACKING.md](https://github.com/mdbtools/mdbtools/blob/master/HACKING.md): reverse-engineered Jet4/ACE page format documentation
- [The Unofficial MDB Guide](https://web.archive.org/web/20230729195418/http://jabakobob.net/mdb/): additional Jet format notes
- [MS-OFFCRYPTO](https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-offcrypto/): Microsoft's open specification for Office document encryption

**Dependencies:**

- [pycryptodome](https://github.com/Legrandin/pycryptodome): AES and RC4 primitives (MIT/BSD licence)

**Built by:**

[Albin David](https://github.com/thealbinary), with the help of [Claude](https://claude.ai) (Anthropic).

## License

MIT, see [LICENSE](LICENSE)
