#!/usr/bin/env python3
"""
accdbpy - Read and dump Microsoft Access .accdb files on Linux
Supports password-protected databases (Agile Encryption, Access 2010+)

Commands:
  tables  <file> [-p PASSWORD]                      List user tables
  dump    <file> [-p PASSWORD] <table>              Pretty-print rows
  export  <file> [-p PASSWORD] <table> [--format]  Export to CSV or JSON
  info    <file> [-p PASSWORD]                      Database summary
  vba     <file> [-p PASSWORD] [--all] [--min-len]  Extract VBA/macro strings

Installation:
  Kali:   sudo apt install python3-pycryptodome
  Other:  pip install pycryptodome --break-system-packages

https://github.com/albindavidc/accdbpy
"""

import argparse
import base64
import hashlib
import json
import struct
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta

try:
    from Crypto.Cipher import AES, ARC4
except ImportError:
    try:
        from Cryptodome.Cipher import AES, ARC4  # Kali: apt install python3-pycryptodome
    except ImportError:
        print("[-] Missing crypto library. Install one of:")
        print("    pip install pycryptodome --break-system-packages")
        print("    sudo apt install python3-pycryptodome  (Kali)")
        sys.exit(1)

PAGE_SIZE      = 0x1000
HEADER_MAGIC   = b'\x00\x01\x00\x00'
ACE_FORMAT_ID  = b'Standard ACE DB\x00'
JET_FORMAT_ID  = b'Standard Jet DB\x00'
RC4_HEADER_KEY = b'\xc7\xda\x39\x6b'

OFF_ENC_KEY      = 0x3e
OFF_ENC_INFO_LEN = 0x299
OFF_ENC_INFO     = 0x29b

# ACE tdef offsets (v4) - verified against access_parser parsing_primitives.py
OFF_TDEF_COL_COUNT   = 0x2d   # u16 column_count
OFF_TDEF_REAL_IDX    = 0x33   # u32 real_index_count
OFF_TDEF_HEADER_END  = 0x3f   # where column defs begin

COL_DEF_SIZE  = 0x19   # 25 bytes per column def in v4
REAL_IDX_SIZE = 0x0c   # 12 bytes per real index entry in v4

OFF_DATA_TDEF = 0x04   # u32 tdef page ptr in data page
OFF_DATA_ROWS = 0x0c   # u16 row count in data page

COL_TYPE_BOOL=0x01; COL_TYPE_BYTE=0x02; COL_TYPE_INT=0x03; COL_TYPE_LONG=0x04
COL_TYPE_CURRENCY=0x05; COL_TYPE_SINGLE=0x06; COL_TYPE_DOUBLE=0x07
COL_TYPE_DATETIME=0x08; COL_TYPE_BINARY=0x09; COL_TYPE_TEXT=0x0a
COL_TYPE_OLE=0x0b; COL_TYPE_MEMO=0x0c; COL_TYPE_GUID=0x0f

COL_FLAG_FIXED    = 0x0001
TABLE_TYPE_USER   = 0x4e  # tdef page flag (not MSysObjects Type)
MSYS_TABLE_TYPE   = 1     # MSysObjects Type value for all tables (user + system)
ACCESS_EPOCH = datetime(1899, 12, 30)

# Patterns that flag a string as potentially interesting in the vba/strings output
CREDENTIAL_PATTERNS = [
    r'password', r'passwd', r'pwd', r'secret', r'credential',
    r'LDAP://', r'ldap://', r'strUser', r'strPass', r'strsUser', r'strsPass',
    r'username', r'login', r'auth',
    r'[A-Za-z0-9]{8,}[0-9][A-Za-z]$',  # password-like: alphanum ending digit+letter
    r'[a-zA-Z0-9]{6,}\d{1,4}[A-Za-z!@#$]',  # pw pattern
    r'\\[a-zA-Z]',       # domain\user style
    r'@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',  # email/domain
    r'\.vl', r'\.local', r'\.corp',  # AD domain suffixes
    r'[A-Za-z0-9+/]{20,}={0,2}$',      # base64 blobs
    r'ADO', r'ActiveX', r'CreateObject',
]


class AccdbError(Exception): pass
class FormatError(AccdbError): pass
class EncryptionError(AccdbError): pass
class PasswordError(AccdbError): pass


def rc4_decrypt_header(header_page):
    cipher = ARC4.new(RC4_HEADER_KEY)
    ks = cipher.decrypt(b'\x00' * 0x80)
    dec = bytearray(header_page)
    for i in range(0x80):
        dec[0x18 + i] ^= ks[i]
    return dec


class AgileEncryption:
    def __init__(self, enc_info, encoding_key):
        self.encoding_key = encoding_key
        self._parse(enc_info)

    def _parse(self, data):
        v_major, v_minor = struct.unpack_from('<HH', data, 0)
        if not (v_major == 0x4 and v_minor == 0x4):
            if v_major == 0x1 and v_minor == 0x1:
                raise EncryptionError("RC4 encryption not supported (old Access 2007)")
            if v_major in (0x2,0x3,0x4) and v_minor == 0x2:
                raise EncryptionError("CryptoAPI encryption not supported")
            raise EncryptionError(f"Unsupported encryption {v_major:#x}/{v_minor:#x} - need Agile (Access 2010+)")
        root = ET.fromstring(data[8:].decode('utf-8', errors='replace'))
        ns_e = 'http://schemas.microsoft.com/office/2006/encryption'
        ns_p = 'http://schemas.microsoft.com/office/2006/keyEncryptor/password'
        kd = root.find(f'{{{ns_e}}}keyData')
        self.db_salt       = base64.b64decode(kd.get('saltValue'))
        self.db_block_size = int(kd.get('blockSize'))
        self.db_key_bits   = int(kd.get('keyBits'))
        ek = root.find(f'{{{ns_e}}}keyEncryptors/{{{ns_e}}}keyEncryptor/{{{ns_p}}}encryptedKey')
        self.pw_salt     = base64.b64decode(ek.get('saltValue'))
        self.pw_spin     = int(ek.get('spinCount'))
        self.pw_key_bits = int(ek.get('keyBits'))
        self.enc_vi = base64.b64decode(ek.get('encryptedVerifierHashInput'))
        self.enc_vh = base64.b64decode(ek.get('encryptedVerifierHashValue'))
        self.enc_kv = base64.b64decode(ek.get('encryptedKeyValue'))

    def _h(self, *parts):
        h = hashlib.sha512()
        for p in parts: h.update(p)
        return h.digest()

    def _derive_key(self, password, block_key):
        pw = password.encode('utf-16-le')
        h = self._h(self.pw_salt, pw)
        for i in range(self.pw_spin):
            h = self._h(struct.pack('<I', i), h)
        h = self._h(h, block_key)
        n = self.pw_key_bits // 8
        return h[:n] if len(h) >= n else h + bytes([0x36]*(n-len(h)))

    def verify_password(self, password):
        k  = self._derive_key(password, b'\xfe\xa7\xd2\x76\x3b\x4b\x9e\x79')
        vi = AES.new(k,  AES.MODE_CBC, iv=self.pw_salt).decrypt(self.enc_vi)
        k2 = self._derive_key(password, b'\xd7\xaa\x0f\x6d\x30\x61\x34\x4e')
        vh = AES.new(k2, AES.MODE_CBC, iv=self.pw_salt).decrypt(self.enc_vh)
        return self._h(vi) == vh[:64]

    def get_master_key(self, password):
        k  = self._derive_key(password, b'\x14\x6e\x0b\xe7\xab\xac\xd0\xd6')
        mk = AES.new(k,  AES.MODE_CBC, iv=self.pw_salt).decrypt(self.enc_kv)
        return mk[:self.db_key_bits // 8]

    def get_iv(self, page_num):
        bk = bytes(a^b for a,b in zip(struct.pack('<I',page_num), self.encoding_key))
        iv = self._h(self.db_salt, bk)
        n  = self.db_block_size
        return iv[:n] if len(iv) >= n else iv + bytes([0x36]*(n-len(iv)))

    def decrypt_page(self, page_data, page_num, master_key):
        return AES.new(master_key, AES.MODE_CBC, iv=self.get_iv(page_num)).decrypt(page_data)


class PageReader:
    def __init__(self, data, encryption=None, master_key=None):
        self.data       = data
        self.encryption = encryption
        self.master_key = master_key
        self.num_pages  = len(data) // PAGE_SIZE

    def read_page(self, page_num):
        if page_num >= self.num_pages:
            raise FormatError(f"Page {page_num} out of range")
        raw = self.data[page_num*PAGE_SIZE:(page_num+1)*PAGE_SIZE]
        if page_num == 0:
            return raw
        if self.encryption and self.master_key:
            return self.encryption.decrypt_page(raw, page_num, self.master_key)
        return raw


class AccdbParser:
    """
    Parses .accdb table definitions and row data.

    Row layout (ACE/Jet4) - verified empirically:
    - Offset table at page end: slot[i] = PAGE_SIZE - 2*(i+1)
      Record for row i spans [row_i_offset : row_{i-1}_offset]
      (i.e. each row's end = the PREVIOUS slot's offset, in slot-table order)
    - Null bitmap: last null_bmap_size bytes of record
    - Var metadata (read from reversed record after stripping null bytes):
        u16 BE: var_field_count
        var_field_count * u16 BE: var start offsets (from record start)
        u16 BE: var_len_count (end of last var field)
    - Fixed cols: at fixed_offset from record start
    - Var cols ordered by var_col_number
    """

    def __init__(self, reader):
        self.reader   = reader
        self._catalog = None

    def get_tables(self):
        cat = self._get_catalog()
        return sorted(
            n for n, info in cat.items()
            if info.get('type') == MSYS_TABLE_TYPE
            and not n.startswith('MSys')
            and info.get('tdef_page', 0) > 0
        )

    def get_rows(self, table_name):
        cat = self._get_catalog()
        if table_name not in cat:
            raise AccdbError(f"Table '{table_name}' not found")
        tdef_page = cat[table_name]['tdef_page']
        cols = self._read_columns(tdef_page)
        rows = []
        for pg_num in self._find_data_pages(tdef_page):
            try:
                page = self.reader.read_page(pg_num)
                if page[0] == 0x01:
                    rows.extend(self._parse_data_page(page, cols))
            except Exception:
                continue
        return rows

    # ------------------------------------------------------------------

    def _get_catalog(self):
        if self._catalog is not None:
            return self._catalog
        header = rc4_decrypt_header(self.reader.read_page(0))
        msys_tdef = struct.unpack_from('<I', header, 0x20)[0]
        if not (0 < msys_tdef < self.reader.num_pages):
            raise FormatError("Cannot find MSysObjects tdef page")
        msys_cols = self._read_columns(msys_tdef)
        catalog = {}
        for pg_num in self._find_data_pages(msys_tdef):
            try:
                page = self.reader.read_page(pg_num)
                if page[0] != 0x01:
                    continue
                for row in self._parse_data_page(page, msys_cols):
                    name     = row.get('Name')
                    obj_type = row.get('Type')
                    obj_id   = row.get('Id')
                    if name and obj_type is not None and obj_id is not None:
                        catalog[name] = {'type': obj_type, 'tdef_page': obj_id}
            except Exception:
                continue
        self._catalog = catalog
        return catalog

    def _read_columns(self, tdef_page_num):
        page = self.reader.read_page(tdef_page_num)
        if page[0] != 0x02:
            raise FormatError(f"Page {tdef_page_num} not a tdef (type={page[0]:#x})")
        num_cols = struct.unpack_from('<H', page, OFF_TDEF_COL_COUNT)[0]
        real_idx = struct.unpack_from('<I', page, OFF_TDEF_REAL_IDX)[0]
        if num_cols == 0 or num_cols > 4096:
            raise FormatError(f"Implausible column count: {num_cols}")
        col_def_base = OFF_TDEF_HEADER_END + real_idx * REAL_IDX_SIZE
        cols_raw = []
        for i in range(num_cols):
            off = col_def_base + i * COL_DEF_SIZE
            if off + COL_DEF_SIZE > PAGE_SIZE:
                break
            col_type  = page[off + 0x00]
            col_id    = struct.unpack_from('<H', page, off + 0x05)[0]
            var_num   = struct.unpack_from('<H', page, off + 0x07)[0]
            flags     = struct.unpack_from('<H', page, off + 0x0f)[0]
            fixed_off = struct.unpack_from('<H', page, off + 0x15)[0]
            length    = struct.unpack_from('<H', page, off + 0x17)[0]
            cols_raw.append((col_type, col_id, var_num, bool(flags & COL_FLAG_FIXED), fixed_off, length))
        name_off = col_def_base + num_cols * COL_DEF_SIZE
        names = []
        for i in range(num_cols):
            if name_off + 2 > PAGE_SIZE:
                names.append(f'col{i}'); continue
            nlen = struct.unpack_from('<H', page, name_off)[0]
            name_off += 2
            if nlen == 0 or name_off + nlen > PAGE_SIZE:
                names.append(f'col{i}'); continue
            names.append(page[name_off:name_off+nlen].decode('utf-16-le', errors='replace'))
            name_off += nlen
        result = []
        for i, (ct, cid, vn, fixed, fo, ln) in enumerate(cols_raw):
            nm = names[i] if i < len(names) else f'col{i}'
            result.append({'name':nm,'type':ct,'is_fixed':fixed,'fixed_off':fo,
                           'length':ln,'var_num':vn,'col_id':cid})
        return result

    def _find_data_pages(self, tdef_page_num):
        pages = []
        for p in range(1, self.reader.num_pages):
            try:
                pg = self.reader.read_page(p)
                if pg[0] == 0x01 and struct.unpack_from('<I', pg, OFF_DATA_TDEF)[0] == tdef_page_num:
                    pages.append(p)
            except Exception:
                continue
        return pages

    def _parse_data_page(self, page, cols):
        """
        Parse a data page.

        Data page layout (ACE v4):
          0x00-0x01  page type + unknown (2 bytes)
          0x02-0x03  free space (u16)
          0x04-0x07  tdef owner page number (u32)
          0x08-0x0b  unknown (u32)
          0x0c-0x0d  record_count (u16)
          0x0e+      offset table: record_count * u16, each entry is raw slot value
          after table: record data area (grows downward from high offsets)

        Slot value flags:
          0x8000 = deleted
          0x4000 = overflow (record continues on another page)
          0x1fff = byte offset of record start within page

        Record boundaries (access_parser style):
          Iterate slots in table order. Each record ends at the previous slot's offset.
          First slot ends at the start of the next record area (no explicit end needed;
          the record simply extends until last_offset, or to page end for the first).
        """
        row_count = struct.unpack_from('<H', page, OFF_DATA_ROWS)[0]
        if row_count == 0 or row_count > 0x800:
            return []

        fixed_cols = sorted([c for c in cols if c['is_fixed']], key=lambda x: x['fixed_off'])
        var_cols   = sorted([c for c in cols if not c['is_fixed']], key=lambda x: x['col_id'])
        num_cols   = len(cols)
        all_by_id  = sorted(cols, key=lambda c: c['col_id'])
        col_null_idx = {c['col_id']: i for i, c in enumerate(all_by_id)}

        # Read offset table from 0x0e (forward, not from page end)
        offsets_raw = []
        for i in range(row_count):
            pos = 0x0e + i * 2
            if pos + 2 > PAGE_SIZE:
                break
            offsets_raw.append(struct.unpack_from('<H', page, pos)[0])

        rows = []
        last_offset = None

        for raw in offsets_raw:
            deleted  = bool(raw & 0x8000)
            overflow = bool(raw & 0x4000)
            offset   = raw & 0x1fff

            if deleted:
                last_offset = offset & 0x0fff
                continue
            if overflow:
                last_offset = offset
                continue

            # Record spans [offset : last_offset] (or to page end if first row)
            if last_offset is None:
                record = page[offset:]
            else:
                record = page[offset:last_offset]

            last_offset = offset

            if not record or len(record) < 4:
                continue

            row = self._parse_row(record, fixed_cols, var_cols, num_cols, col_null_idx)
            if row is not None:
                rows.append(row)

        return rows

    def _parse_row(self, record, fixed_cols, var_cols, num_cols, col_null_idx):
        """
        Parse a single row record (ACE v4).

        Record structure:
          [0:2]   field_count (u16 LE) - stripped before reading fixed cols
          [2:...]  fixed-length column data at fixed_offset from byte 2
          [...]    variable-length column data
          [-n:-3]  var metadata (read from reversed record after null bitmap)
          [-3:]    null bitmap (3 bytes for <=24 cols), ceil(num_cols/8) bytes

        Null bitmap: bit SET = column HAS a value (not null).
        Indexed by col_id (sorted ascending).

        Var metadata (read from reversed record after stripping null_bitmap bytes):
          u16 BE: var_field_count
          var_field_count * u16 BE: start offsets (from record[0], NOT stripped)
          u16 BE: var_len_count (end boundary of last var col)

        Var cols are ordered by col_id ascending for var_offsets indexing.
        """
        if not record or len(record) < 4:
            return None

        # Strip v4 2-byte header to get fixed data base
        fixed_base = record[2:]

        null_bmap_size = (num_cols + 7) // 8
        if null_bmap_size > len(record):
            null_bmap = b'\xff' * null_bmap_size  # assume all present
        else:
            null_bmap = record[-null_bmap_size:]

        def has_value(col_id):
            """Returns True if the column has a value (bit set = present)."""
            idx = col_null_idx.get(col_id, -1)
            if idx < 0:
                return True
            bi, bit = idx // 8, idx % 8
            if bi >= len(null_bmap):
                return True
            return bool(null_bmap[bi] & (1 << bit))

        # Parse var metadata from reversed record after stripping null bytes
        rev_no_null = record[::-1][null_bmap_size:]
        var_offsets   = []
        var_len_count = 0

        if len(rev_no_null) >= 2:
            vfc = struct.unpack_from('>H', rev_no_null, 0)[0]
            if 0 < vfc <= len(var_cols) and 2 + vfc * 2 + 2 <= len(rev_no_null):
                var_offsets = [struct.unpack_from('>H', rev_no_null, 2 + i*2)[0] for i in range(vfc)]
                var_len_count = struct.unpack_from('>H', rev_no_null, 2 + vfc*2)[0]

        result = {}

        # Fixed columns (offsets relative to fixed_base = record[2:])
        for fc in fixed_cols:
            nm = fc['name']
            if not has_value(fc['col_id']):
                result[nm] = None
                continue
            fo, ln = fc['fixed_off'], fc['length']
            if fo + ln > len(fixed_base) or ln == 0:
                result[nm] = None
                continue
            result[nm] = self._decode_value(fixed_base[fo:fo+ln], fc['type'])

        # Variable columns (offsets relative to original record[0])
        for i, vc in enumerate(var_cols):
            nm = vc['name']
            if not has_value(vc['col_id']):
                result[nm] = None
                continue
            if i >= len(var_offsets):
                result[nm] = None
                continue
            start = var_offsets[i]
            end   = var_offsets[i+1] if i+1 < len(var_offsets) else var_len_count
            if start == end:
                result[nm] = ''
                continue
            if start > end or end > len(record):
                result[nm] = None
                continue
            result[nm] = self._decode_value(record[start:end], vc['type'])

        return result if result else None

    def _decode_value(self, raw, col_type):
        if not raw:
            return None
        try:
            if col_type == COL_TYPE_BOOL:     return bool(raw[0])
            if col_type == COL_TYPE_BYTE:     return raw[0]
            if col_type == COL_TYPE_INT:      return struct.unpack_from('<h', raw)[0]
            if col_type == COL_TYPE_LONG:     return struct.unpack_from('<i', raw)[0]
            if col_type == COL_TYPE_CURRENCY: return struct.unpack_from('<q', raw)[0] / 10000.0
            if col_type == COL_TYPE_SINGLE:   return struct.unpack_from('<f', raw)[0]
            if col_type == COL_TYPE_DOUBLE:   return struct.unpack_from('<d', raw)[0]
            if col_type == COL_TYPE_DATETIME:
                v = struct.unpack_from('<d', raw)[0]
                try: return (ACCESS_EPOCH + timedelta(days=v)).strftime('%Y-%m-%d %H:%M:%S')
                except: return str(v)
            if col_type == COL_TYPE_TEXT:
                return self._decode_text(raw)
            if col_type == COL_TYPE_MEMO:
                result = self._read_lval(raw)
                return result if result is not None else raw.hex()
            if col_type == COL_TYPE_GUID:
                if len(raw) >= 16:
                    a,b,c = struct.unpack_from('<IHH', raw)
                    return f'{{{a:08x}-{b:04x}-{c:04x}-{raw[8:10].hex()}-{raw[10:16].hex()}}}'
                return raw.hex()
            if col_type in (COL_TYPE_BINARY, COL_TYPE_OLE):
                return raw.hex()
            try: return raw.decode('utf-16-le', errors='replace').rstrip('\x00')
            except: return raw.hex()
        except Exception:
            return raw.hex() if raw else None

    def _read_lval(self, raw):
        """
        Decode a Memo/Long Text LVAL reference or inline value.

        Access stores Memo (type 0x0c) and long Text fields using a tagged format:
          Flag byte (high byte of first u32):
            0x80 = data is inline in this record
            0x40 = data is on a separate LVAL page (external reference)

        Inline layout  (flag 0x80):
          [u32 flags+size LE][8 zero bytes][fffe + compressed-unicode text]

        External layout (flag 0x40):
          [u32 flags+size LE][u8 row_id][u16 page_num LE][5 zero bytes]
          -> read row row_id from LVAL page page_num
        """
        if not raw or len(raw) < 4:
            return None
        flags = struct.unpack_from('<I', raw, 0)[0]
        flag_byte = (flags >> 24) & 0xFF

        if flag_byte & 0x80:
            # Inline: data follows after 12-byte header
            text_raw = raw[12:]
            return self._decode_compressed_text(text_raw)

        if flag_byte & 0x40:
            # External: pointer to LVAL page
            if len(raw) < 7:
                return None
            row_id   = raw[4]
            page_num = struct.unpack_from('<H', raw, 5)[0]
            if page_num == 0:
                return None
            try:
                pg = self.reader.read_page(page_num)
            except Exception:
                return None
            row_count = struct.unpack_from('<H', pg, 0x0c)[0]
            if row_id >= row_count:
                return None
            offsets_raw = [struct.unpack_from('<H', pg, 0x0e + i*2)[0]
                           for i in range(row_count)]
            last_offset = None
            rows = []
            for r in offsets_raw:
                deleted  = bool(r & 0x8000)
                overflow = bool(r & 0x4000)
                offset   = r & 0x1fff
                if deleted:
                    last_offset = offset & 0x0fff
                    rows.append(None)
                    continue
                if overflow:
                    last_offset = offset
                    rows.append(None)
                    continue
                rec = pg[offset:] if last_offset is None else pg[offset:last_offset]
                last_offset = offset
                rows.append(rec)
            if row_id >= len(rows) or rows[row_id] is None:
                return None
            return self._decode_compressed_text(rows[row_id])

        # Unknown flag — return raw hex
        return raw.hex()

    def _decode_compressed_text(self, raw):
        """Decode Access compressed unicode (fffe prefix = Latin-1) or UTF-16-LE."""
        if not raw:
            return ''
        if raw[:2] == b'\xff\xfe' or raw[:2] == b'\xfe\xff':
            return raw[2:].decode('latin-1', errors='replace').rstrip('\x00')
        try:
            return raw.decode('utf-16-le', errors='replace').rstrip('\x00')
        except Exception:
            return raw.decode('latin-1', errors='replace').rstrip('\x00')

    def _decode_text(self, raw):
        if not raw: return ''
        # Long-text inline overflow header: [16 zero bytes][u32 LE length][text]
        # Used for Text columns (0x0a) with length > 255 stored inline on data page.
        if len(raw) > 20 and raw[:16] == b'\x00' * 16:
            text_len = struct.unpack_from('<I', raw, 16)[0]
            raw = raw[20:20 + text_len]
            if not raw: return ''
        return self._decode_compressed_text(raw)


class Database:
    def __init__(self, file_path, password=None):
        self.file_path = file_path
        self.password  = password
        self._load()

    def _load(self):
        with open(self.file_path, 'rb') as f:
            data = f.read()
        if len(data) < PAGE_SIZE:
            raise FormatError("File too small")
        # .accdt is a ZIP-based XML template, not a binary database
        if data[:2] == b'PK':
            raise FormatError(
                ".accdt template files are not supported - "
                "accdbpy reads binary .accdb databases only"
            )
        header = data[:PAGE_SIZE]
        if header[0:4] != HEADER_MAGIC:
            raise FormatError("Invalid magic - not an Access database")
        fmt = header[0x04:0x14]
        if fmt == JET_FORMAT_ID:
            raise FormatError(".mdb (Jet) format not supported - use mdb-tools instead")
        if fmt != ACE_FORMAT_ID:
            raise FormatError("Unknown format ID")
        header_dec   = rc4_decrypt_header(header)
        encoding_key = bytes(header_dec[OFF_ENC_KEY:OFF_ENC_KEY+4])
        enc_info_len = struct.unpack_from('<H', data, OFF_ENC_INFO_LEN)[0]
        encryption = None; master_key = None
        if 0 < enc_info_len < PAGE_SIZE:
            enc_info = data[OFF_ENC_INFO:OFF_ENC_INFO+enc_info_len]
            try:
                encryption = AgileEncryption(enc_info, encoding_key)
                if self.password is None:
                    raise PasswordError("This database is password-protected. Use -p to provide the password.")
                if not encryption.verify_password(self.password):
                    raise PasswordError("Incorrect password")
                master_key = encryption.get_master_key(self.password)
            except (EncryptionError, PasswordError): raise
            except Exception: encryption = None
        self.parser    = AccdbParser(PageReader(data, encryption, master_key))
        self.encrypted = encryption is not None

    def tables(self):  return self.parser.get_tables()
    def rows(self, t): return self.parser.get_rows(t)


def print_table(rows, table_name):
    if not rows:
        print(f"(no rows in '{table_name}')"); return
    cols = list(rows[0].keys())
    widths = {c: max(len(c), 1) for c in cols}
    for row in rows:
        for c in cols:
            widths[c] = max(widths[c], min(len(str(row.get(c) or '')), 80))
    sep = '+' + '+'.join('-'*(widths[c]+2) for c in cols) + '+'
    print(sep)
    print('|' + '|'.join(f' {c:<{widths[c]}} ' for c in cols) + '|')
    print(sep)
    for row in rows:
        line = '|'
        for c in cols:
            v = str(row.get(c) or '')
            if len(v) > widths[c]: v = v[:widths[c]-3]+'...'
            line += f' {v:<{widths[c]}} |'
        print(line)
    print(sep)
    print(f"({len(rows)} row{'s' if len(rows)!=1 else ''})")


def cmd_tables(args):
    db = Database(args.file, args.password)
    tables = db.tables()
    if not tables: print("(no user tables found)")
    else:
        for t in tables: print(t)

def cmd_dump(args):
    db = Database(args.file, args.password)
    print_table(db.rows(args.table), args.table)

def cmd_export(args):
    db = Database(args.file, args.password)
    rows = db.rows(args.table)
    if args.format == 'json':
        print(json.dumps(rows, indent=2, default=str))
    else:
        import csv
        if rows:
            w = csv.DictWriter(sys.stdout, fieldnames=list(rows[0].keys()))
            w.writeheader(); w.writerows(rows)

def cmd_info(args):
    db = Database(args.file, args.password)
    tables = db.tables()
    print(f"File:      {args.file}")
    print(f"Format:    ACE (.accdb)")
    print(f"Encrypted: {'yes' if db.encrypted else 'no'}")
    print(f"Tables:    {len(tables)}")
    for t in tables:
        try: print(f"  {t} ({len(db.rows(t))} rows)")
        except Exception as e: print(f"  {t} (error: {e})")

    # Check if there is any readable content in VBA/LVAL pages.
    # If so, nudge the user to check — regardless of what the content looks like.
    reader = db.parser.reader
    has_vba_content = False
    for pn in range(reader.num_pages):
        try:
            pg = reader.read_page(pn)
        except Exception:
            continue
        if pg[0] not in (0x01, 0x08, 0x09):
            continue
        import re as _re
        text = pg.decode('latin-1', errors='replace')
        for m in _re.finditer(r'[ -~]{8,}', text):
            s = m.group().strip()
            if s and len(set(s)) >= 3:
                has_vba_content = True
                break
        if has_vba_content:
            break

    if has_vba_content:
        print()
        p_flag = f" -p <password>" if db.encrypted else ""
        print(f"[*] This database contains VBA/macro content.")
        print(f"    It may include credentials, queries, or connection strings not visible in tables.")
        print(f"    Run: accdbpy.py vba {args.file}{p_flag}")

def cmd_vba(args):
    """
    Extract strings from LVAL (large value / memo/OLE) pages in the database.
    These pages store VBA module source, LDAP queries, embedded credentials,
    and other large text/binary objects that are not accessible via table queries.

    Output has two sections:
      [!] Highlighted lines — matched against common credential/config patterns
      [*] All strings      — every printable string >= min_len characters
    """
    import re

    db = Database(args.file, args.password)
    reader = db.parser.reader
    min_len = args.min_len

    # Collect all strings from LVAL pages (page type 0x01 with LVAL magic,
    # and any page whose decoded text contains long printable runs)
    all_strings = []
    seen = set()

    for pn in range(reader.num_pages):
        try:
            pg = reader.read_page(pn)
        except Exception:
            continue

        # Only scan data/LVAL pages - skip tdef, index, map pages
        if pg[0] not in (0x01, 0x08, 0x09):
            continue

        text = pg.decode('latin-1', errors='replace')
        for m in re.finditer(r'[ -~]{' + str(min_len) + r',}', text):
            s = m.group().strip()
            if not s or s in seen:
                continue
            # Skip strings that are pure whitespace, repetitive, or likely bytecode fragments
            if len(set(s)) < 3:
                continue
            # Skip very short fragments that look like bytecode artifacts
            if len(s) < 12 and re.search(r'^[a-z]{1,4} [A-Z_]{1,4}', s):
                continue
            seen.add(s)
            all_strings.append(s)

    if not all_strings:
        print("(no strings found)")
        return

    # Classify strings
    interesting = []
    for s in all_strings:
        for pat in CREDENTIAL_PATTERNS:
            if re.search(pat, s, re.IGNORECASE):
                interesting.append(s)
                break

    if interesting:
        print(f"[!] Interesting strings ({len(interesting)} found):")
        print()
        for s in interesting:
            print(f"    {s}")
        print()

    if args.all or not interesting:
        print(f"[*] All strings ({len(all_strings)} found, min length={min_len}):")
        print()
        for s in all_strings:
            marker = "[!]" if s in interesting else "   "
            print(f"    {marker} {s}")


def main():
    p = argparse.ArgumentParser(prog='accdbpy',
        description='Read and dump Microsoft Access .accdb files on Linux',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  accdbpy.py tables  database.accdb
  accdbpy.py tables  database.accdb -p MyPassword
  accdbpy.py info    database.accdb -p MyPassword
  accdbpy.py dump    database.accdb -p MyPassword Users
  accdbpy.py export  database.accdb -p MyPassword Users --format csv
  accdbpy.py vba     database.accdb -p MyPassword
        """)
    sub = p.add_subparsers(dest='command', metavar='command')
    sub.required = True
    for name, help_txt in [('tables','List user tables'),('info','Show database summary')]:
        sp = sub.add_parser(name, help=help_txt)
        sp.add_argument('file')
        sp.add_argument('-p','--password', default=None, metavar='PASSWORD')
        sp.set_defaults(func=globals()[f'cmd_{name}'])
    for name, help_txt in [('dump','Pretty-print table rows'),('export','Export to CSV/JSON')]:
        sp = sub.add_parser(name, help=help_txt)
        sp.add_argument('file')
        sp.add_argument('-p','--password', default=None, metavar='PASSWORD')
        sp.add_argument('table')
        if name == 'export':
            sp.add_argument('--format', choices=['csv','json'], default='csv')
        sp.set_defaults(func=globals()[f'cmd_{name}'])
    p_vba = sub.add_parser('vba', help='Extract strings from VBA/LVAL pages (credentials, macros)')
    p_vba.add_argument('file')
    p_vba.add_argument('-p', '--password', default=None, metavar='PASSWORD')
    p_vba.add_argument('--all', action='store_true', help='Show all strings, not just interesting ones')
    p_vba.add_argument('--min-len', type=int, default=8, metavar='N', help='Minimum string length (default: 8)')
    p_vba.set_defaults(func=cmd_vba)

    args = p.parse_args()
    try:
        args.func(args)
    except PasswordError as e:
        print(f"[-] {e}", file=sys.stderr); sys.exit(1)
    except AccdbError as e:
        print(f"[-] {e}", file=sys.stderr); sys.exit(1)
    except FileNotFoundError:
        print(f"[-] File not found: {args.file}", file=sys.stderr); sys.exit(1)
    except KeyboardInterrupt:
        pass

if __name__ == '__main__':
    try:
        main()
    except BrokenPipeError:
        pass
