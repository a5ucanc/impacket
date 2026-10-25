# Impacket - Collection of Python classes for working with network protocols.
#
# Copyright Fortra, LLC and its affiliated companies
#
# All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Unit test for NTLM2 (Extended Session Security) RPC message signing used by
# DCERPC_v5 in impacket/dcerpc/v5/rpcrt.py.
#
# With NTLM2 only the stub is sealed, but the signature covers the WHOLE PDU
# (header + plaintext stub + sec_trailer, i.e. get_packet()[:-16]). The send path
# already signed the whole PDU; the recv path used to sign the stub only (the old
# "TODO: FIX THIS"), so a server's sealed-response MAC could never be verified.
# This pins the correct, symmetric round-trip the recv path now implements.
import unittest

from Cryptodome.Cipher import ARC4
from impacket import ntlm


class NTLM2RpcHeaderSigningTests(unittest.TestCase):
    def setUp(self):
        self.flags = (ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
                      | ntlm.NTLMSSP_NEGOTIATE_128
                      | ntlm.NTLMSSP_NEGOTIATE_KEY_EXCH
                      | ntlm.NTLMSSP_NEGOTIATE_SEAL
                      | ntlm.NTLMSSP_NEGOTIATE_SIGN)
        self.sessionKey = b"A" * 16
        # server->client direction keys (what the client recv path verifies)
        self.signKey = ntlm.SIGNKEY(self.flags, self.sessionKey, b"Server")
        self.sealKey = ntlm.SEALKEY(self.flags, self.sessionKey, b"Server")
        # a sealed RESPONSE PDU laid out as [header][stub][sec_trailer][auth(16)]
        self.header = bytes(range(24))                 # common + response header
        self.stub = b"IRpcCmdProc response stub payload" + b"\xBB" * 3   # +auth pad
        self.secTrailer = bytes([10, 6, 3, 0, 0, 0, 1, 2])
        self.seq = 0

    def _server_send(self):
        # Mirror rpcrt.py send: sign the whole PDU minus the 16-byte auth value,
        # encrypt only the stub.
        handle = ARC4.new(self.sealKey).encrypt
        full_minus_auth = self.header + self.stub + self.secTrailer
        sealed, sig = ntlm.SEAL(self.flags, self.signKey, self.sealKey,
                                full_minus_auth, self.stub, self.seq, handle)
        wire = self.header + sealed + self.secTrailer + sig.getData()
        return wire, sig.getData()

    def test_recv_header_signed_roundtrip(self):
        wire, sent_sig = self._server_send()
        off = len(self.header)
        auth_len = 16 + 8                              # signature + sec_trailer
        body = wire[off:]
        auth_data = body[-auth_len:]
        enc_stub = body[:-auth_len]
        sec_len = len(self.secTrailer)
        # recv path (the fix): decrypt the stub, rebuild the whole PDU, verify MAC
        handle = ARC4.new(self.sealKey).encrypt
        plain = handle(enc_stub)
        signedPDU = wire[:off] + plain + auth_data[:sec_len]
        sig = ntlm.SIGN(self.flags, self.signKey, signedPDU, self.seq, handle)
        self.assertEqual(plain, self.stub)
        self.assertEqual(sig.getData(), auth_data[sec_len:])
        self.assertEqual(auth_data[sec_len:], sent_sig)

    def test_old_stub_only_formula_fails(self):
        # The previous recv formula signed only the stub -> never matched.
        wire, sent_sig = self._server_send()
        off = len(self.header)
        auth_len = 16 + 8
        enc_stub = wire[off:][:-auth_len]
        handle = ARC4.new(self.sealKey).encrypt
        _plain, bad_sig = ntlm.SEAL(self.flags, self.signKey, self.sealKey,
                                    enc_stub, enc_stub, self.seq, handle)
        self.assertNotEqual(bad_sig.getData(), sent_sig)


if __name__ == "__main__":
    unittest.main()
