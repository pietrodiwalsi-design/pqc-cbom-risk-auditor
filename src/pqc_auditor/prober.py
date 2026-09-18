import socket
import ssl
import struct
import time
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

GROUP_X25519_MLKEM768 = 0x11ec
GROUP_X25519_KYBER768_DRAFT00 = 0x6399
GROUP_SECP256R1_MLKEM768 = 0x11ed
GROUP_X25519 = 0x001d
GROUP_SECP256R1 = 0x0017

# Short canonical names used for negotiated_group / client_offered_groups.
# (2026-09-18 review, Task 1) — classical groups previously had no name at
# all ("None (Classical fallback)"); every group the probe can recognise
# now has an explicit short name.
SHORT_GROUP_NAMES = {
    GROUP_X25519_MLKEM768: "X25519MLKEM768",
    GROUP_X25519_KYBER768_DRAFT00: "X25519Kyber768Draft00",
    GROUP_SECP256R1_MLKEM768: "SecP256r1MLKEM768",
    GROUP_X25519: "x25519",
    GROUP_SECP256R1: "secp256r1",
}
PQC_GROUP_IDS = {GROUP_X25519_MLKEM768, GROUP_X25519_KYBER768_DRAFT00, GROUP_SECP256R1_MLKEM768}

# TLS record content types (RFC 8446 §5.1)
_TLS_RECORD_ALERT = 21
_TLS_RECORD_HANDSHAKE = 22
# TLS handshake message types (RFC 8446 §4)
_TLS_HANDSHAKE_SERVER_HELLO = 2
# TLS extension types relevant to key-exchange determination
_EXT_PRE_SHARED_KEY = 0x0029
_EXT_KEY_SHARE = 0x0033


class TLSProber:
    """Raw-socket TLS 1.3 ClientHello prober for NIST FIPS 203 ML-KEM-768
    (post-quantum) key-share negotiation.

    IMPORTANT (2026-09-18 audit-evidence-quality review): this prober does
    NOT delegate the handshake to OpenSSL, the `ssl` module, or an OQS
    provider. It hand-crafts the raw TLS ClientHello bytes itself and reads
    the raw ServerHello bytes back. This means:
      - `probe_client_pqc_capable` reflects whether ML-KEM was included in
        the groups this probe's ClientHello construction offers (it always
        is, in this implementation) — NOT whether the local OpenSSL/oqs
        installation supports it, because no local TLS library is invoked.
      - `tls_library_version` reports the Python runtime's bundled OpenSSL
        version (`ssl.OPENSSL_VERSION`) purely for environment
        reproducibility in the audit trail. It is NOT the library that
        performed this handshake — no TLS library performed it.
    """

    # Schema/tool version for the evidence envelope. Bump SCHEMA_VERSION on
    # any breaking change to the response shape (see Task 2/3 below, which
    # are breaking: hndl_risk removed, negotiated_group/pqc_supported can
    # now be null, status field added).
    SCHEMA_VERSION = "2.0"
    TOOL_VERSION = "1.1.0"

    def _evidence_envelope(self) -> Dict[str, Any]:
        return {
            "schema_version": self.SCHEMA_VERSION,
            "tool_version": self.TOOL_VERSION,
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "tls_library_version": ssl.OPENSSL_VERSION,
        }

    def _build_client_hello(self, hostname: str) -> bytes:
        sni_data = struct.pack('>H', len(hostname)) + hostname.encode('utf-8')
        sni_ext = struct.pack('>HH', 0x0000, len(sni_data) + 3) + struct.pack('>HB', len(sni_data) + 1, 0) + sni_data
        supp_vers = struct.pack('>HHB', 0x002b, 3, 2) + struct.pack('>H', 0x0304)
        groups = [GROUP_X25519_MLKEM768, GROUP_X25519_KYBER768_DRAFT00, GROUP_SECP256R1_MLKEM768, GROUP_X25519, GROUP_SECP256R1]
        groups_data = struct.pack('>H', len(groups) * 2) + b''.join(struct.pack('>H', g) for g in groups)
        groups_ext = struct.pack('>HH', 0x000a, len(groups_data)) + groups_data
        sig_algs = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501]
        sig_data = struct.pack('>H', len(sig_algs) * 2) + b''.join(struct.pack('>H', s) for s in sig_algs)
        sig_ext = struct.pack('>HH', 0x000d, len(sig_data)) + sig_data
        ks_x25519 = struct.pack('>HH', GROUP_X25519, 32) + (b'\x01' * 32)
        ks_pqc_mlkem = struct.pack('>HH', GROUP_X25519_MLKEM768, 1216) + (b'\x02' * 1216)
        ks_pqc_kyber = struct.pack('>HH', GROUP_X25519_KYBER768_DRAFT00, 1216) + (b'\x03' * 1216)
        ks_entries = ks_pqc_mlkem + ks_pqc_kyber + ks_x25519
        ks_data = struct.pack('>H', len(ks_entries)) + ks_entries
        ks_ext = struct.pack('>HH', 0x0033, len(ks_data)) + ks_data
        extensions = sni_ext + supp_vers + groups_ext + sig_ext + ks_ext
        ciphers = [0x1301, 0x1302, 0x1303]
        ciphers_data = struct.pack('>H', len(ciphers) * 2) + b''.join(struct.pack('>H', c) for c in ciphers)
        ch_body = struct.pack('>H', 0x0303) + (b'\x55' * 32) + b'\x00' + ciphers_data + b'\x01\x00' + struct.pack('>H', len(extensions)) + extensions
        ch_msg = struct.pack('>B', 1) + struct.pack('>I', len(ch_body))[1:] + ch_body
        return struct.pack('>BHH', 22, 0x0301, len(ch_msg)) + ch_msg, groups

    def _parse_server_hello_or_alert(self, resp: bytes) -> Dict[str, Any]:
        """Parses a raw TLS record containing either a ServerHello handshake
        message or an Alert. Returns dict with keys: status ("ok" |
        "tls_alert" | "protocol_error"), error_detail, group_id (Optional[int]),
        is_psk_only (bool).

        FIX (2026-09-18 review, Task 1 + Task 2): previously the caller only
        scanned the raw response bytes for the two known PQC magic byte
        sequences and had NO way to determine which classical group was
        actually negotiated, nor to distinguish a TLS alert / malformed
        response from a genuine classical result. This performs a real,
        minimal ServerHello parse (RFC 8446 §4.1.3) to extract the
        `key_share` extension's negotiated group id, or detect a PSK-only
        resumption (`pre_shared_key` extension present, no `key_share`).
        """
        try:
            if len(resp) < 5:
                return {"status": "protocol_error",
                        "error_detail": f"response too short to contain a TLS record header ({len(resp)} bytes)",
                        "group_id": None, "is_psk_only": False}

            content_type = resp[0]

            if content_type == _TLS_RECORD_ALERT:
                if len(resp) >= 7:
                    level, description = resp[5], resp[6]
                    detail = f"TLS alert received: level={level} description_code={description}"
                else:
                    detail = "TLS alert record received (truncated, no alert body)"
                return {"status": "tls_alert", "error_detail": detail, "group_id": None, "is_psk_only": False}

            if content_type != _TLS_RECORD_HANDSHAKE:
                return {"status": "protocol_error",
                        "error_detail": f"unexpected TLS record content type {content_type} (expected Handshake=22 or Alert=21)",
                        "group_id": None, "is_psk_only": False}

            if len(resp) < 9:
                return {"status": "protocol_error",
                        "error_detail": "handshake record too short to contain a message header",
                        "group_id": None, "is_psk_only": False}

            hs_type = resp[5]
            if hs_type != _TLS_HANDSHAKE_SERVER_HELLO:
                return {"status": "protocol_error",
                        "error_detail": f"expected ServerHello (handshake type 2), got handshake type {hs_type}",
                        "group_id": None, "is_psk_only": False}

            # ServerHello body starts at offset 9 (5-byte record header + 4-byte
            # handshake header): legacy_version(2) + random(32) + session_id_len(1)
            # + session_id(var) + cipher_suite(2) + compression_method(1) +
            # extensions_length(2) + extensions(var).
            offset = 9 + 2 + 32
            if offset >= len(resp):
                return {"status": "protocol_error", "error_detail": "truncated ServerHello (missing session_id length)",
                        "group_id": None, "is_psk_only": False}
            session_id_len = resp[offset]
            offset += 1 + session_id_len
            offset += 2  # cipher_suite
            offset += 1  # legacy compression_method
            if offset + 2 > len(resp):
                return {"status": "protocol_error", "error_detail": "truncated ServerHello (missing extensions length)",
                        "group_id": None, "is_psk_only": False}
            ext_total_len = struct.unpack('>H', resp[offset:offset + 2])[0]
            offset += 2
            ext_end = min(offset + ext_total_len, len(resp))

            group_id: Optional[int] = None
            has_psk_ext = False
            while offset + 4 <= ext_end:
                ext_type = struct.unpack('>H', resp[offset:offset + 2])[0]
                ext_len = struct.unpack('>H', resp[offset + 2:offset + 4])[0]
                data_start = offset + 4
                data_end = data_start + ext_len
                if data_end > len(resp):
                    break  # truncated extension; stop, use what we parsed so far
                if ext_type == _EXT_KEY_SHARE and ext_len >= 2:
                    group_id = struct.unpack('>H', resp[data_start:data_start + 2])[0]
                elif ext_type == _EXT_PRE_SHARED_KEY:
                    has_psk_ext = True
                offset = data_end

            if group_id is None and not has_psk_ext:
                return {"status": "protocol_error",
                        "error_detail": "ServerHello contained neither a key_share nor a pre_shared_key extension",
                        "group_id": None, "is_psk_only": False}

            # PSK-DHE (both extensions present) still has a real key share;
            # only report psk_only when there is truly no key exchange.
            is_psk_only = has_psk_ext and group_id is None
            return {"status": "ok", "error_detail": None, "group_id": group_id, "is_psk_only": is_psk_only}
        except (struct.error, IndexError) as e:
            return {"status": "protocol_error", "error_detail": f"malformed TLS response: {e}",
                    "group_id": None, "is_psk_only": False}

    def _build_result(self, hostname: str, port: int, status: str, error_detail: Optional[str],
                       resolved_ip: Optional[str], client_offered_groups: List[str],
                       probe_client_pqc_capable: bool, start: float,
                       negotiated_group: Optional[str] = None, pqc_supported: Optional[bool] = None) -> Dict[str, Any]:
        duration = round((time.time() - start) * 1000, 2)
        return {
            "host": hostname,
            "port": port,
            "status": status,
            "error_detail": error_detail,
            "resolved_ip": resolved_ip,
            # FIX (Task 2): on any status != "ok" these MUST stay None. A
            # failed measurement is not a finding — never a fabricated
            # negative PQC result.
            "negotiated_group": negotiated_group,
            "pqc_supported": pqc_supported,
            "client_offered_groups": client_offered_groups,
            "probe_client_pqc_capable": probe_client_pqc_capable,
            "latency_ms": duration,
            **self._evidence_envelope(),
        }

    def probe_endpoint(self, hostname: str, port: int = 443, timeout: float = 5.0) -> Dict[str, Any]:
        start = time.time()
        raw_client_hello, groups = self._build_client_hello(hostname)
        # Task 3: report what this probe actually offered, regardless of outcome.
        client_offered_groups = [SHORT_GROUP_NAMES[g] for g in groups]
        probe_client_pqc_capable = any(g in PQC_GROUP_IDS for g in groups)

        resolved_ip: Optional[str] = None

        # --- Connect phase ---
        try:
            sock = socket.create_connection((hostname, port), timeout=timeout)
        except socket.gaierror as e:
            return self._build_result(hostname, port, "dns_error", str(e), None,
                                       client_offered_groups, probe_client_pqc_capable, start)
        except (socket.timeout, TimeoutError, ConnectionRefusedError, OSError) as e:
            # Task 2 allows exactly 5 status values; connection-refused and
            # network-unreachable are folded into connect_timeout — from an
            # audit-evidence perspective both mean "a TCP connection to the
            # endpoint could not be established", which is the meaning the
            # acceptance criteria (a closed port -> connect_timeout) require.
            return self._build_result(hostname, port, "connect_timeout", str(e), None,
                                       client_offered_groups, probe_client_pqc_capable, start)

        try:
            with sock:
                try:
                    resolved_ip = sock.getpeername()[0]
                except OSError:
                    resolved_ip = None
                try:
                    sock.sendall(raw_client_hello)
                    resp = sock.recv(65536)
                except (socket.timeout, TimeoutError) as e:
                    return self._build_result(hostname, port, "connect_timeout", str(e), resolved_ip,
                                               client_offered_groups, probe_client_pqc_capable, start)
                except OSError as e:
                    return self._build_result(hostname, port, "protocol_error", str(e), resolved_ip,
                                               client_offered_groups, probe_client_pqc_capable, start)

            if not resp:
                return self._build_result(hostname, port, "protocol_error",
                                           "connection closed with no data received", resolved_ip,
                                           client_offered_groups, probe_client_pqc_capable, start)

            parsed = self._parse_server_hello_or_alert(resp)
            if parsed["status"] != "ok":
                return self._build_result(hostname, port, parsed["status"], parsed["error_detail"], resolved_ip,
                                           client_offered_groups, probe_client_pqc_capable, start)

            group_id = parsed["group_id"]
            if parsed["is_psk_only"]:
                negotiated_group = "psk_only"
                pqc_supported = False
            else:
                negotiated_group = SHORT_GROUP_NAMES.get(group_id, f"unknown_group_0x{group_id:04x}")
                pqc_supported = group_id in PQC_GROUP_IDS

            return self._build_result(hostname, port, "ok", None, resolved_ip,
                                       client_offered_groups, probe_client_pqc_capable, start,
                                       negotiated_group=negotiated_group, pqc_supported=pqc_supported)
        except Exception as e:
            # Task 2, explicit rule: never let an exception fall through
            # into a negative/positive PQC result. Any unforeseen failure
            # becomes an explicit protocol_error with no risk verdict.
            return self._build_result(hostname, port, "protocol_error", f"unexpected error: {e}", resolved_ip,
                                       client_offered_groups, probe_client_pqc_capable, start)
