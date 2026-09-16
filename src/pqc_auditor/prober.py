import socket
import struct
import time
from typing import Dict, Any, List

GROUP_X25519_MLKEM768 = 0x11ec
GROUP_X25519_KYBER768_DRAFT00 = 0x6399
GROUP_SECP256R1_MLKEM768 = 0x11ed
GROUP_X25519 = 0x001d
GROUP_SECP256R1 = 0x0017

GROUP_NAMES = {
    GROUP_X25519_MLKEM768: "X25519MLKEM768 (NIST FIPS 203 Standard)",
    GROUP_X25519_KYBER768_DRAFT00: "X25519Kyber768Draft00 (IETF Draft / Cloudflare)",
    GROUP_SECP256R1_MLKEM768: "SecP256r1MLKEM768 (NIST FIPS 203 P-256)",
    GROUP_X25519: "X25519 (Classical Curve25519 - No PQC)",
    GROUP_SECP256R1: "secp256r1 (Classical NIST P-256 - No PQC)"
}

class TLSProber:
    def probe_endpoint(self, hostname: str, port: int = 443, timeout: float = 5.0) -> Dict[str, Any]:
        start = time.time()
        try:
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
            raw_client_hello = struct.pack('>BHH', 22, 0x0301, len(ch_msg)) + ch_msg

            with socket.create_connection((hostname, port), timeout=timeout) as sock:
                sock.sendall(raw_client_hello)
                resp = sock.recv(4096)

            duration = round((time.time() - start) * 1000, 2)
            has_mlkem = (b'\x11\xec' in resp)
            has_kyber = (b'\x63\x99' in resp)
            is_pqc = has_mlkem or has_kyber

            selected_group = "None (Classical fallback)"
            if has_mlkem:
                selected_group = GROUP_NAMES[GROUP_X25519_MLKEM768]
            elif has_kyber:
                selected_group = GROUP_NAMES[GROUP_X25519_KYBER768_DRAFT00]

            return {
                "host": hostname,
                "port": port,
                "pqc_supported": is_pqc,
                "negotiated_group": selected_group,
                "hndl_risk": "LOW" if is_pqc else "HIGH",
                "latency_ms": duration
            }
        except Exception as e:
            return {"host": hostname, "port": port, "error": str(e), "hndl_risk": "UNKNOWN", "latency_ms": round((time.time() - start) * 1000, 2)}
