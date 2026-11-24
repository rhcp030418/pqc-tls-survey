"""Collect TLS observations with OpenSSL; Python standard library only.

No active vulnerability scan or HTTP request. Each listed domain gets one
certificate-verified TCP/TLS handshake. Raw bytes are saved before parsing.
"""
import argparse
import csv
import hashlib
import json
import platform
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path

VERSION = "1.0.1"
GROUPS = "X25519MLKEM768:X25519:P-256:P-384"
KST = timezone(timedelta(hours=9))
PQC_GROUPS = {
    "X25519MLKEM768": "X25519 + ML-KEM-768",
    "SecP256r1MLKEM768": "P-256 + ML-KEM-768",
    "SecP384r1MLKEM1024": "P-384 + ML-KEM-1024",
    "MLKEM512": "ML-KEM-512", "MLKEM768": "ML-KEM-768",
    "MLKEM1024": "ML-KEM-1024",
}
CLASSICAL = {"X25519", "X448", "secp256r1", "secp384r1", "secp521r1"}
ALIASES = {"prime256v1": "secp256r1", "P-256": "secp256r1", "P-384": "secp384r1", "x25519": "X25519", "x448": "X448"}

def now():
    return datetime.now(KST).isoformat(timespec="milliseconds")

def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def save_json(path, value):
    Path(path).write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")

def run(cmd, timeout=25, data=b""):
    try:
        p = subprocess.run(cmd, input=data, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, timeout=timeout, check=False)
        return p.stdout, p.returncode, False
    except subprocess.TimeoutExpired as e:
        return e.stdout or b"", None, True

def first(pattern, text, default=""):
    m = re.search(pattern, text, re.M)
    return m.group(1).strip() if m else default

def parse_observation(tls, cert, cipher_catalog, returncode=0, timed_out=False):
    r = {}
    # The New, SSLv3 label can be a cipher's historical version. Never use it.
    r["protocol"] = first(r"^\s*Protocol\s*:\s*(\S+)", tls)
    r["cipher"] = first(r"^New,.*?Cipher is (\S+)", tls) or first(r"^\s*Cipher\s*:\s*(\S+)", tls)
    r["remote_ip"] = first(r"^Connecting to (\S+)", tls)
    r["issuer_dn"] = first(r"^\s*Issuer:\s*(.+)", cert)
    r["issuer_cn"] = first(r"(?:^|,\s*)CN\s*=\s*([^,]+)", r["issuer_dn"])
    r["public_key_algorithm"] = first(r"Public Key Algorithm:\s*(.+)", cert)
    r["public_key_bits"] = int(first(r"Public-Key:\s*\((\d+) bit\)", cert, "0")) or None
    r["public_key_curve"] = first(r"ASN1 OID:\s*(\S+)", cert)
    r["certificate_signature"] = first(r"Signature Algorithm:\s*(\S+)", cert)
    r["certificate_sha256"] = first(r"(?i)^sha256 Fingerprint=(.+)", cert)
    r["peer_signature"] = first(r"^Peer signature type:\s*(.+)", tls)
    r["verify_code"] = first(r"^\s*Verify return code:\s*(.+)", tls)
    r["certificate_pqc"] = "확인 불가"
    if r["certificate_signature"] in {"sha256WithRSAEncryption", "sha384WithRSAEncryption", "sha512WithRSAEncryption", "ecdsa-with-SHA256", "ecdsa-with-SHA384", "ecdsa-with-SHA512", "rsassaPss", "ED25519", "ED448"}:
        r["certificate_pqc"] = "관측 리프 인증서 서명에 PQC 미사용"
    group = first(r"^Negotiated TLS1\.3 group:\s*(\S+)", tls)
    if not group:
        temp = first(r"^(?:Peer|Server) Temp Key:\s*(.+)", tls)
        parts = [p.strip() for p in temp.split(",")]
        group = parts[1] if len(parts) > 1 and parts[0] == "ECDH" else parts[0]
    r["group_raw"] = group
    group = ALIASES.get(group, group)
    r["group"] = group
    r["key_exchange"] = "확인 불가"
    r["pqc_status"] = "확인 불가"
    r["reason"] = ""
    valid = (returncode == 0 and not timed_out and r["verify_code"] == "0 (ok)"
             and "Verification: OK" in tls and r["protocol"] in {"TLSv1.2", "TLSv1.3"}
             and bool(r["cipher"]) and bool(r["certificate_sha256"]))
    r["handshake_verified"] = valid
    if not valid:
        r["reason"] = "시간 초과" if timed_out else "검증된 핸드셰이크 또는 필수 증거 불충분"
        return r
    if group in PQC_GROUPS and r["protocol"] == "TLSv1.3":
        r["key_exchange"] = PQC_GROUPS[group]
        r["pqc_status"] = "적용 확인"
        r["reason"] = "완료된 TLS 1.3 연결의 실제 협상 그룹에 ML-KEM 포함"
    elif group in CLASSICAL or re.fullmatch(r"ffdhe(?:2048|3072|4096|6144|8192)", group):
        r["key_exchange"] = "DHE" if group.startswith("ffdhe") else "ECDHE"
        r["pqc_status"] = "해당 연결에서 PQC 미사용"
        r["reason"] = "관측 연결에서 고전 키 교환 그룹 협상"
    elif not group and r["protocol"] == "TLSv1.2" and cipher_catalog.get(r["cipher"], {}).get("kx") == "RSA":
        r["group"] = "해당 없음 (정적 RSA)"
        r["key_exchange"] = "RSA"
        r["pqc_status"] = "해당 연결에서 PQC 미사용"
        r["reason"] = "TLS 1.2 협상 스위트의 OpenSSL Kx=RSA; 명명 그룹 없음"
    else:
        r["reason"] = "그룹 누락 또는 미등록 그룹으로 자동 판정 보류"
    return r

def catalog_from(text):
    catalog = {}
    for line in text.splitlines():
        m = re.match(r"(\S+)\s+-\s+(\S+)\s+\S+\s+Kx=(\S+)", line)
        if m:
            catalog[m[2]] = {"iana": m[1], "kx": m[3], "evidence": line}
    return catalog

def collect(args):
    out = Path(args.out).resolve()
    if out.exists() and any(out.iterdir()):
        raise ValueError("출력 폴더가 비어 있지 않습니다. 원본 보존을 위해 새 폴더를 지정하세요.")
    out.mkdir(parents=True, exist_ok=True)
    exe = shutil.which(args.openssl)
    if not exe:
        raise ValueError("OpenSSL 실행 파일을 찾을 수 없습니다.")
    cafile = Path(args.cafile).resolve()
    if not cafile.is_file():
        raise ValueError("CA 파일이 없습니다.")
    with open(args.sites, encoding="utf-8-sig", newline="") as f:
        sites = list(csv.DictReader(f))
    domains = [s["domain"] for s in sites]
    if len(domains) != len(set(domains)) or not domains:
        raise ValueError("도메인은 중복 없이 한 개 이상 필요합니다.")
    if any(not re.fullmatch(r"(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}", d) for d in domains):
        raise ValueError("유효한 ASCII DNS 도메인만 허용합니다.")
    meta = {"program_version": VERSION, "started_at": now(), "python": sys.version,
            "platform": platform.platform(), "openssl_path": exe,
            "openssl_sha256": sha256(exe), "ca_sha256": sha256(cafile),
            "ca_file": str(cafile), "sites_sha256": sha256(args.sites),
            "groups_offered": args.groups, "ipv4": True, "port": 443,
            "timeout_seconds": args.timeout, "forced_tls13": args.tls13,
            "http_requests": 0, "alpn": "미설정",
            "retry": 0, "session_resumption": False, "source_sha256": sha256(__file__)}
    for name, options in [("openssl_version", ["version", "-a"]), ("openssl_groups", ["list", "-tls-groups"]), ("cipher_catalog", ["ciphers", "-stdname", "-v", "ALL"])]:
        raw, code, timeout = run([exe] + options)
        (out / (name + ".txt")).write_bytes(raw)
        if code != 0 or timeout:
            raise ValueError("OpenSSL 환경 조회 실패: " + name)
    catalog = catalog_from((out / "cipher_catalog.txt").read_text())
    rows = []
    for site in sites:
        domain = site["domain"]
        prefix = out / domain
        cmd = [exe, "s_client", "-4", "-connect", domain + ":443", "-servername", domain,
               "-verify_hostname", domain, "-verify_return_error", "-CAfile", str(cafile),
               "-groups", args.groups, "-showcerts"]
        if args.tls13:
            cmd.append("-tls1_3")
        started = now()
        raw, code, timed_out = run(cmd, args.timeout)
        tls_path = Path(str(prefix) + ".tls.txt")
        tls_path.write_bytes(raw)
        tls = raw.decode("utf-8", errors="replace")
        pem_match = re.search(rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", raw, re.S)
        cert_raw = b""
        cert_cmd = []
        cert_code = None
        if pem_match:
            pem_path = Path(str(prefix) + ".leaf.pem")
            pem_path.write_bytes(pem_match[0] + b"\n")
            cert_cmd = [exe, "x509", "-in", str(pem_path), "-noout", "-text", "-fingerprint", "-sha256"]
            cert_raw, cert_code, _ = run(cert_cmd, args.timeout)
        cert_path = Path(str(prefix) + ".cert.txt")
        cert_path.write_bytes(cert_raw)
        row = {**site, "started_at": started, "ended_at": now(),
               **parse_observation(tls, cert_raw.decode("utf-8", errors="replace"), catalog, code, timed_out),
               "returncode": code, "timed_out": timed_out,
               "tls_log": tls_path.name, "cert_log": cert_path.name,
               "tls_sha256": sha256(tls_path), "cert_log_sha256": sha256(cert_path)}
        save_json(str(prefix) + ".meta.json", {**row, "command": cmd, "certificate_command": cert_cmd, "certificate_returncode": cert_code})
        rows.append(row)
        save_json(out / "results.json", rows)  # checkpoint after each site
        print(domain, row["protocol"], row["group"], row["pqc_status"], flush=True)
    with (out / "results.csv").open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    meta["ended_at"] = now()
    save_json(out / "run_metadata.json", meta)
    return rows

def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--sites", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--cafile", required=True)
    p.add_argument("--openssl", default="openssl")
    p.add_argument("--groups", default=GROUPS)
    p.add_argument("--timeout", type=float, default=25)
    p.add_argument("--tls13", action="store_true", help="보충 실험용 TLS 1.3 강제")
    args = p.parse_args()
    if args.timeout <= 0:
        p.error("timeout은 양수여야 합니다")
    collect(args)

if __name__ == "__main__":
    main()
