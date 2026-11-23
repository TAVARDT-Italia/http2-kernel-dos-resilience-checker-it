#!/usr/bin/env python3
"""
TAVARDT HTTP/2 & Linux Kernel DoS Resilience Checker
Auditor di Resilienza contro NoisyTCP, Rapid Reset e Crash dei Server Web
TAVARDT Italia
"""

import sys
import os
import json
import socket
import ssl
import argparse
from typing import Dict, Any, List

VERSION = "1.0.0"

RECOMMENDED_SYSCTL = {
    "net.ipv4.tcp_syncookies": {"expected": "1", "weight": 20, "desc": "Protezione contro SYN Flood e saturazione delle connessioni"},
    "net.ipv4.tcp_timestamps": {"expected": "0", "weight": 20, "desc": "Mitigazione dell'avvelenamento e riordinamento NoisyTCP"},
    "net.ipv4.tcp_sack": {"expected": "1", "weight": 15, "desc": "Riconoscimento selettivo dei pacchetti TCP (SACK)"},
    "net.ipv4.tcp_fin_timeout": {"expected": "15", "weight": 15, "desc": "Rilascio rapido dei socket in stato FIN-WAIT"},
    "net.ipv4.tcp_max_syn_backlog": {"expected": "8192", "weight": 15, "desc": "Coda estesa per richieste di handshake in sospeso"},
    "net.core.somaxconn": {"expected": "4096", "weight": 15, "desc": "Limite del backlog delle connessioni socket del sistema"}
}

def audit_local_kernel() -> Dict[str, Any]:
    """Verifica i parametri di rete del kernel Linux locale contro la vulnerabilità NoisyTCP."""
    results = {
        "platform": sys.platform,
        "is_linux": sys.platform.startswith("linux"),
        "checks": [],
        "score": 100,
        "critical_alerts": []
    }

    if not results["is_linux"]:
        results["warning"] = "Audit del kernel applicabile nativamente su host Linux. Su altri sistemi operativi, utilizzare l'audit remoto via rete."
        return results

    total_weight = sum(v["weight"] for v in RECOMMENDED_SYSCTL.values())
    accumulated_score = 0

    for param, meta in RECOMMENDED_SYSCTL.items():
        proc_path = os.path.join("/proc/sys", param.replace(".", "/"))
        current_val = None
        if os.path.exists(proc_path):
            try:
                with open(proc_path, "r", encoding="utf-8") as f:
                    current_val = f.read().strip()
            except Exception:
                pass

        conforming = (current_val == meta["expected"])
        if conforming:
            accumulated_score += meta["weight"]
        else:
            results["critical_alerts"].append({
                "param": param,
                "current": current_val or "non_configurato",
                "recommended": meta["expected"],
                "desc": meta["desc"]
            })

        results["checks"].append({
            "param": param,
            "current": current_val or "non disponibile",
            "recommended": meta["expected"],
            "status": "CONFORME" if conforming else "VULNERABILE",
            "desc": meta["desc"]
        })

    results["score"] = round((accumulated_score / total_weight) * 100)
    return results

def audit_remote_host(host: str, port: int = 443, timeout: int = 5) -> Dict[str, Any]:
    """Verifica un endpoint remoto valutando la negoziazione HTTP/2, TLS e la fuga di versione."""
    report = {
        "target": f"{host}:{port}",
        "http2_supported": False,
        "tls_version": None,
        "alpn_negotiated": None,
        "server_banner": None,
        "banner_leaked": False,
        "score": 100,
        "findings": []
    }

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        ctx.set_alpn_protocols(["h2", "http/1.1"])
    except Exception:
        pass

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                report["tls_version"] = ssock.version()
                alpn = ssock.selected_alpn_protocol()
                report["alpn_negotiated"] = alpn
                report["http2_supported"] = (alpn == "h2")
    except Exception as e:
        report["connection_error"] = str(e)
        report["score"] = 30
        report["findings"].append(f"Errore di connessione TLS con {host}:{port}: {e}")
        return report

    req = f"HEAD / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: TAVARDT-Security-Auditor/1.0\r\nConnection: close\r\n\r\n"
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                ssock.sendall(req.encode())
                raw_resp = ssock.recv(4096).decode("utf-8", errors="ignore")
                for line in raw_resp.split("\r\n"):
                    if line.lower().startswith("server:"):
                        report["server_banner"] = line.split(":", 1)[1].strip()
                        report["banner_leaked"] = True
                    if line.lower().startswith("x-powered-by:"):
                        report["x_powered_by"] = line.split(":", 1)[1].strip()
                        report["banner_leaked"] = True
    except Exception:
        pass

    deductions = 0
    if not report["http2_supported"]:
        deductions += 40
        report["findings"].append("ALPN h2 non negoziato: server privo di multiplexing moderno o con h2c in chiaro.")
    if report["banner_leaked"]:
        deductions += 30
        report["findings"].append(f"Fuga attiva della versione del software nel banner: '{report.get('server_banner')}'")

    report["score"] = max(10, 100 - deductions)
    return report

def main():
    parser = argparse.ArgumentParser(
        description="TAVARDT Italia Auditor di Resilienza HTTP/2 & NoisyTCP Linux Kernel"
    )
    parser.add_argument("--host", help="Host remoto per audit di negoziazione HTTP/2 e banner", default=None)
    parser.add_argument("--port", help="Porta remota (predefinita: 443)", type=int, default=443)
    parser.add_argument("--kernel", action="store_true", help="Esegui audit locale dei parametri di rete Linux")
    parser.add_argument("--json", action="store_true", help="Generare output esclusivamente in formato JSON")

    args = parser.parse_args()

    results = {
        "version": VERSION,
        "auditor": "TAVARDT Italia",
        "documentation": "https://ag.tavardt.com/it/sicurezza-informatica/",
        "web_tool": "https://tavardt-italia.github.io/http2-kernel-dos-resilience-checker-it/"
    }

    if args.kernel or (not args.host and not args.kernel):
        results["kernel_audit"] = audit_local_kernel()

    if args.host:
        results["remote_audit"] = audit_remote_host(args.host, args.port)

    if args.json:
        print(json.dumps(results, indent=2, ensure_ascii=False))
        return

    print("================================================================================")
    print("      TAVARDT ITALIA : AUDITOR DI RESILIENZA HTTP/2 E CRASH DEL KERNEL LINUX           ")
    print("================================================================================")
    print(f"Versione: {VERSION} | Giurisdizione: Italia | Portale: https://ag.tavardt.com/it/sicurezza-informatica/")
    print("--------------------------------------------------------------------------------\n")

    if "kernel_audit" in results:
        ka = results["kernel_audit"]
        print(f"[*] AUDIT DEL KERNEL LINUX (Mitigazione NoisyTCP) | Score: {ka['score']}/100")
        if not ka["is_linux"]:
            print(f"    [AVVISO] {ka.get('warning')}")
        else:
            for c in ka["checks"]:
                tag = "[OK]        " if c["status"] == "CONFORME" else "[VULNERABILE]"
                print(f"    {tag} {c['param']}: attuale={c['current']} | raccomandato={c['recommended']}")
        print()

    if "remote_audit" in results:
        ra = results["remote_audit"]
        print(f"[*] AUDIT REMOTO DI PROTOCOLLO: {ra['target']} | Score: {ra['score']}/100")
        print(f"    HTTP/2 Supportato (ALPN): 'SÌ' if ra['http2_supported'] else 'NO'")
        print(f"    Versione TLS: {ra['tls_version'] or 'Sconosciuta'}")
        print(f"    Banner Server Esposto: 'SÌ (' + str(ra['server_banner']) + ')' if ra['banner_leaked'] else 'NO (Protetto)'")
        if ra["findings"]:
            print("    Segnalazioni di Rischio Identificate:")
            for f in ra["findings"]:
                print(f"      * {f}")
        print()

    print("Per supporto tecnico e blindatura perimetrale:")
    print(f"TAVARDT Italia: https://ag.tavardt.com/it/sicurezza-informatica/")

if __name__ == "__main__":
    main()
