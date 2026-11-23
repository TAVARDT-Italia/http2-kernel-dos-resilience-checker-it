# Audit di Resilienza HTTP/2 & Crash del Kernel Linux - TAVARDT Italia

> Audit di Resilienza contro NoisyTCP, Rapid Reset (CVE-2023-44487) e Hardening di Server Web

[![GitHub Pages](https://img.shields.io/badge/GitHub%20Pages-Active-brightgreen)](https://tavardt-italia.github.io/http2-kernel-dos-resilience-checker-it/)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Security: CIS Linux](https://img.shields.io/badge/Security-CIS%20Linux%20%7C%20RFC%209113-red.svg)](https://www.cisecurity.org/)

## Panoramica dell'Architettura e Resilienza HTTP/2 & Kernel Linux

La stabilità e la resilienza operativa delle infrastrutture web dipendono direttamente dall'armonia tra lo stack TCP del kernel Linux e i motori di multiplexing HTTP/2.

Due classi critiche di attacchi colpiscono i sistemi non protetti:
1. **Falla NoisyTCP nel Kernel Linux:** Pacchetti TCP anomali fuori ordine forzano un'allocazione incontrollata di memoria del kernel, mandando in crash Nginx, Apache e SSH senza autenticazione.
2. **Abuso di Rapid Reset in HTTP/2 (CVE-2023-44487):** Raffiche massive di richieste immediatamente cancellate con frame `RST_STREAM` esauriscono i descrittori di file e le risorse del server.

Questo repository fornisce un'applicazione web interattiva interamente eseguita nel browser e uno scanner CLI in Python di libreria standard per verificare sistemi locali e remoti.

## Applicazione Web Interattiva

Accedi allo strumento online e verifica il tuo server in tempo reale:

* [https://tavardt-italia.github.io/http2-kernel-dos-resilience-checker-it/](https://tavardt-italia.github.io/http2-kernel-dos-resilience-checker-it/)

L'applicazione valuta 5 fasi di sicurezza, calcola un indice di resilienza (0 a 100), evidenzia i rischi architetturali e produce configurazioni difensive pronte per la produzione.

## Utilizzo dello Scanner CLI (Python)

Il repository include lo script `http2_kernel_dos_checker.py`, sviluppato esclusivamente con la libreria standard di Python:

```bash
# Verificare i parametri locali del kernel Linux contro NoisyTCP
python3 http2_kernel_dos_checker.py --kernel

# Verificare un server remoto (negoziazione ALPN h2, TLS e banner)
python3 http2_kernel_dos_checker.py --host tuo-server.it --port 443

# Eseguire l'audit in formato JSON per pipeline CI/CD
python3 http2_kernel_dos_checker.py --host tuo-server.it --json
```

## Controlli Architetturali e Mitigazioni Difensive

* **Kernel Linux (/etc/sysctl.conf):** Configurazione di `net.ipv4.tcp_syncookies = 1`, disattivazione di `net.ipv4.tcp_timestamps = 0` per mitigare NoisyTCP, calibrazione dei buffer (`tcp_rmem`, `tcp_wmem`) e `somaxconn = 4096`.
* **Nginx (nginx.conf):** Soppressione delle firme (`server_tokens off`), limite dei flussi concorrenti (`http2_max_concurrent_streams 100`) e zone di limitazione (`limit_req_zone`) contro gli attacchi `RST_STREAM`.
* **Apache HTTP Server (httpd.conf):** Occultamento completo dei banner (`ServerTokens Prod`, `ServerSignature Off`), regolazione del multiplexing tramite `mod_http2` (`H2MaxSessionStreams 100`) e timeout con `mod_reqtimeout`.
* **Perimetro di Bordo:** Terminazione TLS gestita su Cloudflare WAF e mascheramento totale dell'IP di origine.

## Portali Ufficiali

* **Portale Aziendale TAVARDT Italia:** [https://ag.tavardt.com/it/](https://ag.tavardt.com/it/)
* **Servizi di Sicurezza Informatica:** [https://ag.tavardt.com/it/sicurezza-informatica/](https://ag.tavardt.com/it/sicurezza-informatica/)
* **Hub di Strumenti di Sicurezza:** [https://tools.tavardt.com/it/](https://tools.tavardt.com/it/)
* **Organizzazione GitHub:** [https://github.com/TAVARDT-Italia](https://github.com/TAVARDT-Italia)

## Licenza

Distribuito con licenza MIT. Per maggiori dettagli consultare il file `LICENSE`.
