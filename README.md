# Hub di Hardening e Resilienza DoS HTTP/2 e Kernel Linux

[![Live Demo](https://img.shields.io/badge/Live%20Demo-GitHub%20Pages-5b3cf5.svg)](https://tavardt-italia.github.io/http2-kernel-dos-resilience-checker-it/)
[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![RFC 7540](https://img.shields.io/badge/RFC-7540-blue.svg)](https://datatracker.ietf.org/doc/html/rfc7540)
[![RFC 9113](https://img.shields.io/badge/RFC-9113-blue.svg)](https://datatracker.ietf.org/doc/html/rfc9113)

**Hub di Architettura Difensiva e Mitigazione contro DoS in HTTP/2 (Rapid Reset CVE-2023-44487) e Kernel Linux**

Sviluppato e gestito dalla divisione di ingegneria della sicurezza delle infrastrutture di **TAVARDT**.

***

## Dimostrazione Online & Hub di Architettura Difensiva

È possibile consultare le specifiche tecniche difensive, i test di diagnostica architetturale e i blueprint di mitigazione direttamente dal browser:

* **[Applicazione Web Ufficiale su GitHub Pages](https://tavardt-italia.github.io/http2-kernel-dos-resilience-checker-it/)**
* **Centro Strumenti TAVARDT**

> [!NOTE]
> **Ambito di Esecuzione Tecnica:** Questo hub web fornisce specifiche di architettura difensiva e blueprint di configurazione. L'ispezione attiva dello stato del kernel Linux e i controlli dello stack di rete richiedono privilegi di sistema (root) e devono essere eseguiti direttamente sull'host mediante l'utilità CLI ufficiale (`http2_kernel_dos_checker.py`). Le pagine web caricate nella sandbox del browser non possono esaminare i parametri interni del kernel.

***

## Blueprint Tecnici di Hardening

1. **sysctl-hardening.conf:** Parametri ottimizzati in `/proc/sys/net/ipv4` che mitigano i SYN flood, gli attacchi timestamp NoisyTCP e l'esaurimento dei socket orfani.
2. **nginx-http2-hardened.conf:** Configurazione di reverse proxy NGINX blindata che impone quote rigide di flussi concorrenti (`http2_max_concurrent_streams 64`) e limitazione severa dei frame RST_STREAM.
3. **nftables-dos-protection.conf:** Regole di filtraggio dei pacchetti di Livello 4 che scartano raffiche anomale TCP SYN e RST prima dell'allocazione dei socket nel kernel.
4. **docker-compose-hardened.yml:** Architettura di container isolati che applica limiti rigidi di risorse (memoria, CPU, ulimits) ai proxy web perimetrali.
5. **http2_kernel_dos_checker.py:** Utilità CLI locale deterministica eseguita con privilegi di sistema sul server per esaminare direttamente i parametri `/proc/sys` e convalidare la conformità RFC.

***

## Utilizzo dell'Utilità CLI Deterministica

Per eseguire l'ispezione deterministica direttamente sull'host del server Linux:

```bash
# 1. Scaricare lo script di audit dal repository ufficiale
curl -sO https://raw.githubusercontent.com/TAVARDT-Italia/http2-kernel-dos-resilience-checker-it/main/http2_kernel_dos_checker.py

# 2. Ispezionare i parametri locali del kernel Linux
sudo python3 http2_kernel_dos_checker.py -kernel

# 3. Esportare i risultati in formato JSON strutturato
sudo python3 http2_kernel_dos_checker.py -kernel -json
```

***

## Link Utili

* **Portale Aziendale:** https://ag.tavardt.com/it/
* **Suite di Diagnostica:** https://tools.tavardt.com/it/
* **Contatto Tecnico:** https://ag.tavardt.com/it/contatto/

***

© 2026 TAVARDT. Tutti i diritti riservati.
