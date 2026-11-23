# Hub di Hardening e Resilienza DoS HTTP/2 e Kernel Linux

Specifica tecnica aziendale di ingegneria difensiva e blueprint di infrastruttura per mitigare i vettori di saturazione HTTP/2 Rapid Reset (CVE-2023-44487) e NoisyTCP, hardening del kernel Linux (sysctl) e verifica CLI deterministica locale.

## Ambito Tecnico del Repository

Questo repository fornisce modelli di hardening testati in produzione e strumenti CLI deterministici:

1. **sysctl-hardening.conf:** Parametri ottimizzati in `/proc/sys/net/ipv4` che mitigano i SYN flood, gli attacchi timestamp NoisyTCP e l'esaurimento dei socket orfani.
2. **nginx-http2-hardened.conf:** Configurazione di reverse proxy NGINX blindata che impone quote rigide di flussi concorrenti (`http2_max_concurrent_streams 64`) e limitazione severa dei frame RST_STREAM.
3. **nftables-dos-protection.conf:** Regole di filtraggio dei pacchetti di Livello 4 che scartano raffiche anomale TCP SYN e RST prima dell'allocazione dei socket nel kernel.
4. **docker-compose-hardened.yml:** Architettura di container isolati che applica limiti rigidi di risorse (memoria, CPU, ulimits) ai proxy web perimetrali.
5. **http2_kernel_dos_checker.py:** Utilita CLI locale deterministica eseguita con privilegi di sistema sul server per esaminare direttamente i parametri `/proc/sys` e convalidare la conformita RFC.

> [!NOTE]
> L'ispezione attiva dello stato del kernel Linux e dei parametri di rete richiede privilegi di sistema e deve essere eseguita direttamente sul server host mediante l'utilita CLI in Python. Le pagine web caricate nella sandbox del browser non possono esaminare i parametri del kernel host.

## Utilizzo dell'Utilita CLI

Eseguire lo script di audit deterministico direttamente sull'host del server:

```bash
# 1. Scaricare lo script di audit
curl -sO https://raw.githubusercontent.com/TAVARDT-Italia/http2-kernel-dos-resilience-checker-it/main/http2_kernel_dos_checker.py

# 2. Ispezionare i parametri locali del kernel Linux
sudo python3 http2_kernel_dos_checker.py -kernel

# 3. Esportare i risultati in formato JSON
sudo python3 http2_kernel_dos_checker.py -kernel -json
```

## Governance e Sovranita

* **Organizzazione:** TAVARDT-Italia
* **Giurisdizione:** Italia
* **Conformita agli Standard:** RFC 7540, RFC 9113, CVE-2023-44487, Architettura Zero Trust

Sviluppato dalla Divisione Cybersecurity & Ingegneria delle Infrastrutture di **TAVARDT Italia**. Tutti i diritti riservati.
