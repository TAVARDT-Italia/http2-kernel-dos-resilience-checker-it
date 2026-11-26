<p align="center">
  <a href="https://ag.tavardt.com/it/">
    <img src="https://ag.tavardt.com/img/tavardt-banner.png" alt="TAVARDT" width="1024" />
  </a>
</p>

# HTTP/2 & Linux Kernel DoS Resilience Checker

[![Live Demo](https://img.shields.io/badge/Live%20Demo-GitHub%20Pages-5b3cf5.svg)](https://tavardt-italia.github.io/http2-kernel-dos-resilience-checker-it/)
[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![RFC 7540](https://img.shields.io/badge/RFC-7540-blue.svg)](https://datatracker.ietf.org/doc/html/rfc7540)
[![RFC 9113](https://img.shields.io/badge/RFC-9113-blue.svg)](https://datatracker.ietf.org/doc/html/rfc9113)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

***

Auditor di sicurezza automatizzato per i parametri di rete del kernel Linux, negoziazione del protocollo HTTP/2 (ALPN) e resilienza contro attacchi Denial-of-Service, sviluppato da **TAVARDT**, in piena conformità con le Misure Minime di Sicurezza ICT di AgID, la Direttiva NIS2 e il GDPR.

I servizi web moderni affrontano costanti minacce di denegazione del servizio che prendono di mira i protocolli di rete fondamentali, come NoisyTCP e HTTP/2 Rapid Reset. Senza un'accurata ottimizzazione dei socket a livello di sistema operativo e una verifica rigorosa dei protocolli, i server di origine rischiano l'esaurimento dei thread di calcolo sotto carichi asimmetrici.

***

## Funzionalità Principali e Architettura Difensiva

* **Audit Deterministico dei Parametri del Kernel Linux**: Esamina le configurazioni in `/proc/sys/net/` a fronte di standard rigorosi per prevenire attacchi NoisyTCP, flood SYN e saturazione dei socket.
* **Verifica Remota del Protocollo HTTP/2**: Controlla la negoziazione ALPN su canale TLS per validare il supporto effettivo della multiplazione binaria `h2`.
* **Rilevamento di Esposizione di Banner Tecnici**: Individua la trasmissione non sicura di versioni software e framework all'interno degli header HTTP `Server` e `X-Powered-By`.
* **Zero Dipendenze Esterne**: Sviluppato interamente con i moduli della libreria standard di Python (`socket`, `ssl`, `json`, `os`, `sys`), offrendo massima rapidità senza componenti software aggiuntivi.
* **Automazione per Pipeline CI/CD**: Genera report strutturati in formato JSON tramite l'opzione `-json` per controlli continui all'interno dei processi di rilascio software.

***

## Vettori di Rischio e Impatto Operativo

Mantenere server di rete operativi con i parametri predefiniti del kernel Linux espone l'infrastruttura ad attacchi di saturazione delle risorse. Lo strumento analizza quattro vettori di rischio prioritari:

* **NoisyTCP e Avvelenamento dei Timestamp**: Manipolazione dei timestamp TCP per provocare il riordinamento anomalo dei pacchetti e sovraccaricare la CPU di rete.
* **Saturazione da SYN Flood ed Esaurimento Socket**: Blocco delle code di connessione in ingresso dovuto all'assenza di SYN cookie e a limiti di backlog inadeguati.
* **Degradazione di Protocollo e Mancata Negoziazione ALPN**: Impossibilità di concordare `h2`, con conseguente arretramento verso connessioni HTTP/1.1 meno efficienti.
* **Riconoscimento di Sistema tramite Header Informativi**: Diffusione di versioni dettagliate dei server web tramite header, semplificando la preparazione di attacchi mirati.

***

## Installazione ed Esecuzione CLI

Eseguite controlli locali sul kernel Linux o verifiche remote di protocollo impiegando comandi Python standard:

```bash
# Clonare il repository ufficiale
git clone https://github.com/TAVARDT-Italia/http2-kernel-dos-resilience-checker-it.git

# Accedere alla directory del progetto
cd http2-kernel-dos-resilience-checker-it

# Eseguire l'audit locale dei parametri di rete del kernel Linux
python http2_kernel_dos_checker.py -kernel

# Eseguire l'audit remoto su un endpoint per HTTP/2 e banner
python http2_kernel_dos_checker.py -host example.com -port 443

# Generare un report strutturato in JSON per pipeline CI/CD
python http2_kernel_dos_checker.py -host example.com -json
```

***

## Domande Tecniche Frequenti

### In che modo l'ottimizzazione dei parametri sysctl del kernel Linux contrasta gli attacchi NoisyTCP?

Disabilitare i timestamp TCP previene attacchi di previsione delle sequenze e il disordinamento forzato dei pacchetti che intasano le code dello stack di rete. Contemporaneamente, attivare i SYN cookie ed espandere le code di backlog garantisce la disponibilità delle connessioni durante attacchi di saturazione massiva.

### Per quale ragione la verifica della negoziazione ALPN è determinante per la sicurezza HTTP/2?

Il meccanismo ALPN assicura che client e server stabiliscano la multiplazione binaria su canale cifrato TLS senza degradare verso comunicazioni in chiaro. Verificare la selezione di h2 conferma che le impostazioni moderne di regolazione del traffico e controllo dei flussi siano operative fin dall'avvio della sessione.

### Perché l'esposizione degli header Server e X-Powered-By accresce la vulnerabilità a interruzioni di servizio?

Rivelare le versioni software esatte consente ad attori malevoli di impiegare exploit mirati contro difetti specifici di gestione dei buffer o dei protocolli. Rimuovere tali informazioni priva gli strumenti di scansione automatica dei dettagli necessari per pianificare attacchi diretti al sistema.

### Qual è la differenza sul piano operativo tra l'audit locale del kernel e il controllo remoto di rete?

L'audit locale ispeziona i parametri sysctl direttamente nel file system proc per verificare la configurazione difensiva del sistema operativo ospitante. Il controllo remoto analizza invece l'handshake TLS, il supporto ALPN e la presenza di banner informativi attraverso la rete senza richiedere privilegi amministrativi sull'host.

### Lo strumento di audit può essere integrato in pipeline automatizzate di integrazione continua CI/CD?

Il comando CLI fornisce output strutturati mediante l'opzione -json, consentendo ai flussi di automazione di verificare programmaticamente la rispondenza ai parametri di sicurezza. I team DevOps possono analizzare tali dati per impedire il rilascio in produzione di macchine che non rispettino i livelli minimi di conformità stabiliti.

***

## Link Utili

* **Portale Aziendale:** https://ag.tavardt.com/it/
* **Suite di Diagnostica:** https://tools.tavardt.com/it/
* **Contatto Tecnico:** https://ag.tavardt.com/it/contatto/

***

### Licenza
Distribuito sotto la Licenza MIT. Consultare il file [LICENSE](LICENSE) per tutti i dettagli.

***

© 2026 TAVARDT. Tutti i diritti riservati.
