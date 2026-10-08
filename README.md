# Slow-and-low-ngap-attack
Repository ufficiale contenente il codice sorgente, gli script di simulazione e la contromisura sviluppati nell'ambito della Tesi di Laurea:
> **"Sistemi di Telecomunicazioni Satellitari 5G Resilienti: Analisi Comparativa tra Reti Terrestri e Non Terrestri"**
> *Candidato: Francesco Labate*

## Contenuto del Repository
- `ngap.py`: Modulo per la costruzione e la codifica/decodifica delle PDU NGAP (es. *Handover Required*, *NGSetupRequest*).
- `gnb_finto.py`: Implementazione del gNodeB fittizio e gestione delle associazioni SCTP verso l'AMF.
- `attacker.py`: Logica di iniezione reattiva *Slow-and-Low* e sniffing in tempo reale del traffico N2.
- `thesis_saturation.sh`: Orchestratore per l'esecuzione automatizzata dei test, la generazione di handover legittimi e il monitoraggio delle risorse AMF.
- Configurazione WireGuard per l'isolamento del canale di segnalazione N2.
