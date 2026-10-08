# Slow-and-low-ngap-attack
Repository ufficiale contenente il codice sorgente, gli script di simulazione e la contromisura sviluppati nell'ambito della Tesi di Laurea:
> **"Sistemi di Telecomunicazioni Satellitari 5G Resilienti: Analisi Comparativa tra Reti Terrestri e Non Terrestri"**
> *Candidato: Francesco Labate*

## Contenuto del Repository
- `ngap.py`: Modulo per la costruzione e la codifica/decodifica delle PDU NGAP (es. *Handover Required*, *NGSetupRequest*).
- `03_ngap_handover_craft.py`: Modulo wrapper per la composizione rapida dei pacchetti NGAP, impiegato come astrazione di codifica per gli script di testbed e di attacco.
- `gnb_finto.py`: Implementazione del gNodeB fittizio e gestione delle associazioni SCTP verso l'AMF.
- `attacker.py`: Logica di iniezione reattiva *Slow-and-Low* e sniffing in tempo reale del traffico N2.
- `thesis_saturation.sh`: Orchestratore per l'esecuzione automatizzata dei test, la generazione di handover legittimi e il monitoraggio delle risorse AMF.
- `wg_n2.sh`: Script di orchestrazione della contromisura architetturale. Gestisce la creazione del tunnel WireGuard (`wgcore`/`wgran`), il partizionamento tramite Network Namespace (`netns`), il re-binding dell'AMF, le regole firewalling `iptables` su SCTP
- `wg_ngsetup_probe.py`: Sonda di verifica della raggiungibilità e dell'accessibilità dell'interfaccia N2; esegue test di connessione diretta e verifica l'efficacia del firewall e del tunnel prima e dopo l'attivazione di WireGuard.
