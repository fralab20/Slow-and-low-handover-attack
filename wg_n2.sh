#!/usr/bin/env bash
set -uo pipefail

SD="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$SD/../.." && pwd)"
AMF_YAML="$REPO/config/open5gs/amf.yaml"
LAUNCH="$REPO/scripts/launch/01_start_core.sh"
DIR=/etc/wireguard/n2demo
NS=ran
IF_CORE=wgcore
IF_RAN=wgran
IP_CORE=10.9.0.1
IP_RAN=10.9.0.2
PORT=51820
FW='! -i wgcore -p sctp -m sctp --dport 38412 -m comment --comment wgn2demo -j DROP'

usage(){
  echo "uso: $0 tunnel|tunnel-down|protect|demo|capture|down"
}

need_root(){ [ "$(id -u)" -eq 0 ] || { echo "[!] esegui con sudo"; exit 1; }; }

gen_keys(){
  mkdir -p "$DIR"; chmod 700 "$DIR"
  [ -f "$DIR/core.key" ] || { wg genkey > "$DIR/core.key"; wg pubkey < "$DIR/core.key" > "$DIR/core.pub"; }
  [ -f "$DIR/ran.key" ]  || { wg genkey > "$DIR/ran.key";  wg pubkey < "$DIR/ran.key"  > "$DIR/ran.pub"; }
  chmod 600 "$DIR"/*.key
}

tunnel_down(){
  ip netns del "$NS" 2>/dev/null || true
  ip link del "$IF_CORE" 2>/dev/null || true
}

tunnel(){
  need_root
  gen_keys
  local CORE_PUB RAN_PUB
  CORE_PUB=$(cat "$DIR/core.pub"); RAN_PUB=$(cat "$DIR/ran.pub")

  echo "[*] pulizia eventuale stato precedente..."
  tunnel_down

  echo "[*] creo il netns '$NS'..."
  ip netns add "$NS"
  ip -n "$NS" link set lo up

  echo "[*] interfaccia lato CORE ($IF_CORE = $IP_CORE) sul host..."
  ip link add "$IF_CORE" type wireguard
  wg set "$IF_CORE" private-key "$DIR/core.key" listen-port "$PORT" \
     peer "$RAN_PUB" allowed-ips "$IP_RAN/32"
  ip addr add "$IP_CORE/24" dev "$IF_CORE"
  ip link set "$IF_CORE" up

  echo "[*] interfaccia lato RAN ($IF_RAN = $IP_RAN): creata sul host, poi spostata in '$NS'"
  echo "    (il trasporto UDP resta sul host -> endpoint 127.0.0.1:$PORT raggiunge $IF_CORE)"
  ip link add "$IF_RAN" type wireguard
  wg set "$IF_RAN" private-key "$DIR/ran.key" \
     peer "$CORE_PUB" endpoint 127.0.0.1:"$PORT" allowed-ips "$IP_CORE/32" persistent-keepalive 15
  ip link set "$IF_RAN" netns "$NS"
  ip -n "$NS" addr add "$IP_RAN/24" dev "$IF_RAN"
  ip -n "$NS" link set "$IF_RAN" up

  echo "[*] attendo l'handshake..."
  sleep 2
  echo "=================================================================="
  echo "=== wg show $IF_CORE (deve comparire 'latest handshake') ==="
  wg show "$IF_CORE"
  echo "=== ping dal netns '$NS' -> lato CORE $IP_CORE (ATTRAVERSO il tunnel) ==="
  if ip netns exec "$NS" ping -c 3 -W 2 "$IP_CORE"; then
    echo "=================================================================="
    echo "[V] TUNNEL OK: i due estremi si parlano cifrati. Chiavi in $DIR/"
    echo "    Prossimo passo: ./wg_n2.sh protect (sposta N2 dietro il tunnel)."
  else
    echo "[!] ping fallito: il tunnel non e' salito. Controlla 'wg show'."
    exit 1
  fi
}

restart_core(){
  pkill -f 'open5gs-' 2>/dev/null || true; sleep 2
  setsid bash "$LAUNCH" >/tmp/core_wg.out 2>&1 < /dev/null &
  local i
  for i in $(seq 1 25); do ss -lnA sctp 2>/dev/null | grep -q ':38412' && return 0; sleep 1; done
  return 1
}

protect(){
  need_root
  ip link show "$IF_CORE" >/dev/null 2>&1 || { echo "[!] tunnel assente: esegui prima './wg_n2.sh tunnel'"; exit 1; }
  echo "[*] sposto il bind di N2 dell'AMF: 0.0.0.0 -> $IP_CORE (backup .n2bak)"
  [ -f "$AMF_YAML.n2bak" ] || cp "$AMF_YAML" "$AMF_YAML.n2bak"
  sed -i '/ngap:/,/port: 38412/ s/address: 0\.0\.0\.0/address: '"$IP_CORE"'/' "$AMF_YAML"
  grep -A3 'ngap:' "$AMF_YAML" | sed 's/^/    /'
  echo "[*] riavvio il core..."
  restart_core || { echo "[!] AMF non e' tornato in ascolto"; exit 1; }
  echo "[*] AMF in ascolto (Local Address): $(ss -lnA sctp | awk '/38412/{print $4}' | head -1)"
  echo "[*] firewall: SCTP 38412 accettato SOLO da $IF_CORE (il resto DROP)"
  eval iptables -D INPUT $FW 2>/dev/null || true
  eval iptables -I INPUT $FW
  echo "[V] N2 PROTETTO. Ora: sudo ./wg_n2.sh demo"
}

demo(){
  need_root
  local USER_SITE; USER_SITE=$(ls -d /home/*/.local/lib/python3*/site-packages 2>/dev/null | head -1)
  echo "=================================================================="
  echo " DEMO CONTROMISURA — N2 dietro WireGuard"
  echo "=================================================================="
  echo "(1) gNB LEGITTIMO — NGSetup dal netns '$NS', ATTRAVERSO il tunnel (ha la chiave):"
  ip netns exec "$NS" env PYTHONPATH="$USER_SITE" python3 "$SD/wg_ngsetup_probe.py" "$IP_CORE"
  echo
  echo "(2) ATTACCANTE sul HOST — gateway compromesso, NESSUNA chiave WireGuard:"
  echo "    a) verso l'IP del tunnel $IP_CORE (interfaccia locale, ma il firewall blocca):"
  env PYTHONPATH="$USER_SITE" python3 "$SD/wg_ngsetup_probe.py" "$IP_CORE"
  echo "    b) verso 127.0.0.1 (dove l'attacco puntava prima della contromisura):"
  env PYTHONPATH="$USER_SITE" python3 "$SD/wg_ngsetup_probe.py" 127.0.0.1
  echo "=================================================================="
  echo " Atteso: (1) OK — (2a/2b) FALLITO. La chiave, non la raggiungibilita', da' l'accesso."
  echo "=================================================================="
}

down(){
  need_root
  echo "[*] rimuovo il firewall..."
  eval iptables -D INPUT $FW 2>/dev/null || true
  if [ -f "$AMF_YAML.n2bak" ]; then
    echo "[*] ripristino amf.yaml (N2 -> 0.0.0.0)"; cp "$AMF_YAML.n2bak" "$AMF_YAML"; rm -f "$AMF_YAML.n2bak"
  fi
  echo "[*] rimuovo il tunnel..."; tunnel_down
  echo "[*] riavvio il core sullo stato originale..."
  restart_core && echo "[V] RIPRISTINATO: N2 di nuovo su 0.0.0.0, tunnel/firewall rimossi." || echo "[!] core non ripartito, controlla /tmp/core_wg.out"
}

capture(){
  need_root
  ip link show "$IF_CORE" >/dev/null 2>&1 || { echo "[!] N2 non protetto: esegui prima 'tunnel' e 'protect'"; exit 1; }
  local TS ENC DEC USER_SITE
  TS=$(date +%Y%m%d_%H%M%S)
  ENC="$REPO/captures/wg_n2_sulfilo_cifrato_$TS.pcap"
  DEC="$REPO/captures/wg_n2_dentro_tunnel_chiaro_$TS.pcap"
  USER_SITE=$(ls -d /home/*/.local/lib/python3*/site-packages 2>/dev/null | head -1)
  echo "[*] due catture parallele:"
  echo "    (A) SUL FILO           -> lo, 'udp port $PORT'   (cio' che vede chi sniffa)"
  echo "    (B) DENTRO IL TUNNEL   -> $IF_CORE, 'sctp port 38412'  (solo gli endpoint)"
  tcpdump -i lo -w "$ENC" "udp port $PORT" >/dev/null 2>&1 & local PA=$!
  tcpdump -i "$IF_CORE" -w "$DEC" 'sctp port 38412' >/dev/null 2>&1 & local PB=$!
  sleep 1
  echo "[*] genero 3 NGSetup legittimi dal netns '$NS' (dentro il tunnel)..."
  local i; for i in 1 2 3; do
    ip netns exec "$NS" env PYTHONPATH="$USER_SITE" python3 "$SD/wg_ngsetup_probe.py" "$IP_CORE" >/dev/null 2>&1 || true
    sleep 0.5
  done
  sleep 1; kill "$PA" "$PB" 2>/dev/null || true; sleep 1
  echo "=================================================================="
  echo " (A) SUL FILO (l'attaccante che sniffa vede QUESTO) -> $(basename "$ENC")"
  echo -n "     pacchetti totali: "; tcpdump -r "$ENC" 2>/dev/null | wc -l
  echo -n "     dissezionati come WireGuard (cifrati): "; tshark -r "$ENC" -Y wg 2>/dev/null | wc -l
  echo -n "     NGAP LEGGIBILI (deve essere 0): "; tshark -r "$ENC" -Y ngap 2>/dev/null | wc -l
  echo -n "     AMF-UE-NGAP-ID leggibili (deve essere 0): "; tshark -r "$ENC" -T fields -e ngap.AMF_UE_NGAP_ID 2>/dev/null | grep -c '[0-9]'
  echo " (B) DENTRO IL TUNNEL (solo chi ha la chiave) -> $(basename "$DEC")"
  echo -n "     NGAP leggibili (i 3 NGSetup): "; tshark -r "$DEC" -Y ngap 2>/dev/null | wc -l
  echo "=================================================================="
  echo " Tesi: sul filo N2 e' ora UDP WireGuard CIFRATO (0 NGAP, 0 ID sniffabili);"
  echo " nel vecchio pcap d'attacco N2 era in CHIARO (NGAP dissezionato, 0 ESP)."
  chown "${SUDO_USER:-root}:${SUDO_USER:-root}" "$ENC" "$DEC" 2>/dev/null || true
}

case "${1:-}" in
  tunnel) tunnel ;;
  tunnel-down) need_root; tunnel_down; echo "[V] tunnel rimosso" ;;
  protect) protect ;;
  demo) demo ;;
  capture) capture ;;
  down) down ;;
  *) usage ;;
esac
