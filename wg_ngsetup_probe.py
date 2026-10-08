#!/usr/bin/env python3
import sys, socket, os, importlib.util

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("craft", os.path.join(HERE, "03_ngap_handover_craft.py"))
craft = importlib.util.module_from_spec(spec); spec.loader.exec_module(craft)

addr = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
port = 38412
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_SCTP)
    s.settimeout(5)
    s.connect((addr, port))
    s.send(craft.encode(craft.build_ng_setup_request(0xABC, "gNB-test")))
    resp = craft.decode(s.recv(4096)); s.close()
    ok = resp[0] == "successfulOutcome"
    print(f"    [{addr}:{port}] NGSetup -> {'OK — ACCETTATO dall AMF' if ok else 'RIFIUTATO'}")
    sys.exit(0 if ok else 2)
except socket.timeout:
    print(f"    [{addr}:{port}] NGSetup -> FALLITO (timeout: N2 irraggiungibile / bloccato dal firewall)")
    sys.exit(1)
except ConnectionRefusedError:
    print(f"    [{addr}:{port}] NGSetup -> FALLITO (connessione rifiutata: nessun N2 in ascolto qui)")
    sys.exit(1)
except Exception as e:
    print(f"    [{addr}:{port}] NGSetup -> FALLITO ({type(e).__name__}: {e})")
    sys.exit(1)
