#!/usr/bin/env python3
import socket
from ngap import MessaggiNGAP


class GnbFinto:
    AMF_ADDR = "127.0.0.1"
    AMF_PORT = 38412

    def __init__(self, gnb_id, nome="gNB-OAI", addr=None, timeout=5):
        self.gnb_id = gnb_id
        self.nome = nome
        self.ngap = MessaggiNGAP()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_SCTP)
        self.sock.settimeout(timeout)
        self.sock.connect((addr or self.AMF_ADDR, self.AMF_PORT))

    def registrati(self):
        self.sock.send(self.ngap.codifica(self.ngap.ng_setup_request(self.gnb_id, self.nome)))
        try:
            return self.ngap.decodifica(self.sock.recv(4096))[0] == "successfulOutcome"
        except Exception:
            return False

    def invia_handover(self, ran_ue_id, amf_ue_id, target_gnb_id):
        self.sock.send(self.ngap.codifica(
            self.ngap.handover_required(ran_ue_id, amf_ue_id, target_gnb_id)))
        self.sock.settimeout(0.7)
        try:
            risposta = self.ngap.decodifica(self.sock.recv(8192))
            return risposta[1].get("value", [None])[0] != "ErrorIndication"
        except socket.timeout:
            return True

    def svuota(self):
        self.sock.settimeout(0.05)
        try:
            while self.sock.recv(8192):
                pass
        except Exception:
            pass

    def chiudi(self):
        try:
            self.sock.close()
        except Exception:
            pass
