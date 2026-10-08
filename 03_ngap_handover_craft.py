#!/usr/bin/env python3
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ngap import MessaggiNGAP
from gnb_finto import GnbFinto

_m = MessaggiNGAP()
AMF_ADDR = GnbFinto.AMF_ADDR
AMF_PORT = GnbFinto.AMF_PORT


def build_ng_setup_request(gnb_id, nome):
    return _m.ng_setup_request(gnb_id, nome)


def build_handover_required(ran_ue_id, amf_ue_id, target_gnb_id):
    return _m.handover_required(ran_ue_id, amf_ue_id, target_gnb_id)


def encode(messaggio):
    return _m.codifica(messaggio)


def decode(dati):
    return _m.decodifica(dati)
