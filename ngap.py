#!/usr/bin/env python3
from pycrate_asn1dir import NGAP


class MessaggiNGAP:
    PLMN = bytes.fromhex("09f107")
    TAC = bytes.fromhex("000001")

    SOURCE_TO_TARGET = bytes.fromhex(
        "408130102028000000000000000000010242aaa400409a0a200205e3f07156040794813920"
        "05004312300000000380284d005e5204bd8014010c48c00000800e00a1340200327ef8e049"
        "08f00112e060c911440222ec60c00000410020010c10d21a1a0301b005e0404063ae025800"
        "88bd76380830f800584888bd76380832f00058e0190437e30d07828407c0202683c0800041"
        "24981950001ffff000000010ee2004000010106e28840001002c800009053099aa926a0000"
        "801010002003404004ed924603b80ecf13579a0000053420040004b0184180583830438006"
        "2503820043de802000200000c8118101400060140180ca82803115554001c00400468800a8"
        "8400a0000000000001c1740054a0000000000000010a100400800105400102520000a201c0"
        "08e38800a284040016300000000a00010009f1070000b00020010009f1070000b000208000"
        "0a0400"
    )

    def __init__(self):
        self.pdu = NGAP.NGAP_PDU_Descriptions.NGAP_PDU
        self.ies = NGAP.NGAP_IEs

    def _ie(self, id_, criticita, valore):
        return {"id": id_, "criticality": criticita, "value": valore}

    def codifica(self, messaggio):
        self.pdu.set_val(messaggio)
        return self.pdu.to_aper()

    def decodifica(self, dati):
        self.pdu.from_aper(dati)
        return self.pdu.get_val()

    def ng_setup_request(self, gnb_id, nome):
        gnb = ("globalGNB-ID", {"pLMNIdentity": self.PLMN, "gNB-ID": ("gNB-ID", (gnb_id, 28))})
        ta = {"tAC": self.TAC, "broadcastPLMNList": [{"pLMNIdentity": self.PLMN,
              "tAISliceSupportList": [{"s-NSSAI": {"sST": b"\x01", "sD": bytes.fromhex("000001")}}]}]}
        ies = [
            self._ie(27, "reject", ("GlobalRANNodeID", gnb)),
            self._ie(82, "ignore", ("RANNodeName", nome)),
            self._ie(102, "reject", ("SupportedTAList", [ta])),
            self._ie(50, "ignore", ("PagingDRX", "v128")),
        ]
        return ("initiatingMessage", {"procedureCode": 21, "criticality": "reject",
                "value": ("NGSetupRequest", {"protocolIEs": ies})})

    def handover_required(self, ran_ue_id, amf_ue_id, target_gnb_id):
        self.ies.HandoverRequiredTransfer.set_val({})
        ho_transfer = self.ies.HandoverRequiredTransfer.to_aper()
        target = ("targetRANNodeID", {
            "globalRANNodeID": ("globalGNB-ID", {"pLMNIdentity": self.PLMN,
                                "gNB-ID": ("gNB-ID", (target_gnb_id, 28))}),
            "selectedTAI": {"pLMNIdentity": self.PLMN, "tAC": self.TAC}})
        ies = [
            self._ie(10, "reject", ("AMF-UE-NGAP-ID", amf_ue_id)),
            self._ie(85, "reject", ("RAN-UE-NGAP-ID", ran_ue_id)),
            self._ie(29, "reject", ("HandoverType", "intra5gs")),
            self._ie(15, "ignore", ("Cause", ("radioNetwork", "handover-desirable-for-radio-reason"))),
            self._ie(105, "reject", ("TargetID", target)),
            self._ie(61, "reject", ("PDUSessionResourceListHORqd",
                 [{"pDUSessionID": 10, "handoverRequiredTransfer": ho_transfer}])),
            self._ie(101, "reject", ("SourceToTarget-TransparentContainer", self.SOURCE_TO_TARGET)),
        ]
        return ("initiatingMessage", {"procedureCode": 12, "criticality": "reject",
                "value": ("HandoverRequired", {"protocolIEs": ies})})
