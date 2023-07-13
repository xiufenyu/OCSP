import sys
import os
import json
import sqlite3
import base64


from constants import RESULT_JSON
from constants import DOMAIN, CERT_NAME, CERT_ERROR, ISSUER_CERT
from constants import STAPLING_STATUS, STAPLING_ERROR, STAPLING_RESP, STAPLING_ERROR_MSG
from constants import OCSP_URI, OCSP_VERIFY, OCSP_REVOKE, OCSP_ERROR, OCSP_RESP, CRL_URI, CRL_STATUS, CRL_ERROR

from constants import DOWNLOAD_CERT, CERT_CHAIN

from constants import NAME_OR_SERVICE_NOT_KNOWN, NO_ADDRESS_ASSOCIATED_WITH_HOST_NAME, NO_PEER_CERTIFICATE, TEMPORAY_FAILURE_IN_NAME_RESOLUTION

OUT      = sys.argv[1]
database = sys.argv[2]


conn = sqlite3.connect(database)
cursor = conn.cursor()

cursor.execute('''CREATE TABLE IF NOT EXISTS server(domain TEXT PRIMARY KEY, cert_name TEXT, cert_error TEXT, issuer_cert TEXT,  stapling_status TEXT, \
                  stapling_error TEXT, stapling_resp, stapling_error_msg, ocsp_uri TEXT, ocsp_verify TEXT, ocsp_revoke TEXT, ocsp_error TEXT, ocsp_resp TEXT, \
                  crl_uri TEXT, crl_status TEXT, crl_error TEXT)''')


def init_data(data_dict):
    if ISSUER_CERT not in data_dict:
        data_dict[ISSUER_CERT] = None
    if STAPLING_STATUS not in data_dict:
        data_dict[STAPLING_STATUS] = None
    if STAPLING_ERROR not in data_dict:
        data_dict[STAPLING_ERROR] = None
    if STAPLING_RESP not in data_dict:
        data_dict[STAPLING_RESP] = None
    if STAPLING_ERROR_MSG not in data_dict:
        data_dict[STAPLING_ERROR_MSG] = None
    if OCSP_URI not in data_dict:
        data_dict[OCSP_URI] = None
    if OCSP_VERIFY not in data_dict:
        data_dict[OCSP_VERIFY] = None
    if OCSP_REVOKE not in data_dict:
        data_dict[OCSP_REVOKE] = None
    if CRL_ERROR not in data_dict:
        data_dict[CRL_ERROR] = None
    if OCSP_RESP not in data_dict:
        data_dict[OCSP_RESP] = None

    return data_dict


def parse_result_files(out):
    folders = next(os.walk(out))[1]
    result = list()
    for folder in folders:
        rfile = os.path.join(out, folder, RESULT_JSON)
        if not os.path.exists(rfile):
            continue
        with open(rfile, "r") as f:
            data_dict = json.load(f)
            data_dict = init_data(data_dict)

            data_dict[CERT_ERROR] = data_dict[DOWNLOAD_CERT] if DOWNLOAD_CERT in data_dict else None
            data_dict[CERT_NAME] = CERT_CHAIN if not data_dict[CERT_ERROR] else None
            data_dict[OCSP_ERROR] = data_dict[OCSP_ERROR] if OCSP_ERROR in data_dict else None
            data_dict[CRL_URI] = data_dict[CRL_URI] if CRL_URI in data_dict else None
            data_dict[CRL_STATUS] = data_dict[CRL_STATUS] if CRL_STATUS in data_dict else None         

            if data_dict[STAPLING_STATUS] is None and data_dict[STAPLING_ERROR_MSG] is not None:
                if NAME_OR_SERVICE_NOT_KNOWN in data_dict[STAPLING_ERROR_MSG]:
                    data_dict[STAPLING_STATUS] = NAME_OR_SERVICE_NOT_KNOWN
                    data_dict[STAPLING_ERROR] = NAME_OR_SERVICE_NOT_KNOWN
                elif NO_ADDRESS_ASSOCIATED_WITH_HOST_NAME in data_dict[STAPLING_ERROR_MSG]:
                    data_dict[STAPLING_STATUS] = NO_ADDRESS_ASSOCIATED_WITH_HOST_NAME
                    data_dict[STAPLING_ERROR] = NO_ADDRESS_ASSOCIATED_WITH_HOST_NAME
                elif NO_PEER_CERTIFICATE in data_dict[STAPLING_ERROR_MSG]:
                    data_dict[STAPLING_STATUS] = NO_PEER_CERTIFICATE
                    data_dict[STAPLING_ERROR] = NO_PEER_CERTIFICATE
                elif TEMPORAY_FAILURE_IN_NAME_RESOLUTION in data_dict[STAPLING_ERROR_MSG]:
                    data_dict[STAPLING_STATUS] = TEMPORAY_FAILURE_IN_NAME_RESOLUTION
                    data_dict[STAPLING_ERROR] = TEMPORAY_FAILURE_IN_NAME_RESOLUTION

            if data_dict[STAPLING_RESP] is not None:
                data_dict[STAPLING_RESP] = base64.b64encode(bytes(data_dict[STAPLING_RESP], "utf-8")).decode('utf-8')
            if data_dict[STAPLING_ERROR_MSG] is not None:
                data_dict[STAPLING_ERROR_MSG] = base64.b64encode(bytes(data_dict[STAPLING_ERROR_MSG], "utf-8")).decode('utf-8')
            if data_dict[OCSP_RESP] is not None:
                if type(data_dict[OCSP_RESP]) == list:
                    data_dict[OCSP_RESP] =  "\n".join(data_dict[OCSP_RESP])
                data_dict[OCSP_RESP] = base64.b64encode(bytes(data_dict[OCSP_RESP], "utf-8")).decode('utf-8')

            result.append(data_dict)

        if len(result) >=1000:
            write_database(result)
            result.clear()
    write_database(result)

    return result



def write_database(result_list):
    print("Start to write database")
    cursor = conn.cursor()
    for result in result_list:
        sql = f"INSERT INTO server ({DOMAIN}, {CERT_NAME}, {CERT_ERROR}, {ISSUER_CERT}, " \
            f"{STAPLING_STATUS}, {STAPLING_ERROR}, {STAPLING_RESP}, {STAPLING_ERROR_MSG}, {OCSP_URI}, {OCSP_VERIFY}, {OCSP_REVOKE}, {OCSP_ERROR}, {OCSP_RESP}, {CRL_URI}, {CRL_STATUS}, {CRL_ERROR}) " \
            f" VALUES ('{result[DOMAIN]}', '{result[CERT_NAME]}', '{result[CERT_ERROR]}', '{result[ISSUER_CERT]}', '{result[STAPLING_STATUS]}', '{result[STAPLING_ERROR]}', '{result[STAPLING_RESP]}', " \
            f" '{result[STAPLING_ERROR_MSG]}', '{result[OCSP_URI]}', '{result[OCSP_VERIFY]}', '{result[OCSP_REVOKE]}', '{result[OCSP_ERROR]}', '{result[OCSP_RESP]}', '{result[CRL_URI]}', " \
            f" '{result[CRL_STATUS]}', '{result[CRL_ERROR]}')"
        
        cursor = cursor.execute(sql)
    conn.commit()


if __name__ == "__main__":
    parse_result_files(OUT)
    