import sys
import os
import json
import sqlite3
import base64



from cert_mgr import CertificateManager


from constants import RESULT_JSON
from constants import DOMAIN, SERIAL, CERT_NAME, CERT_ERROR, ISSUER_CERT, ISSUER_CN
from constants import STAPLING_STATUS, STAPLING_ERROR, STAPLING_RESP, STAPLING_ERROR_MSG, STAPLING_REASON, STAPLING_VERIFICATION
from constants import OCSP_URI, OCSP_VERIFY, OCSP_REVOKE, OCSP_REASON, OCSP_ERROR, OCSP_RESP
from constants import CRL_URI, CRL_STATUS, CRL_REASON, CRL_ERROR, CRL_RESP, CRL_SIZE
from constants import TIME_STAMP, VALIDITY, NOT_BEFORE, NOT_AFTER

from constants import DOWNLOAD_CERT, CERT_CHAIN

from constants import NAME_OR_SERVICE_NOT_KNOWN, NO_ADDRESS_ASSOCIATED_WITH_HOST_NAME, NO_PEER_CERTIFICATE, TEMPORAY_FAILURE_IN_NAME_RESOLUTION





OUT      = sys.argv[1]
database = sys.argv[2]

ZERO = 0


conn = sqlite3.connect(database)
cursor = conn.cursor()

cursor.execute('''CREATE TABLE IF NOT EXISTS server( \
                  domain TEXT PRIMARY KEY, cert_name TEXT, serial TEXT, issuer_cn TEXT, not_before TEXT, not_after TEXT, validity integer, issuer_cert TEXT, cert_error TEXT,\
                  stapling_status TEXT, stapling_reason TEXT, stapling_error TEXT, stapling_verification TEXT, stapling_resp, stapling_error_msg, \
                  ocsp_uri TEXT, ocsp_verify TEXT, ocsp_revoke TEXT, ocsp_reason TEXT, ocsp_error TEXT, ocsp_resp TEXT, \
                  crl_uri TEXT, crl_status TEXT, crl_reason TEXT, crl_error TEXT, crl_resp TEXT, crl_size integer, ts TEXT)''')


def init_data(data_dict):
    if SERIAL not in data_dict:
        data_dict[SERIAL] = None
    if ISSUER_CN not in data_dict:
        data_dict[ISSUER_CN] = None
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
    if STAPLING_REASON not in data_dict:
        data_dict[STAPLING_REASON] = None
    if STAPLING_VERIFICATION not in data_dict:
        data_dict[STAPLING_VERIFICATION] = None
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
    if OCSP_REASON not in data_dict:
        data_dict[OCSP_REASON] = None
    if CRL_SIZE not in data_dict:
        data_dict[CRL_SIZE] = ZERO
    if CRL_RESP not in data_dict:
        data_dict[CRL_RESP] = None
    if CRL_REASON not in data_dict:
        data_dict[CRL_REASON] = None
    
    if NOT_BEFORE not in data_dict:
        data_dict[NOT_BEFORE] = None
    if NOT_AFTER not in data_dict:
        data_dict[NOT_AFTER] = None
    if VALIDITY not in data_dict:
        data_dict[VALIDITY] = None
    if TIME_STAMP not in data_dict:
        data_dict[TIME_STAMP] = None

    return data_dict


def update_cert_infor(data_dict, cert_path, rfile):
    cert_mgr = CertificateManager()
    # cert_path = os.path.join(out, folder, CERT_CHAIN)
    if os.path.exists(cert_path):
        if data_dict[SERIAL] is None:
            data_dict[SERIAL] = cert_mgr.get_serial(cert_path)
        if data_dict[ISSUER_CN] is None:
            data_dict[ISSUER_CN] = cert_mgr.extract_issuer_authority(cert_path)
        expiry_dict = cert_mgr.extract_expiry(cert_path)
        if data_dict[NOT_BEFORE] is None:
            data_dict[NOT_BEFORE] = expiry_dict[NOT_BEFORE]
        if data_dict[NOT_AFTER] is None:
            data_dict[NOT_AFTER] = expiry_dict[NOT_AFTER]
        if data_dict[VALIDITY] is None:
            data_dict[VALIDITY] = expiry_dict[VALIDITY]

        if data_dict[TIME_STAMP] is None:
            data_dict[TIME_STAMP] = os.path.getctime(rfile)

    return data_dict


def update_crl_infor(data_dict):


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
            cert_path = os.path.join(out, folder, CERT_CHAIN)
            data_dict = update_cert_infor(data_dict, cert_path, rfile)
           

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
            if data_dict[CRL_RESP] is not None:
                if type(data_dict[CRL_RESP]) == list:
                    data_dict[CRL_RESP] = "\n".join(data_dict[CRL_RESP])
                data_dict[CRL_RESP] = base64.b64encode(bytes(data_dict[CRL_RESP], "utf-8")).decode("utf-8")
            

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
        sql = f"INSERT INTO server ({DOMAIN}, {CERT_NAME}, {SERIAL}, {ISSUER_CN}, {NOT_BEFORE}, {NOT_AFTER}, {VALIDITY}, {ISSUER_CERT}, {CERT_ERROR}, " \
            f"{STAPLING_STATUS}, {STAPLING_REASON}, {STAPLING_ERROR}, {STAPLING_VERIFICATION}, {STAPLING_RESP}, {STAPLING_ERROR_MSG}, " \
            f"{OCSP_URI}, {OCSP_VERIFY}, {OCSP_REVOKE}, {OCSP_REASON}, {OCSP_ERROR}, {OCSP_RESP}, " \
            f"{CRL_URI}, {CRL_STATUS}, {CRL_REASON}, {CRL_ERROR}, {CRL_RESP}, {CRL_SIZE}, {TIME_STAMP}) " \
            f" VALUES ('{result[DOMAIN]}', '{result[CERT_NAME]}', '{result[SERIAL]}', '{result[ISSUER_CN]}', '{result[NOT_BEFORE]}', '{result[NOT_AFTER]}', '{result[VALIDITY]}', '{result[ISSUER_CERT]}', '{result[CERT_ERROR]}', " \
            f" '{result[STAPLING_STATUS]}', '{result[STAPLING_REASON]}', '{result[STAPLING_ERROR]}', '{result[STAPLING_VERIFICATION]}', '{result[STAPLING_RESP]}', '{result[STAPLING_ERROR_MSG]}', " \
            f" '{result[OCSP_URI]}', '{result[OCSP_VERIFY]}', '{result[OCSP_REVOKE]}', '{result[OCSP_REASON]}', '{result[OCSP_ERROR]}', '{result[OCSP_RESP]}', " \
            f" '{result[CRL_URI]}', '{result[CRL_STATUS]}', '{result[CRL_REASON]}', '{result[CRL_ERROR]}', '{result[CRL_RESP]}', {result[CRL_SIZE]}, {result[TIME_STAMP]})"
        # print(sql)
        cursor = cursor.execute(sql)
    conn.commit()


if __name__ == "__main__":
    parse_result_files(OUT)
    