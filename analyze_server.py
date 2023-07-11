import sys
import os
import json
import sqlite3

from constants import RESULT_JSON
from constants import DOMAIN, CERT_NAME, CERT_ERROR, ISSUER_CERT
from constants import STAPLING_STATUS, STAPLING_ERROR, OCSP_URI, OCSP_VERIFY, OCSP_REVOKE, OCSP_ERROR, CRL_URI, CRL_STATUS, CRL_ERROR

from constants import DOWNLOAD_CERT, CERT_CHAIN

OUT      = sys.argv[1]
database = sys.argv[2]


conn = sqlite3.connect(database)
cursor = conn.cursor()

cursor.execute('''CREATE TABLE IF NOT EXISTS server(domain TEXT PRIMARY KEY, cert_name TEXT, cert_error TEXT, issuer_cert TEXT,  \
                  stapling_status TEXT, stapling_error TEXT, ocsp_uri TEXT, ocsp_verify TEXT, ocsp_revoke TEXT, ocsp_error TEXT, crl_uri, crl_status TEXT, crl_error TEXT)''')


def init_data(data_dict):
    if ISSUER_CERT not in data_dict:
        data_dict[ISSUER_CERT] = None
    if STAPLING_STATUS not in data_dict:
        data_dict[STAPLING_STATUS] = None
    if STAPLING_ERROR not in data_dict:
        data_dict[STAPLING_ERROR] = None
    if OCSP_URI not in data_dict:
        data_dict[OCSP_URI] = None
    if OCSP_VERIFY not in data_dict:
        data_dict[OCSP_VERIFY] = None
    if OCSP_REVOKE not in data_dict:
        data_dict[OCSP_REVOKE] = None
    if CRL_ERROR not in data_dict:
        data_dict[CRL_ERROR] = None

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

            if STAPLING_ERROR in data_dict and data_dict[STAPLING_ERROR] is not None:
                stapling_error = data_dict[STAPLING_ERROR]
                errors_list = stapling_error.split("\n")
                if len(errors_list) >= 3:
                    data_dict[STAPLING_ERROR] = errors_list[-3] + "," + errors_list[-2]
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
        # print(result)
        sql = f"INSERT INTO server ({DOMAIN}, {CERT_NAME}, {CERT_ERROR}, {ISSUER_CERT}, " \
            f"{STAPLING_STATUS}, {STAPLING_ERROR}, {OCSP_URI}, {OCSP_VERIFY}, {OCSP_REVOKE}, {OCSP_ERROR}, {CRL_URI}, {CRL_STATUS}, {CRL_ERROR}) " \
            f" VALUES ('{result[DOMAIN]}', '{result[CERT_NAME]}', '{result[CERT_ERROR]}', '{result[ISSUER_CERT]}', '{result[STAPLING_STATUS]}', '{result[STAPLING_ERROR]}', "  \
            f" '{result[OCSP_URI]}', '{result[OCSP_VERIFY]}', '{result[OCSP_REVOKE]}', '{result[OCSP_ERROR]}', '{result[CRL_URI]}', '{result[CRL_STATUS]}', '{result[CRL_ERROR]}')"
        print(sql)
        
        cursor = cursor.execute(sql)
    conn.commit()


if __name__ == "__main__":
    parse_result_files(OUT)
    