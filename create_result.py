import sqlite3
import sys

from constants import STATUS_GOOD
from constants import OCSP_RESP_STAPLING_NO_RESPONSE_SENT, ISSUER_IS_NONE

# 16079
database = sys.argv[1]
conn = sqlite3.connect(database)
cursor = conn.cursor()

def count_websites():
    sql = f"SELECT COUNT(DISTINCT domain) FROM server"
    cursor = conn.cursor()
    cursor = cursor.execute(sql)
    total = cursor.fetchone()[0]
    print("Total Websites: ", total)
    return total


def ocsp_stapling_websites():
    # ocsp_stapling
    print("---------- OCSP STAPLING Result ----------------")
    sql = f"SELECT domain, stapling_status FROM server GROUP BY domain, stapling_status"

    cursor = conn.cursor()
    cursor = cursor.execute(sql)
    result = dict()

    for row in cursor:
        domain, status = row[0], row[1]
        if status not in result:
            result[status] = set()
        result[status].add(domain)

    for status in result:
        print(status, len(result[status]))


def ocsp_websites():
    # ocsp
    print("---------- OCSP Result ----------------")
    sql = f"SELECT domain, ocsp_revoke FROM server GROUP BY domain, ocsp_revoke"
    cursor = conn.cursor()
    cursor = cursor.execute(sql)
    ocsp_result = dict()
    for row in cursor:
        domain, revoked = row[0], row[1]
        if revoked not in ocsp_result:
            ocsp_result[revoked] = set()
        ocsp_result[revoked].add(domain)
    for revoked in ocsp_result:
        print(revoked, len(ocsp_result[revoked]))


def reasons_for_none_ocsp():
    sql = f"SELECT domain, ocsp_revoke FROM server WHERE ocsp_revoke='{None}' AND ocsp_error='{ISSUER_IS_NONE}'"
    cursor = conn.cursor()
    cursor = cursor.execute(sql)
    print("ocsp issuer is None", len(cursor.fetchall()))

    sql = f"SELECT domain, ocsp_revoke FROM server WHERE ocsp_revoke='{None}' AND ocsp_uri='{None}'"
    cursor = conn.cursor()
    cursor = cursor.execute(sql)
    print("ocsp uri is None", len(cursor.fetchall()))


    sql = f"SELECT domain, ocsp_revoke FROM server WHERE ocsp_revoke='{None}' AND ocsp_uri=='{None}' AND ocsp_error='{ISSUER_IS_NONE}'"
    cursor = conn.cursor()
    cursor = cursor.execute(sql)
    print("ocsp revoke is None, uri==None", len(cursor.fetchall()))


def crl_websites():
    # CRL
    print("---------- CRL Result ----------------")
    sql = f"SELECT domain, crl_status FROM server GROUP BY domain, crl_status"
    cursor = conn.cursor()
    cursor = cursor.execute(sql)
    crl_result = dict()
    for row in cursor:
        domain, revoked = row[0], row[1]
        if revoked not in crl_result:
            crl_result[revoked] = set()
        crl_result[revoked].add(domain)
    for revoked in crl_result:
        print(revoked, len(crl_result[revoked]))



if __name__ == "__main__":
    # count_websites()
    # ocsp_stapling_websites()
    # ocsp_websites()
    # reasons_for_none_ocsp()
    crl_websites()