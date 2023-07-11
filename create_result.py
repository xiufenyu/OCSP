import sqlite3
import sys

from constants import STATUS_GOOD
from constants import OCSP_RESP_STAPLING_NO_RESPONSE_SENT

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


def classify_websites():
    # ocsp_stapling
    print("---------- STAPLING Result ----------------")
    sql = f"SELECT domain, stapling_status FROM server WHERE stapling_status='{STATUS_GOOD}'"
    cursor = conn.cursor()
    cursor = cursor.execute(sql)
    print("Stapling [Good] websites:", len(cursor.fetchall()))

    sql = f"SELECT domain, stapling_status FROM server WHERE stapling_status='{OCSP_RESP_STAPLING_NO_RESPONSE_SENT}'"
    cursor = conn.cursor()
    cursor = cursor.execute(sql)
    print("Stapling [No response sent] websites:", len(cursor.fetchall()))

    # ocsp
    sql = f"SELECT domain, ocsp_revoke FROM server GROUP BY domain, ocsp_revoke"
    cursor = conn.cursor()
    cursor = cursor.execute(sql)
    ocsp_result = dict()
    for row in cursor:
        domain, revoked = row[0], row[1]
        if revoked not in ocsp_result:
            ocsp_result[revoked] = 0
        ocsp_result[revoked] += 1
    print("---------- OCSP Result ----------------")
    for revoked in ocsp_result:
        print(revoked, ocsp_result[revoked])

    # CRL 
    sql = f"SELECT domain, crl_status FROM server GROUP BY domain, crl_status"
    cursor = conn.cursor()
    cursor = cursor.execute(sql)
    crl_result = dict()
    for row in cursor:
        domain, revoked = row[0], row[1]
        if revoked not in crl_result:
            crl_result[revoked] = 0
        crl_result[revoked] += 1
    print("---------- CRL Result ----------------")
    for revoked in crl_result:
        print(revoked, crl_result[revoked])


if __name__ == "__main__":
    count_websites()
    classify_websites()