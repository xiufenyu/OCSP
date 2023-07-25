import csv
import sqlite3
import sys

from constants import STATUS_GOOD, STATUS_REVOKED, CERT_CHAIN, SERIAL_NOT_IN_CRL
from constants import OCSP_RESP_STAPLING_NO_RESPONSE_SENT, ISSUER_IS_NONE


database = sys.argv[1]
conn = sqlite3.connect(database)
cursor = conn.cursor()


BIN = 10000
TOTAL = 1000000

# def write_csv(data: list)

def count_websites():
    sql = f"SELECT COUNT(DISTINCT domain) FROM server"
    cursor = conn.cursor()
    cursor = cursor.execute(sql)
    total = cursor.fetchone()[0]
    print("Total Websites: ", total)
    return total


def ocsp_stapling_websites(total):
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
        size = len(result[status])
        print(status, size, "{:.1%}".format(size/total))


def ocsp_stapling_reasons():
    cursor = conn.cursor()
    sql = "SELECT stapling_reason, COUNT(domain) FROM SERVER GROUP BY stapling_reason"
    cursor = cursor.execute(sql)
    for row in cursor:
        print(row)


def ocsp_stapling_adoption_rate(fname):
    end = 10000
    result = []
    cursor = conn.cursor()
    while (end <= TOTAL):
        sql = f"SELECT COUNT(domain) FROM server WHERE rank >=1 AND rank <= {end} AND (stapling_status='{STATUS_GOOD}' or stapling_status='{STATUS_REVOKED}')"
        cursor = cursor.execute(sql)
        count = cursor.fetchone()[0]
        rate = "{:.1%}".format(count/end)
        print(end, count, rate)
        result.append([end, rate])
        end += BIN
    
    with open(fname, "w") as f:
        writer = csv.writer(f)
        writer.writerows(result)


    # ocsp
def ocsp_websites():
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
        size = len(ocsp_result[revoked])
        print(revoked, size, "{:.1%}".format(size/TOTAL))


def ocsp_adoption_rate(fname):
    result = {}
    end = BIN
    cursor = conn.cursor()
    while end <= TOTAL:
        sql = f"SELECT COUNT(domain) FROM server WHERE cert_name='{CERT_CHAIN}' AND rank >=0 and rank <={end}"
        cursor = cursor.execute(sql)
        count = cursor.fetchone()[0]
        rate = "{:.1%}".format(count/end)
        print(end, count, rate)
        result[end] = [rate]
        end += BIN

    end = BIN
    while end <= TOTAL:
        sql = f"SELECT COUNT(domain) FROM server WHERE ocsp_revoke!='None' AND rank >=0 and rank <={end}"
        cursor = cursor.execute(sql)
        count = cursor.fetchone()[0]
        rate = "{:.1%}".format(count/end)
        print(end, count, rate)
        result[end].append(rate)
        end += BIN

    with open(fname, "w") as f:
        writer = csv.writer(f)
        for key in result:
            values = result[key]
            writer.writerow([key, values[0], values[1]])



def ocsp_revoked_reasons():
    cursor = conn.cursor()
    sql = "SELECT ocsp_reason, COUNT(domain) FROM server GROUP BY ocsp_reason"
    cursor = cursor.execute(sql)
    for row in cursor:
        print(row)


def crl_websites():
    # CRL
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


def group_by_CA(fname):
    sql = f"SELECT domain, issuer_cn FROM server WHERE issuer_cn!='{None}'"
    cursor = conn.execute(sql)
    result = {}
    for row in cursor:
        dm, issuer_cn = row[0], row[1]
        if issuer_cn not in result:
            result[issuer_cn] = set()
        result[issuer_cn].add(dm)
    
    sorted_result = dict(sorted(result.items(), key=lambda item: len(item[1]), reverse=True))
    with open(fname, "w") as f:
        writer = csv.writer(f)
        for issuer in sorted_result:
            # print(issuer, sorted_result)
            size = len(sorted_result[issuer])
            writer.writerow([issuer, size])


def revoke_status_diff(fname):
    cursor = conn.cursor()
    print("Certificate revoked in CRL, but not in OCSP")
    sql = f"SELECT domain, crl_uri FROM SERVER WHERE crl_status='{STATUS_REVOKED}' AND ocsp_revoke='{STATUS_GOOD}'"
    cursor = cursor.execute(sql)
    for row in cursor:
        print(row)

    print("Certificate revoked in OCSP, but not in CRL")
    result2 = []
    sql = f"SELECT domain, crl_uri FROM SERVER WHERE crl_status='{SERIAL_NOT_IN_CRL}' AND (ocsp_revoke='{STATUS_REVOKED}')"
    cursor = cursor.execute(sql)
    for row in cursor:
        dm, crl_uri = row[0], row[1]
        result2.append([dm, crl_uri])
        # print(row)
    with open("OCSP_revoke_crl_good.csv", 'w') as f:
        writer = csv.writer(f)
        writer.writerows(result2)

    print("Certificate revoked in stapling, but not in ocsp")
    sql = f"SELECT domain, crl_uri FROM SERVER WHERE stapling_status='{STATUS_REVOKED}' AND ocsp_revoke='{STATUS_GOOD}'"
    cursor = cursor.execute(sql)
    for row in cursor:
        dm, crl_uri = row[0], row[1]
        print(row)

    
    print("Certificate revoked in OCSP, but not in Stapling")
    sql = f"SELECT domain FROM SERVER WHERE ocsp_revoke='{STATUS_REVOKED}' AND stapling_status='{STATUS_GOOD}'"
    cursor = cursor.execute(sql)
    for row in cursor:
        print(row)

    print("Certificate revoked in Stapling, but not in CRL")
    sql = f"SELECT domain, crl_uri FROM SERVER WHERE stapling_status='{STATUS_REVOKED}' AND crl_status='{SERIAL_NOT_IN_CRL}'"
    cursor = cursor.execute(sql)
    for row in cursor:
        print(row)

    print("Certificate revoked in CRL, but not in Stapling")
    sql = f"SELECT domain FROM SERVER WHERE stapling_status='{STATUS_GOOD}' AND crl_status='{STATUS_REVOKED}'"
    cursor = cursor.execute(sql)
    for row in cursor:
        print(row)


def cert_expiration(fname):
    validity = ["0-30", "30-90", "90-180", "180-365", "365-3650", "3650-999999999"]
    result = {}
    cursor = conn.cursor()
    for v in validity:
        start, end = v.split("-")[0], v.split("-")[1]
        start, end = int(start), int(end)
        sql = f"SELECT COUNT(domain) FROM server WHERE validity>{start} AND validity<={end}"
        cursor = cursor.execute(sql)
        index = str(start) + "-" + str(end)
        result[index] = cursor.fetchone()[0]

    with open(fname, "w") as f:
        writer = csv.writer(f)
        for index in result:
            count = result[index]
            writer.writerow([index, count, "{:.1%}".format(count/TOTAL)])


def stapling_errors(fname):
    cursor = conn.cursor()
    sql = f"SELECT stapling_error, COUNT(domain) FROM server GROUP BY stapling_error"
    cursor = cursor.execute(sql)

    with open(fname, "w") as f:
        writer = csv.writer(f)
        for row in cursor:
            error, count = row[0], row[1]
            writer.writerow([error, count])
            # print(row)



def crl_file_size(fname):
    cursor = conn.cursor()
    sql = f"SELECT crl_size FROM server  WHERE crl_size>0 ORDER BY rank"
    cursor = cursor.execute(sql)
    result = {}
    for row in cursor:
        key = ""
        size = row[0]
        # if size < 1000:
        #     print(size/1000)
        if size / 1000 < 1:
            key = "[0-1K)"
        elif size /(10*1000) < 1:
            key = "[1k-10K)"
        elif size / (1000*1000) < 1:
            key = "[10K-1M)"
        elif size / (10*1000*1000) < 1:
            key = "[1M-10M)"
        elif size /(100*1000*1000) < 1:
            key = "10M-100M"
        elif size /(200*1000*1000) < 1:
            key = "[100M-200M)"
        else:
            key = ">200M"
        if key not in result:
            result[key] = 1
        else:
            result[key] += 1
    with open(fname, "w") as f:
        writer = csv.writer(f)
        for key in result:
            size = result[key]
            writer.writerow([key, size])
    

def crl_revoked_reasons():
    cursor = conn.cursor()
    sql = "SELECT crl_reason, COUNT(domain) FROM server GROUP BY crl_reason"
    cursor = cursor.execute(sql)
    for row in cursor:
        print(row)


if __name__ == "__main__":
    print("----------------OCSP Stapling Report -------------------------")
    total = count_websites()
    # ocsp_stapling_websites(total)
    # ocsp_stapling_adoption_rate("stapling_adoption.csv")
    ocsp_stapling_reasons()

    print("----------------OCSP Report -------------------------")
    # ocsp_websites()
    # ocsp_adoption_rate("ocsp_adoption.csv")
    # ocsp_revoked_reasons()

    print("----------------CRL--------------------")
    # crl_websites()
    # crl_revoked_reasons()

    print("-----------CA-----------")
    # group_by_CA("cert_ca.csv")
    # cert_expiration("validity.csv")

    # stapling_errors("stapling_errors.csv")
    
    # crl_file_size("crl_size.csv")

    print("---------------Status Compare----------------")
    # revoke_status_diff("Status_compare.csv")