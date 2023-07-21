import os
import sys
# import subprocess
import json
import time
from multiprocessing import Pool


from constants import invoke_subproc
from cert_mgr import CertificateManager


from constants import END_CERTIFICATE
from constants import OCSP_RESP_STAPLING_NO_RESPONSE_SENT, OCSP_STAPLING_STATUS, STAPLING_VERIFICATION_ERROR, STAPLING_VERIFICATION_WORD
from constants import RESPONSE_VERIFY, CA_ISSUERS

# DATABASE Attributes
from constants import DOMAIN, DOWNLOAD_CERT, DOWNLOAD_CERT_ERROR
from constants import ISSUER_CERT, SERIAL, ISSUER_CN
from constants import STAPLING_ERROR, STAPLING_STATUS, STAPLING_REASON, STAPLING_VERIFICATION, UNAUTHORIZED
from constants import OCSP_URI, OCSP_VERIFY, OCSP_REVOKE, OCSP_ERROR, OCSP_REASON, REASON
from constants import CRL_URI, CRL_STATUS, CRL_REASON, CRL_ERROR, CRL_RESP, CRL_SIZE
from constants import STAPLING_RESP, STAPLING_ERROR_MSG, VERIFY_ERROR, OCSP_RESP
from constants import TIME_STAMP

# RESULT
from constants import SERIAL_NOT_IN_CRL, CRL_URI_IS_NONE, ISSUER_IS_NONE
from constants import STATUS_GOOD, STATUS_REVOKED
from constants import OCSP_REVOCATION_REASON, CRL_REVOCATION_REASON
from constants import CRL_SERIAL_NUMBER


from constants import EMPTY_STR, CERT_CHAIN, FILE_CRL, RESULT_JSON


'''
Reference Book: https://www.feistyduck.com/library/openssl-cookbook/online/testing-with-openssl/checking-crl-revocation.html

Download Certificate Chain: $ echo | openssl s_client -showcerts -connect www.feistyduck.com:443 2>&1 | sed --quiet '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' > feistyduck.chain
OCSP Stapling: $ echo | openssl s_client -connect www.feistyduck.com:443 -status
OCSP Request:  $ openssl ocsp -issuer issuer.crt -cert fd.crt -url http://ocsp.comodoca.com -CAfile issuer.crt

Parse Certificate: $ openssl storeutl -noout -text -certs bundle.crt
'''


TIMEOUT = 300



OUT = sys.argv[1]
TRANCO_LIST = sys.argv[2]

add_www = True if sys.argv[3] == 'True' else False



class OSCPServer:
    def __init__(self):
        self.cert_mgr = CertificateManager()


    def download_certs(self, domain):
        cert_path, dl_error = self.cert_mgr.download_certchain(domain)
        return cert_path, dl_error


    def ocsp_stapling(self, domain):
        status = None
        reason = None
        cmd = f"echo | openssl s_client -connect {domain}:443 -status"
        (resp, error) = invoke_subproc(cmd)
        resp_list = resp.split("\n")
        for line in resp_list:
            if OCSP_RESP_STAPLING_NO_RESPONSE_SENT in line:
                print(domain + ":" + OCSP_RESP_STAPLING_NO_RESPONSE_SENT)
                status = OCSP_RESP_STAPLING_NO_RESPONSE_SENT
                break
            elif OCSP_STAPLING_STATUS in line:
                status = line.split(":")[1].strip()
        if status is None and error:
            print("❌", error)
        else:
            print("ocsp_stapling status=" + status)
        # resp_b64 = base64.b64encode(bytes(resp, "utf-8")).decode('utf-8')
        # error_b64 = base64.b64encode(bytes(error, "utf-8")).decode('utf-8')
        cert_mgr = self.cert_mgr
        reason = cert_mgr.get_OCSP_revocation_reason(resp_list)
        verification = cert_mgr.get_stapling_verification(resp_list)
        stapling_error = None
        error_list = error.split("\n")
        for err in error_list:
            if VERIFY_ERROR in err:
                stapling_error = err.split(":")[-1].strip("\n")

        return {STAPLING_STATUS: status, STAPLING_ERROR:stapling_error,
                STAPLING_REASON: reason, STAPLING_VERIFICATION: verification,
                STAPLING_RESP: resp, STAPLING_ERROR_MSG: error}


    def ocsp_revocation(self, domain):
        result = dict()
        cert_mgr = self.cert_mgr
        cert_path = os.path.join(OUT, domain, CERT_CHAIN)
        expiry_dict = cert_mgr.extract_expiry(cert_path)
        serial = cert_mgr.get_serial(cert_path)
        issuer_cn = cert_mgr.extract_issuer_authority(cert_path)
        ocsp_uri = cert_mgr.get_oscp_uri(cert_path)
        result = result | {OCSP_URI: ocsp_uri} | expiry_dict | {SERIAL: serial} | {ISSUER_CN: issuer_cn}

        issuer_cert = cert_mgr.extract_issuer_cert(domain, cert_path)
        if issuer_cert is None:
            issuer_cert = cert_mgr.download_issuer_cert_with_aia(domain, cert_path)
        result = result | {ISSUER_CERT: issuer_cert}

        if issuer_cert is None:
            print("❌ " + domain + ": no issuer")
            result = result | {OCSP_ERROR: ISSUER_IS_NONE}
            return result

        # Make the OCSP request
        cmd_ocsp = f"openssl ocsp -issuer {issuer_cert} -cert {cert_path} -text -url {ocsp_uri}"
        response, error = invoke_subproc(cmd_ocsp)
        stdout_resp = response.split("\n")
        reason = cert_mgr.get_OCSP_revocation_reason(stdout_resp)
        error_list = error.split("\n")
        verify_status = None
        revoked_status = None
        for line in stdout_resp:
            if cert_path in line:
                revoked_status = line.split(": ")[1]
            if RESPONSE_VERIFY in line:
                verify_status = line.split(RESPONSE_VERIFY)[1].strip()
                break
        if verify_status is None:
            if UNAUTHORIZED in response:
                revoked_status = UNAUTHORIZED
            for line in error_list:
                if RESPONSE_VERIFY in line:
                    verify_status = line.split(RESPONSE_VERIFY)[1].strip()
                    break

        result = result | {OCSP_VERIFY: verify_status, OCSP_REVOKE: revoked_status, OCSP_RESP: response, OCSP_REASON: reason}
        print("OCSP verify:", verify_status, ", revoke:", revoked_status)
        return result
    

    def crl_revocation(self, domain):
        result = dict()
        dir_out = os.path.join(OUT, domain)
        cert_path = os.path.join(dir_out, CERT_CHAIN)
        cert_mgr = self.cert_mgr
        
        cmd_crl = f"openssl x509 -in {cert_path} -noout -text | grep -A 5 CRL"
        response, error = invoke_subproc(cmd_crl)
        crl_uri = None
        for line in response.split("\n"):
            line = line.strip()
            if line.startswith("URI:"):
                crl_uri = line.split("URI:")[1].strip("\n")
                result = result | {CRL_URI: crl_uri}
                break
        crl_path = os.path.join(dir_out, FILE_CRL)
        issuer_cert = cert_mgr.extract_issuer_cert(domain, cert_path)
        status = None
        if crl_uri is not None:
            size = cert_mgr.download_crl(crl_uri, crl_path)

            # TODO: verify crl file
            # cmd_verify = f"openssl crl -in {crl_path} -inform DER -CAfile {issuer_cert} -noout"
            # response, _ = invoke_subproc(cmd_verify)
            # print("!!!!!!!!!!!!", response)
            serial = cert_mgr.get_serial(cert_path)
            status, error = cert_mgr.detect_crl_revoked(crl_path, serial)
            reason_dict = None
            if status == STATUS_REVOKED:
                reason_dict = cert_mgr.get_crl_revocation_reason(crl_path, serial)
            if reason_dict:
                result = result | {SERIAL: serial, CRL_STATUS: status, CRL_ERROR: error, CRL_SIZE: size, CRL_REASON: reason_dict[CRL_REASON], CRL_RESP: reason_dict[CRL_RESP]}
            else:
                result = result | {SERIAL: serial, CRL_STATUS: status, CRL_ERROR: error, CRL_SIZE: size, CRL_REASON: None, CRL_RESP: None}
            return result
        else:
            print("❌: CRL URI is None")
            result = result | {CRL_ERROR: CRL_URI_IS_NONE}
            return result



    def wait_file_download(self, fpath, start_ts, timeout=TIMEOUT):
        now = time.time()
        while now - start_ts <=timeout:
            if os.path.exists(fpath):
                return True
            time.sleep(1)
        return False
    

    def check_finished(self, domain):
        result_file = os.path.join(OUT, domain, RESULT_JSON)
        if os.path.exists(result_file):
            return True
        return False
        

    def write_result(self, result_dict, json_file):
        with open(json_file, "w") as f:
            json.dump(result_dict, f)


    def delete_file(self, fpath):
        if os.path.exists(fpath):
            os.system(f"rm -f {fpath}")


def start_measure(domain):
    server = OSCPServer()
    if server.check_finished(domain):
        return
    print(f"------------{domain}--------------")
    result = {DOMAIN: domain, TIME_STAMP: time.time()}
    result_file = os.path.join(OUT, domain, RESULT_JSON)

    staple_result = server.ocsp_stapling(domain)
    result = result | staple_result
    cert_path, dl_error = server.download_certs(domain)
    if not os.path.exists(cert_path):
        result = result | {DOWNLOAD_CERT: DOWNLOAD_CERT_ERROR}
        server.write_result(result, result_file)
        return
    ocsp_result = server.ocsp_revocation(domain)
    crl_result = server.crl_revocation(domain)
    result = result | ocsp_result | crl_result
    server.write_result(result, result_file)
    time.sleep(1)


def load_domains(fpath, add_www):
    domains_list = set()
    with open(fpath, "r") as f:
        for row in f:
            domain = row.split(",")[1].strip("\n")
            domain = "www." + domain if add_www else domain
            domains_list.add(domain)
    return domains_list


def main():
    # Multiple Process
    domains_list = load_domains(TRANCO_LIST, add_www)
    # domains_list = ["www.aikis.or.jp", "www.algarnet.com.br", "www.belti.ru"]
    with Pool(50) as p:
        p.map(start_measure, domains_list)


# python3 server.py [out] [tranco_list] [True/False]
if __name__ == "__main__":
    main()
   


  