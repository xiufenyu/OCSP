import os
import sys
import subprocess
from parse import parse
from glob import glob
import json
import time
from multiprocessing import Pool


from constants import END_CERTIFICATE
from constants import OCSP_RESP_STAPLING_NO_RESPONSE_SENT, OCSP_STAPLING_STATUS
from constants import RESPONSE_VERIFY, CA_ISSUERS

# DATABASE Attributes
from constants import DOMAIN, DOWNLOAD_CERT, DOWNLOAD_CERT_ERROR
from constants import ISSUER_CERT, CERT_SERIAL
from constants import STAPLING_ERROR, STAPLING_STATUS, UNAUTHORIZED
from constants import OCSP_URI, OCSP_VERIFY, OCSP_REVOKE, OCSP_ERROR
from constants import CRL_URI, CRL_STATUS, CRL_ERROR, CRL_SIZE
from constants import STAPLING_RESP, STAPLING_ERROR_MSG, VERIFY_ERROR, OCSP_RESP

# RESULT
from constants import SERIAL_NOT_IN_CRL, CRL_URI_IS_NONE, ISSUER_IS_NONE, CRL_DOWNLOAD_FAILURE
from constants import STATUS_GOOD, STATUS_REVOKED

from constants import EMPTY_STR, CERT_CHAIN, FILE_CRL, RESULT_JSON


'''
Reference Book: https://www.feistyduck.com/library/openssl-cookbook/online/testing-with-openssl/checking-crl-revocation.html

Download Certificate Chain: $ echo | openssl s_client -showcerts -connect www.feistyduck.com:443 2>&1 | sed --quiet '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' > feistyduck.chain
OCSP Stapling: $ echo | openssl s_client -connect www.feistyduck.com:443 -status
OCSP Request:  $ openssl ocsp -issuer issuer.crt -cert fd.crt -url http://ocsp.comodoca.com -CAfile issuer.crt

Parse Certificate: $ openssl storeutl -noout -text -certs bundle.crt
'''



ZERO = 0
TIMEOUT = 300



OUT = sys.argv[1]
TRANCO_LIST = sys.argv[2]
add_www = True if sys.argv[3] == 'True' else False


def invoke_subproc(cmd):
    output = subprocess.run(cmd, capture_output=True, shell=True)
    resp = output.stdout.decode("utf-8")
    error = output.stderr.decode("utf-8")
    return (resp, error)


# TODO:
class CertificateManager:
    def download_certchain(self, domain):
        dir_out = os.path.join(OUT, domain)
        if not os.path.exists(dir_out):
            os.makedirs(dir_out)
        cert_path = os.path.join(dir_out, CERT_CHAIN)

        cmd = f"echo | openssl s_client -showcerts -connect {domain}:443 2>&1 | sed --quiet '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' > {cert_path}"
        (_, error) = invoke_subproc(cmd)
        if os.path.getsize(cert_path) == ZERO:
            print("❌ download certificate failed")
            os.system(f"rm -f {cert_path}")

        return (cert_path, error)
    

    def download_crl(self, crl_uri, crl_path):
        print(crl_uri)
        os.system(f"wget {crl_uri} -O {crl_path}")
        size = ZERO
        if os.path.exists(crl_path):
            size = os.path.getsize(crl_path)
            if size == ZERO:
                print("❌ crl file size = 0")
                os.system(f"rm -f {crl_path}")
        return size


    def split_certchains(self, cert_path):
        cmd = f"openssl storeutl  -certs {cert_path}"
        output, _ = invoke_subproc(cmd)
        output = output.split("\n")
        number = 0
        cert_content = EMPTY_STR
        for line in output:
            if ": Certificate" in line:
                number = line.split(":")[0]
                continue
            cert_content += line
            cert_content += "\n"
            if line.startswith(END_CERTIFICATE):
                dir_out = os.path.dirname(cert_path)
                dest_path = os.path.join(dir_out, f"cert_{number}.crt")
                with open(dest_path, "w") as f:
                    f.write(cert_content)
                cert_content = EMPTY_STR

    
    def extract_issuer_cert(self, domain, cert_path):
        dir_out = os.path.join(OUT, domain)
        cmd_issuer = f"openssl x509 -in {cert_path} -noout -issuer"
        issuer_name, error = invoke_subproc(cmd_issuer)
        issuer_name = issuer_name.split("issuer=")[1]
        print(domain+", issuer: "+issuer_name)
        
        self.split_certchains(cert_path)

        cert_files = glob(os.path.join(dir_out, "cert_*.crt"))
        issuer_cert = None
        for cert in cert_files:
            (number, ) = parse("cert_{}.crt", os.path.basename(cert))
            if number == "0":
                continue
            cmd_subject = f"openssl x509 -in {cert} -noout -subject"
            subject_name, error = invoke_subproc(cmd_subject)
            subject_name = subject_name.split("subject=")[1]
            if issuer_name == subject_name:
                issuer_cert = cert
                break
        return issuer_cert
    

    def get_oscp_uri(self, cert_path):
        cmd_uri = f"openssl x509 -in {cert_path} -noout -ocsp_uri"
        ocsp_uri, _ = invoke_subproc(cmd_uri)
        ocsp_uri = ocsp_uri.strip("\n")
        print(cert_path, ", ocsp_uri:" + ocsp_uri)
        return ocsp_uri


    def get_serial(self, cert_path):
        cmd_serial = f"openssl x509 -in {cert_path} -noout -serial"
        response, _ = invoke_subproc(cmd_serial)
        serial = response.split("serial=")[1]
        serial = serial.strip("\n")
        print(cert_path + ", serial:" + serial)
        return serial


    def detect_crl_revoked(self, crl_path, serial):
        cmd = f"openssl crl -in {crl_path} -inform DER -text -noout | grep {serial}"
        response, error = invoke_subproc(cmd)
        status = STATUS_REVOKED if response is not EMPTY_STR else SERIAL_NOT_IN_CRL
        print("crl_status:", status)
        return (status, error)


    def download_issuer_cert_with_aia(self, domain, cert_path):
        cmd_issuer_uri = f"openssl x509 -in {cert_path} -noout -text"
        response, error = invoke_subproc(cmd_issuer_uri)
        resp_list = response.split("\n")
        issuer_uri = None
        for item in resp_list:
            if CA_ISSUERS in item:
                issuer_uri = item.split("URI:")[1]
                break
        if issuer_uri is None:
            return None
        print("issuer_uri", issuer_uri)

        issuer_path = os.path.join(OUT, domain, ISSUER_CERT+".crt")
        os.system(f"wget {issuer_uri} -O {issuer_path}")
        if os.path.getsize(issuer_path) == ZERO:
            print("❌ Download issuer certificate failure")
            os.system(f"rm -f {issuer_path}")
            return None

        return issuer_path

class OSCPServer:
    def __init__(self):
        self.cert_mgr = CertificateManager()


    def download_certs(self, domain):
        cert_path, dl_error = self.cert_mgr.download_certchain(domain)
        return cert_path, dl_error


    def ocsp_stapling(self, domain):
        status = None
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
        stapling_error = None
        error_list = error.split("\n")
        for err in error_list:
            if VERIFY_ERROR in err:
                stapling_error = err.split(":")[-1].strip("\n")
        return {STAPLING_STATUS: status, STAPLING_ERROR:stapling_error, STAPLING_RESP: resp, STAPLING_ERROR_MSG: error}


    def ocsp_revocation(self, domain):
        result = dict()
        cert_mgr = self.cert_mgr
        cert_path = os.path.join(OUT, domain, CERT_CHAIN)
        ocsp_uri = cert_mgr.get_oscp_uri(cert_path)
        result = result | {OCSP_URI: ocsp_uri}

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

        result = result | {OCSP_VERIFY: verify_status, OCSP_REVOKE: revoked_status, OCSP_RESP: response}
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
            self.delete_file(crl_path)
            result = result | {CERT_SERIAL: serial, CRL_STATUS: status, CRL_ERROR: error, CRL_SIZE: size}
            return result
        else:
            print("❌: URI is None")
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
    result = {DOMAIN: domain } 
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


# python3 server.py [out] [tranco_list] [True/False]
if __name__ == "__main__":
    # Multiple Process
    domains_list = load_domains(TRANCO_LIST, add_www)
    with Pool(100) as p:
        p.map(start_measure, domains_list)


  