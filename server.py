import os
import sys
import subprocess
from parse import parse
from glob import glob
import json
import time

'''
Reference Book: https://www.feistyduck.com/library/openssl-cookbook/online/testing-with-openssl/checking-crl-revocation.html

Download Certificate Chain: $ echo | openssl s_client -showcerts -connect www.feistyduck.com:443 2>&1 | sed --quiet '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' > feistyduck.chain
OCSP Stapling: $ echo | openssl s_client -connect www.feistyduck.com:443 -status
OCSP Request:  $ openssl ocsp -issuer issuer.crt -cert fd.crt -url http://ocsp.comodoca.com -CAfile issuer.crt

Parse Certificate: $ openssl storeutl -noout -text -certs bundle.crt
'''


OCSP_STAPLING_NOT_SUPPORT_STR = "OCSP response: no response sent"
OCSP_STAPLING_STATUS = "Cert Status:"
GOOD = "good"
REVOKED = "revoked"
SERIAL_NOT_IN_CRL = "serial_not_in_crl"
CRL_URI_IS_NONE = "crl_uri_is_none"
CRL_DOWNLOAD_FAILURE = "crl_download_failure"
ISSUER_IS_NONE = "issuer_is_none"

RESPONSE_VERIFY = "Response verify"

BEGIN_CERTIFICATE = "-----BEGIN CERTIFICATE-----"
END_CERTIFICATE = "-----END CERTIFICATE-----"

EMPTY_STR = ""
CERT_CHAIN = "cert.chain"
FILE_CRL = "file.crl"


DOMAIN = "domain"
DOWNLOAD_CERT = "download_cert"
DOWNLOAD_CERT_ERROR = "download_cert_failed"
ISSUER_CERT = "issuer_cert"
CERT_SERIAL = "cert_serial"
STAPLING_STATUS = "stapling_status"
STAPLING_ERROR = "stapling_error"
OCSP_URI = "ocsp_uri"
OCSP_VERIFY = "ocsp_verify"
OCSP_REVOKE = "ocsp_revoke"
OCSP_ERROR = "ocsp_error"
CRL_URI = "crl_uri"
CRL_STATUS = "crl_status"
CRL_ERROR = "crl_error"

RESULT_JSON = "result.json"

ZERO = 0
TIMEOUT = 300



OUT = sys.argv[1]
TRANCO_LIST = sys.argv[2]


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
        if os.path.getsize(crl_path) == ZERO:
            print("❌ crl file size = 0")
            os.system(f"rm -f {crl_path}")


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
        # print("result=", response, error)
        status = REVOKED if response is not EMPTY_STR else SERIAL_NOT_IN_CRL
        print("crl_status:", status)
        return (status, error)



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
            if OCSP_STAPLING_NOT_SUPPORT_STR in line:
                print(domain + ":" + OCSP_STAPLING_NOT_SUPPORT_STR)
                status = OCSP_STAPLING_NOT_SUPPORT_STR
                break
            elif OCSP_STAPLING_STATUS in line:
                status = line.split(":")[1].strip()
                print(domain, status)
        if status is None and error:
            print("❌", error)
        else:
            print("ocsp_stapling status=" + status)
        return {STAPLING_STATUS: status, STAPLING_ERROR:error}


    def ocsp_revocation(self, domain):
        result = dict()
        cert_mgr = self.cert_mgr
        cert_path = os.path.join(OUT, domain, CERT_CHAIN)
        ocsp_uri = cert_mgr.get_oscp_uri(cert_path)
        result = result | {OCSP_URI: ocsp_uri}

        issuer_cert = cert_mgr.extract_issuer_cert(domain, cert_path)
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
            for line in error_list:
                if RESPONSE_VERIFY in line:
                    verify_status = line.split(RESPONSE_VERIFY)[1].strip()
                    break
        result = result | {OCSP_VERIFY: verify_status, OCSP_REVOKE: revoked_status}
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
            cert_mgr.download_crl(crl_uri, crl_path)
            # if not self.wait_file_download(crl_path, time.time()):
            #     return (status, CRL_DOWNLOAD_FAILURE)

            # TODO: verify crl file
            # cmd_verify = f"openssl crl -in {crl_path} -inform DER -CAfile {issuer_cert} -noout"
            # response, _ = invoke_subproc(cmd_verify)
            # print("!!!!!!!!!!!!", response)
            serial = cert_mgr.get_serial(cert_path)
            status, error = cert_mgr.detect_crl_revoked(crl_path, serial)
            result = result | {CERT_SERIAL: serial, CRL_STATUS: status, CRL_ERROR: error}
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



def start_measure(domains_list):
    server = OSCPServer()
    for domain in domains_list:
        if server.check_finished(domain):
            continue
        print(f"------------{domain}--------------")
        result = {DOMAIN: domain } 
        result_file = os.path.join(OUT, domain, RESULT_JSON)
        
        staple_result = server.ocsp_stapling(domain)
        cert_path, dl_error = server.download_certs(domain)
        if not os.path.exists(cert_path):
            result = result | {DOWNLOAD_CERT: DOWNLOAD_CERT_ERROR}
            server.write_result(result, result_file)
            continue
        ocsp_result = server.ocsp_revocation(domain)
        crl_result = server.crl_revocation(domain)
        result = result | staple_result | ocsp_result | crl_result
        server.write_result(result, result_file)
        time.sleep(1)


def load_domains(fpath):
    domains_list = set()
    with open(fpath, "r") as f:
        for row in f:
            domain = row.split(",")[1].strip("\n")
            domains_list.add(domain)
    return domains_list


# python3 server.py [out] [tranco_list]
if __name__ == "__main__":
   domains_list = load_domains(TRANCO_LIST)
   start_measure(domains_list)
  