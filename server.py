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
NOT_DEFINED = "not_defined"

RESPONSE_VERIFY = "Response verify"

BEGIN_CERTIFICATE = "-----BEGIN CERTIFICATE-----"
END_CERTIFICATE = "-----END CERTIFICATE-----"

EMPTY_STR = ""
CERT_CHAIN = "cert.chain"
FILE_CRL = "file.crl"


DOMAIN = "domain"
STAPLING_STATUS = "stapling_status"
OCSP_VERIFY = "ocsp_verify"
OCSP_REVOKE = "ocsp_revoke"
CRL_STATUS = "crl_status"



OUT = sys.argv[1]
TRANCO_LIST = sys.argv[2]

# TODO:
class CertificateManager:
    def download_certchain(self, domain):
        dir_out = os.path.join(OUT, domain)
        if not os.path.exists(dir_out):
            os.makedirs(dir_out)
        cmd = f"echo | openssl s_client -showcerts -connect {domain}:443 2>&1 | sed --quiet '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' > {dir_out}/{CERT_CHAIN}"
        subprocess.run(cmd, stdout=subprocess.PIPE, shell=True).stdout.decode('utf-8')
        return os.path.join(dir_out, CERT_CHAIN)
    

    def split_certchains(self, cert_path):
        cmd = f"openssl storeutl  -certs {cert_path}"
        output = subprocess.run(cmd, stdout=subprocess.PIPE, shell=True).stdout.decode('utf-8')
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
        issuer_name = subprocess.run(cmd_issuer, stdout=subprocess.PIPE, shell=True).stdout.decode('utf-8')
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
            subject_name = subprocess.run(cmd_subject, stdout=subprocess.PIPE, shell=True).stdout.decode('utf-8')
            subject_name = subject_name.split("subject=")[1]
            if issuer_name == subject_name:
                issuer_cert = cert
                break
        return issuer_cert
    

    def get_oscp_uri(self, cert_path):
        cmd_uri = f"openssl x509 -in {cert_path} -noout -ocsp_uri"
        ocsp_uri = subprocess.run(cmd_uri, stdout=subprocess.PIPE, shell=True).stdout.decode('utf-8')
        print(cert_path, ", ocsp_uri:" + ocsp_uri)
        return ocsp_uri


    def get_serial(self, cert_path):
        cmd_serial = f"openssl x509 -in {cert_path} -noout -serial"
        response = subprocess.run(cmd_serial, capture_output=True, shell=True).stdout.decode("utf-8")
        serial = response.split("serial=")[1]
        print(cert_path + ", serial:" + serial)
        return serial


    def detect_crl_revoked(self, crl_path, serial):
        # print(crl_path, serial)
        cmd = f"openssl crl -in {crl_path} -inform DER -text -noout | grep {serial}"
        response = subprocess.run(cmd, capture_output=True, shell=True).stdout.decode("utf-8")
        # print(response)
        status = REVOKED if response is not EMPTY_STR else NOT_DEFINED
        print("crl_status:" + status)
        return status



class OSCPServer:
    def __init__(self):
        self.cert_mgr = CertificateManager()


    def ocsp_stapling(self, domain):
        status = None
        cmd = f"echo | openssl s_client -connect {domain}:443 -status"
        output = subprocess.run(cmd, stdout=subprocess.PIPE, shell=True).stdout.decode('utf-8')
        output_list = output.split("\n")
        for line in output_list:
            if OCSP_STAPLING_NOT_SUPPORT_STR in line:
                print(domain + ":" + OCSP_STAPLING_NOT_SUPPORT_STR)
                status = OCSP_STAPLING_NOT_SUPPORT_STR
                break
            elif OCSP_STAPLING_STATUS in line:
                status = line.split(":")[1]
                print(domain, status)
        if status is None:
            print("❌", output)
        print("ocsp_stapling=" + status)
        return status


    def ocsp_revocation(self, domain):
        cert_mgr = self.cert_mgr
        cert_mgr.download_certchain(domain)
    
        dir_out = os.path.join(OUT, domain)
        if not os.path.exists(dir_out):
            print(domain, ": download certificate failed")
            return

        cert_path = os.path.join(dir_out, CERT_CHAIN)
        ocsp_uri = cert_mgr.get_oscp_uri(cert_path)

        issuer_cert = cert_mgr.extract_issuer_cert(domain, cert_path)
        if issuer_cert is None:
            print("❌ " + domain + ": no issuer")
            return 

        # Make the OCSP request
        cmd_ocsp = f"openssl ocsp -issuer {issuer_cert} -cert {cert_path} -text -url {ocsp_uri}"
        response = subprocess.run(cmd_ocsp, capture_output=True, shell=True)
        stdout_resp = response.stdout.decode("utf-8").split("\n")
        stderr_resp = response.stderr.decode("utf-8").split("\n")
        verify_status = None
        revoked_status = None
        for line in stdout_resp:
            if cert_path in line:
                revoked_status = line.split(": ")[1]
            if RESPONSE_VERIFY in line:
                verify_status = line.split(RESPONSE_VERIFY)[1].strip()
                break
        if verify_status is None:
            for line in stderr_resp:
                if RESPONSE_VERIFY in line:
                    verify_status = line.split(RESPONSE_VERIFY)[1].strip()
                    break
        
        print("OSCP verify:" +verify_status + ", revoke:" +revoked_status)
        return (verify_status, revoked_status)
    

    def crl_revocation(self, domain):
        dir_out = os.path.join(OUT, domain)
        cert_path = os.path.join(dir_out, CERT_CHAIN)
        cert_mgr = self.cert_mgr
        if not os.path.exists(cert_path):
            cert_path = cert_mgr.download_certchain(domain)
        
        cmd_crl = f"openssl x509 -in {cert_path} -noout -text | grep -A 5 CRL"
        response = subprocess.run(cmd_crl, capture_output=True, shell=True).stdout.decode("utf-8")
        URI = None
        for line in response.split("\n"):
            line = line.strip()
            if line.startswith("URI:"):
                URI = line.split("URI:")[1]
                break
        crl_path = os.path.join(dir_out, FILE_CRL)
        issuer_cert = cert_mgr.extract_issuer_cert(domain, cert_path)
        if URI is not None:
            os.system(f"wget {URI} -O {FILE_CRL}")

            # TODO: verify crl file
            # cmd_verify = f"openssl crl -in {crl_path} -inform DER -CAfile {issuer_cert} -noout"
            # response = subprocess.run(cmd_verify, capture_output=True, shell=True).stdout.decode("utf-8")
            # print("!!!!!!!!!!!!", response)
            serial = cert_mgr.get_serial(cert_path)
            status = cert_mgr.detect_crl_revoked(crl_path, serial)
            return status
        else:
            print(domain + ": URI is None")
            return None
        


def measure_top1m():
    server = OSCPServer()
    with open(TRANCO_LIST, "r") as f:
        for row in f:
            domain = row.split(",")[1].strip("\n")
            staple_status = server.ocsp_stapling(domain)
            (ocsp_verify, ocsp_revoked) = server.ocsp_revocation(domain)
            crl_status = server.crl_revocation(domain)
            result = {DOMAIN: domain, STAPLING_STATUS: staple_status,
                      OCSP_VERIFY: ocsp_verify, OCSP_REVOKE: ocsp_revoked,
                      CRL_STATUS: crl_status}
            result_file = os.path.join(OUT, domain, "result.json")
            with open(result_file, "w") as f:
                json.dump(result, f)
            break
            time.sleep(1)


if __name__ == "__main__":
    measure_top1m()    



# cmd_uri = f"openssl x509 -in {cert_path} -noout -ocsp_uri"
# ocsp_uri = subprocess.run(cmd_uri, stdout=subprocess.PIPE, shell=True).stdout.decode('utf-8')
# logging.info(domain + ", ocsp_uri:" + ocsp_uri)

# cmd_issuer = f"openssl x509 -in {cert_path} -noout -issuer"
# issuer_name = subprocess.run(cmd_issuer, stdout=subprocess.PIPE, shell=True).stdout.decode('utf-8')
# issuer_name = issuer_name.split("issuer=")[1]
# logging.info(domain+", issuer: "+issuer_name)

# cert_mgr.split_certchains(cert_path)

# cert_files = glob(os.path.join(dir_out, "cert_*.crt"))
# issuer_cert = None
# for cert in cert_files:
#     (number, ) = parse("cert_{}.crt", os.path.basename(cert))
#     if number == "0":
#         continue
#     cmd_subject = f"openssl x509 -in {cert} -noout -subject"
#     subject_name = subprocess.run(cmd_subject, stdout=subprocess.PIPE, shell=True).stdout.decode('utf-8')
#     subject_name = subject_name.split("subject=")[1]
#     if issuer_name == subject_name:
#         issuer_cert = cert
#         break