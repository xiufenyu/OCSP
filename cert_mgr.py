import os
import sys
from glob import glob
from parse import parse

from datetime import datetime


from constants import invoke_subproc

from constants import NOT_BEFORE, NOT_AFTER, VALIDITY


from constants import END_CERTIFICATE
from constants import STAPLING_VERIFICATION_ERROR, STAPLING_VERIFICATION_WORD
from constants import CA_ISSUERS

from constants import ISSUER_CERT, ISSUER_CN
from constants import OCSP_URI
from constants import CRL_STATUS, CRL_REASON, CRL_RESP


# RESPONSE RESULT
from constants import SERIAL_NOT_IN_CRL
from constants import STATUS_REVOKED
from constants import OCSP_REVOCATION_REASON, CRL_REVOCATION_REASON, REASON
from constants import CRL_SERIAL_NUMBER
from constants import REVOCATION_TIME, THIS_UPDATE, NEXT_UPDATE

from constants import EMPTY_STR, CERT_CHAIN


ZERO = 0
OUT = sys.argv[1]


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
        resp, error = invoke_subproc(cmd_issuer)
        issuer_name = resp.split("issuer=")[1]
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
        # print(cert_path + ", serial:" + serial)
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
        if not os.path.exists(issuer_path):
            return None

        if os.path.getsize(issuer_path) == ZERO:
            print("❌ Download issuer certificate failure")
            os.system(f"rm -f {issuer_path}")
            return None

        return issuer_path


    def get_stapling_verification(self, resp_list):
        verification = None
        for row in resp_list:
            if STAPLING_VERIFICATION_ERROR in row or STAPLING_VERIFICATION_WORD in row:
                verification = row.split(":")[1].strip("\n").strip()
                break
        return verification


    def get_OCSP_revocation_reason(self, resp_list):
        reason = None
        for row in resp_list:
            if OCSP_REVOCATION_REASON in row or REASON in row:
                reason = row.split(":")[1].strip("\n").strip()
                break
        return reason


    def get_crl_revocation_reason(self, crl_path, serial):
        if serial is None:
            return None
        crl_output = []
        cmd = f"openssl crl -in {crl_path} -inform DER -text -noout"
        response, error = invoke_subproc(cmd)
        status = None
        resp_list = response.split("\n")
        this_cert_resp = []
        for row in resp_list:
            if serial in row:
                status = STATUS_REVOKED
                this_cert_resp.append(row)
                continue
            if status is not None:
                if CRL_SERIAL_NUMBER in row:
                    break
                this_cert_resp.append(row)
        if this_cert_resp != STATUS_REVOKED:
            status = SERIAL_NOT_IN_CRL

        # Get the revocation reason
        b_match = False
        reason = None
        for row in this_cert_resp:
            if CRL_REVOCATION_REASON in row:
                b_match = True
                continue
            if b_match:
                reason = row.strip("\n").strip()
                break
        return {CRL_REASON: reason, CRL_RESP: this_cert_resp}

    
    def extract_expiry(self, cert_path):
        cmd = f"openssl x509 -in {cert_path} -noout -startdate"
        response, error = invoke_subproc(cmd)
        not_before = response.split("=")[1].strip("\n").lstrip()

        cmd = f"openssl x509 -in {cert_path} -noout -enddate"
        resp, error = invoke_subproc(cmd)
        not_after = resp.split("=")[1].strip("\n").lstrip()

        validity = self.extract_validity(not_before, not_after)

        return {NOT_BEFORE: not_before, NOT_AFTER: not_after, VALIDITY: validity}

    
    def extract_validity(self, not_before, not_after):
        if not_before is None or not_after is None:
            return None
        # Jul 12 01:35:31 2021 GMT

        notbefore = datetime.strptime(not_before, "%b %d %H:%M:%S %Y %Z")
        notafter = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")

        return (notafter-notbefore).days


    def extract_issuer_authority(self, cert_path):
        cmd = f"openssl x509 -in {cert_path} -noout -text | grep Issuer:"
        response, error = invoke_subproc(cmd)
        # issuer_cn = None
        # if "CN = " in response:
        #     issuer_cn = response.split("CN = ")[1].lstrip().rstrip()
        #     issuer_cn = ",".join()
        # return issuer_cn

        issuer_o = None
        if "O = " in response:
            issuer_o = response.split("O = ")[1].lstrip().rstrip()
            delimiter = ","
            if issuer_o.startswith('"'):
                delimiter = '",'
            issuer_o = issuer_o.split(delimiter)[0]

        return issuer_o
        #   Issuer: C = US, O = Amazon, CN = Amazon RSA 2048 M02


    def get_revocation_time(self, resp_list):
        revo_time = None
        for row in resp_list:
            if REVOCATION_TIME in row:
                revo_time = row.split(REVOCATION_TIME)[1]
                break
        return revo_time


    def get_this_update(self, resp_list):
        this_update = None
        for row in resp_list:
            # print("This Update", THIS_UPDATE, "row=", row)
            if THIS_UPDATE in row:
                this_update = row.split(THIS_UPDATE)[1]
                break
        return this_update


    def get_next_update(self, resp_list):
        next_update = None
        for row in resp_list:
            if NEXT_UPDATE in row:
                next_update = row.split(NEXT_UPDATE)[1]
                break
        return next_update
