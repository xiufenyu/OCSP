# Custom Definition
import subprocess

def invoke_subproc(cmd):
    output = subprocess.run(cmd, capture_output=True, shell=True)
    resp = output.stdout.decode("utf-8")
    error = output.stderr.decode("utf-8")
    return (resp, error)



BEGIN_CERTIFICATE = "-----BEGIN CERTIFICATE-----"
END_CERTIFICATE = "-----END CERTIFICATE-----"
OCSP_RESP_STAPLING_NO_RESPONSE_SENT = "OCSP response: no response sent"
# STAPLING_OUTPUT = "stapling_output"
NAME_OR_SERVICE_NOT_KNOWN = "Name or service not known"
NO_ADDRESS_ASSOCIATED_WITH_HOST_NAME = "No address associated with hostname"
NO_PEER_CERTIFICATE = "no peer certificate available"
TEMPORAY_FAILURE_IN_NAME_RESOLUTION = "Temporary failure in name resolution"
NO_CLIENT_CERTIFICATE_CA_NAMES_SENT = "No client certificate CA names sent"
UNAUTHORIZED = "Responder Error: unauthorized"

RESPONSE_VERIFY = "Response verify"
OCSP_STAPLING_STATUS = "Cert Status:"

VERIFY_ERROR = "verify error"
STAPLING_VERIFICATION_ERROR = "Verification error"
STAPLING_VERIFICATION_WORD = "Verification"

CA_ISSUERS = "CA Issuers"

OCSP_REVOCATION_REASON = "Revocation Reason"
REASON = "Reason"
CRL_REVOCATION_REASON = "CRL Reason Code"

CRL_SERIAL_NUMBER = "Serial Number"

# NOT_BEFORE_KEYWORD = "Not Before="
# NOT_AFTER_KEYWORD = "Not After="



# Database Attributes
DOMAIN = "domain"
SERIAL = "serial"
CERT_NAME = "cert_name"
CERT_ERROR = "cert_error"
DOWNLOAD_CERT = "download_cert"
DOWNLOAD_CERT_ERROR = "download_cert_failed"
# CERT_SERIAL = "cert_serial"
ISSUER_CERT = "issuer_cert"
ISSUER_CN = "issuer_cn"
STAPLING_STATUS = "stapling_status"
STAPLING_ERROR = "stapling_error"
STAPLING_RESP = "stapling_resp"
STAPLING_ERROR_MSG = "stapling_error_msg"
STAPLING_REASON = "stapling_reason"
STAPLING_VERIFICATION = "stapling_verification"
OCSP_URI = "ocsp_uri"
OCSP_VERIFY = "ocsp_verify"
OCSP_REVOKE = "ocsp_revoke"
OCSP_REASON = "ocsp_reason"
OCSP_ERROR = "ocsp_error"
OCSP_RESP = "ocsp_resp"
CRL_URI = "crl_uri"
CRL_STATUS = "crl_status"
CRL_REASON = "crl_reason"
CRL_ERROR = "crl_error"
CRL_RESP="crl_resp"
CRL_SIZE = "crl_size"

NOT_BEFORE = "not_before"
NOT_AFTER = "not_after"
VALIDITY = "validity"
TIME_STAMP = "ts"


# Values
STAPLING_NO_RESPONSE_SENT = "no_response_sent"
STATUS_GOOD = "good"
STATUS_REVOKED = "revoked"
SERIAL_NOT_IN_CRL = "serial_not_in_crl"
CRL_URI_IS_NONE = "crl_uri_is_none"
CRL_DOWNLOAD_FAILURE = "crl_download_failure"
ISSUER_IS_NONE = "issuer_is_none"


# 
EMPTY_STR = ""
CERT_CHAIN = "cert.chain"
FILE_CRL = "file.crl"
RESULT_JSON = "result.json"