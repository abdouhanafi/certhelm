"""
DigiCert CertCentral REST helpers used by the automatic renewal workflow.

IMPORTANT - NOT VERIFIED AGAINST THE LIVE SERVICE. This code follows the public
CertCentral v2 API documentation (order/certificate/{product}, order status,
certificate download) but has only ever been exercised against a local fake
server. Ordering a certificate can be billed: run a first renewal against
DigiCert's demo environment (Paramètres → Renouvellement → URL de l'API) before
pointing the application at production.

Every function takes the HTTP transport as a parameter so tests can substitute
a fake and no real request ever leaves the machine by accident.
"""

import json
import re
import urllib.error
import urllib.request

DEFAULT_BASE_URL = "https://www.digicert.com/services/v2"
DEFAULT_VALIDITY_YEARS = 1
CSR_PLACEHOLDER = "<CSR généré sur le serveur par l'agent au moment de la commande>"

_PRODUCT_ID_RE = re.compile(r'^[a-z0-9_]+$')


class DigiCertError(Exception):
    """definitive=True means DigiCert answered with a 4xx error: the request was
    understood and refused, so nothing was created. definitive=False (network
    failure, timeout, 5xx) means we cannot know whether an order now exists."""

    def __init__(self, message, definitive=False):
        super().__init__(message)
        self.definitive = definitive


def default_http(method, url, api_key, body=None, timeout=20, accept="application/json"):
    """Returns (status_code, body_bytes). Network-level failures raise."""
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("X-DC-DEVKEY", api_key)
    req.add_header("Content-Type", "application/json")
    req.add_header("Accept", accept)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def _error_text(raw):
    try:
        errors = json.loads(raw.decode("utf-8", "ignore")).get("errors") or []
        return "; ".join(e.get("message") or e.get("code") or "?" for e in errors) or "erreur inconnue"
    except Exception:
        return raw.decode("utf-8", "ignore")[:200] or "erreur inconnue"


def _checked(status, raw):
    if 200 <= status < 300:
        return raw
    # 4xx = refused, nothing created. 5xx = the server may have acted before failing.
    raise DigiCertError(f"HTTP {status}: {_error_text(raw)}", definitive=400 <= status < 500)


def find_order_for_domain(orders, domain):
    """Most recent issued DigiCert order whose common name is this domain."""
    wanted = (domain or "").strip().lower()
    matches = [
        o for o in orders
        if o.get("status") == "issued"
        and ((o.get("certificate") or {}).get("common_name") or "").strip().lower() == wanted
    ]
    if not matches:
        return None
    return max(matches, key=lambda o: (o.get("certificate") or {}).get("valid_till") or "")


def build_renewal_request(order, csr_pem, validity_years=DEFAULT_VALIDITY_YEARS):
    """Builds (product_name_id, payload) for a renewal order of `order`. Pure - no I/O."""
    cert = order.get("certificate") or {}
    product = order.get("product") or cert.get("product") or {}
    name_id = product.get("name_id")
    if not name_id or not _PRODUCT_ID_RE.match(str(name_id)):
        raise DigiCertError("Produit DigiCert introuvable sur la commande d'origine", definitive=True)
    org_id = (order.get("organization") or {}).get("id")
    if org_id is None:
        raise DigiCertError("Organisation introuvable sur la commande d'origine", definitive=True)
    common_name = cert.get("common_name")
    if not common_name:
        raise DigiCertError("Nom commun introuvable sur la commande d'origine", definitive=True)
    dns_names = list(cert.get("dns_names") or [common_name])
    if common_name not in dns_names:
        dns_names.insert(0, common_name)

    payload = {
        "certificate": {
            "common_name": common_name,
            "dns_names": dns_names,
            "csr": csr_pem,
            "signature_hash": "sha256",
            "server_platform": {"id": -1},
        },
        "organization": {"id": int(org_id)},
        "validity_years": validity_years,
        "renewal_of_order_id": order.get("id"),
    }
    return name_id, payload


def describe_request(name_id, payload):
    """The request as it will be sent, with the CSR replaced by a placeholder -
    shown to the user before they confirm a renewal, and stored with the job."""
    described = json.loads(json.dumps(payload))
    described["certificate"]["csr"] = CSR_PLACEHOLDER
    return {"method": "POST", "endpoint": f"/order/certificate/{name_id}", "body": described}


def place_order(base_url, api_key, name_id, payload, http=default_http):
    """Places the renewal order. Returns the parsed DigiCert answer (has 'id')."""
    if not _PRODUCT_ID_RE.match(str(name_id)):
        raise DigiCertError("Identifiant de produit invalide", definitive=True)
    status, raw = http("POST", f"{base_url.rstrip('/')}/order/certificate/{name_id}", api_key, payload)
    result = json.loads(_checked(status, raw).decode("utf-8"))
    if not isinstance(result, dict) or not result.get("id"):
        raise DigiCertError("Réponse DigiCert sans numéro de commande", definitive=False)
    return result


def get_order(base_url, api_key, order_id, http=default_http):
    """Returns {'status': str, 'certificate_id': int|None} for an order."""
    if not re.match(r'^\d+$', str(order_id)):
        raise DigiCertError("Numéro de commande invalide", definitive=True)
    status, raw = http("GET", f"{base_url.rstrip('/')}/order/certificate/{order_id}", api_key)
    data = json.loads(_checked(status, raw).decode("utf-8"))
    return {"status": data.get("status", ""), "certificate_id": (data.get("certificate") or {}).get("id")}


def download_chain(base_url, api_key, certificate_id, http=default_http):
    """Leaf + intermediates in PEM (no root - servers don't need to send it)."""
    if not re.match(r'^\d+$', str(certificate_id)):
        raise DigiCertError("Identifiant de certificat invalide", definitive=True)
    status, raw = http("GET", f"{base_url.rstrip('/')}/certificate/{certificate_id}/download/format/pem_noroot",
                       api_key, accept="*/*")
    pem = _checked(status, raw).decode("utf-8", "ignore")
    if "-----BEGIN CERTIFICATE-----" not in pem:
        raise DigiCertError("Le certificat téléchargé n'est pas au format PEM", definitive=True)
    return pem
