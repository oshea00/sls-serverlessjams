import os
import json

from six.moves.urllib.request import urlopen
from jose import jwt

AUTH0_DOMAIN = os.environ.get("AUTH0_DOMAIN")
AUTH0_API_ID = os.environ.get("AUTH0_API_ID")

def handler(event, context):
    print(event)
    print(context)
    token = get_token(event)
    id_token = verify_token(token)
    print(id_token)
    if id_token and id_token.get('permissions'):
        scopes = '|'.join(id_token['permissions'])
        policy = generate_policy(
            id_token['sub'], 
            'Allow', 
            event['methodArn'],
            scopes=scopes
        )
        return policy
    else:
        policy = generate_policy(
            id_token['sub'],
            "Deny",
            event['methodArn']
        )
        return policy

def generate_policy(principal_id, effect, resource, scopes=None):
    policy = {
        'principalId': principal_id,
        'policyDocument': {
            'Version': '2012-10-17',
            'Statement': [
                {
                    "Action": "execute-api:Invoke",
                    "Effect": effect,
                    "Resource": resource
                }
            ]
        }
    }
    if scopes:
        policy['context'] = {'scopes': scopes}
    return policy

def get_token(event):
    # whole_auth_token should look like:
    # "Bearer SOME_CODE_GIBBERISH6r712fyasd.othergibberish.finalgibberish"
    whole_auth_token = event.get('authorizationToken')
    print('Client token: ' + whole_auth_token)
    print('Method ARN: ' + event['methodArn'])
    if not whole_auth_token:
        raise Exception('Unauthorized')
    token_parts = whole_auth_token.split(' ')
    auth_token = token_parts[1]
    token_method = token_parts[0]
    if not (token_method.lower() == 'bearer' and auth_token):
        print("Failing due to invalid token_method or missing auth_token")
        raise Exception('Unauthorized')
    # At this point we've confirmed the token format looks ok
    # So return the unverified token
    return auth_token

def verify_token(token):
    # Validate the token to make sure it's authentic
    jsonurl = urlopen("https://"+AUTH0_DOMAIN+"/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())
    # This currently expects the token to have three distinct sections 
    # each separated by a period.
    unverified_header = jwt.get_unverified_header(token)
    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }
    if rsa_key:
        try:  # to validate the jwt
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=["RS256"],
                audience=AUTH0_API_ID,
                issuer="https://"+AUTH0_DOMAIN+"/"
            )
            print("token validated successfully")
            return payload
        except jwt.ExpiredSignatureError:
            print("Token is expired")
            raise Exception('Unauthorized')
        except jwt.JWTClaimsError:
            print("Token has invalid claims")
            raise Exception('Unauthorized')
        except Exception:
            print("Unable to parse token")
            raise Exception('Unauthorized')
        