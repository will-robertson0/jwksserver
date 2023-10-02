import json
from django.http import JsonResponse, HttpResponseBadRequest, HttpResponseServerError, HttpResponse
from django.views.decorators.http import require_POST
from django.views.decorators.csrf import csrf_exempt
from datetime import datetime
from .models import JWK
import jwt

# utility function to get a valid key from the database
def get_valid_key():
    now = datetime.now()
    try:
        return JWK.objects.get(expiry_timestamp__gt=now)
    except JWK.DoesNotExist:
        return None

# JWKS endpoint view
def jwks_view(request):
    keys = JWK.objects.all().filter(expiry_timestamp__gt=datetime.now())
    jwks = {
        "keys": [{"kid": key.kid, "kty": "RSA", "alg": "RS256", "use": "sig", "n": key.public_key} for key in keys]
    }
    return JsonResponse(jwks)

# /auth endpoint view
@csrf_exempt
@require_POST
def auth_view(request):
    # mock authentication (replace with real authentication logic)
    username = request.POST.get("username")
    password = request.POST.get("password")

    if username == "userABC" and password == "password123":
        # authentication successful, issue a JWT
        key = get_valid_key()
        if key:
            # create a JWT using PyJWT library
            payload = {"sub": username}
            jwt_token = jwt.encode(payload, key.public_key, algorithm="RS256", headers={"kid": key.kid})
            return JsonResponse({"token": jwt_token.decode("utf-8")})
        else:
            # no valid keys available for signing
            return HttpResponseServerError("No valid keys available for signing.", status=500)
    else:
        # authentication failed
        return HttpResponse("Authentication failed.", status=401)
