import urllib.request, urllib.error, json

data = json.dumps({"username": "filip", "password": "B3zpi3czn3997@"}).encode()
req_login = urllib.request.Request("http://127.0.0.1:8000/login", data=data, headers={"Content-Type": "application/json"})

with urllib.request.urlopen(req_login) as resp:
    token = json.loads(resp.read().decode())["access_token"]

print(f"Pobrano token dla roli 'user': {token[:30]}...")

req_admin = urllib.request.Request("http://127.0.0.1:8000/admin/dashboard", headers={"Authorization": f"Bearer {token}"})

try:
    urllib.request.urlopen(req_admin)
except urllib.error.HTTPError as e:
    print(f"Status HTTP: {e.code} {e.reason}")
    print(f"Odpowiedz serwera: {e.read().decode()}")
