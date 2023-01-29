import requests

data = {
    "email": "example@email.com",
    "password": "mypassword"
}

response = requests.post("http://localhost:10001/auth/register", json=data)
print(response.json())
