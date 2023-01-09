import base64

user  = base64.b64decode(b'eW91cl91c2VybmFtZQ==')
passw  = base64.b64decode(b'eW91cl9wYXNzd29yZA==')

username = user.decode('utf-8')
passwd = passw.decode('utf-8')

