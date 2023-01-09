import base64

#passw  = base64.b64decode(b'T0JvRk8yS21VZmtyQzhsZEx1SUE=')
user  = base64.b64decode(<user_base64_token>)
passw  = base64.b64decode(<insert_base64_token>)

#username = "API-CPI"
username = user.decode('utf-8')
passwd = passw.decode('utf-8')

