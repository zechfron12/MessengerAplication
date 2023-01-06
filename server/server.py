import socket
import threading
import rsa
import time
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

simple_key = get_random_bytes(32)
salt = simple_key
password = "mypassword"

key = PBKDF2(password, salt, dkLen=32)

message = b"Hello Secred world!"


def encrypt(message: bytes, key):
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv
    ciphered_data = cipher.encrypt(pad(message, AES.block_size))
    return iv + ciphered_data


def decrypt(message: bytes, key):
    iv = message[:16]
    decrypt_data = message[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    original = unpad(cipher.decrypt(decrypt_data), AES.block_size)
    return original


HOST = '127.0.0.1'
PORT = 1111
LISTENER_LIMIT = 10
active_clients = []


public_key, private_key = rsa.newkeys(2048)
public_key_client = None


def create_message_dic(sender, receiver, message_type, content):
    return {
        "sender": sender,
        "receiver": receiver,
        "type": message_type,
        "content": content
    }


def save_message(message):
    with open("server/database/history.txt", "a") as file_object:
        file_object.write(message + '\n')


def listen_for_messages(client, username):
    while 1:

        message = decrypt(client.recv(16394), key).decode()
        if message != '':
            dic = eval(message)
            if dic["receiver"] == "all":
                send_messages_to_all(message)
            else:
                send_message_to_user(dic["receiver"], message)
                send_message_to_client(client, str(dic), False)

        else:
            print(f"The message send from client {username} is empty")


def send_message_to_client(client, message, should_save=True):
    if should_save:
        save_message(message)

    client.sendall(encrypt(message.encode(), key))


def send_messages_to_all(message):
    save_message(message)
    for user in active_clients:
        send_message_to_client(user[1], message, should_save=False)


def is_user_logged(username):
    for active_client in active_clients:
        if username in active_client:
            return True
    return False


def send_message_to_user(username, message):
    dic = eval(message)
    if not is_user_logged:
        prompt_message = create_message_dic(
            'server', dic["sender"], "error", "User is not logged or it does not exist")
        send_message_to_user(dic["sender"], str(prompt_message))
    else:
        for active_client in active_clients:
            if username in active_client:
                send_message_to_client(active_client[1], message)


def send_history_to_client(username, client):
    with open("server/database/history.txt", "r") as file:
        content = ''
        for line in file:
            dic = eval(line)
            if (dic['receiver'] == username or dic['sender'] == username or dic['receiver'] == 'all') and dic['type'] != "informative":
                content += str(dic) + '\n'
        enc_dic = encrypt(content.encode(), key)
        client.sendall(b"STARTLOG~" + enc_dic + b"~ENDLOG")
        # send_message_to_client(client, "STARTLOG~"+content+"~ENDLOG", False)


def client_handler(client):
    message = client.recv(16384).decode()

    login_dic = eval(message)
    username = login_dic["sender"]
    client_key = rsa.PublicKey.load_pkcs1(login_dic["content"])
    if username != '':
        if is_user_logged(username):
            prompt_message = create_message_dic(
                'server', username, "login-error", f"{username} is already logged")
            send_message_to_client(client, str(prompt_message))
        else:
            print(key)
            client.send(rsa.encrypt(key, client_key))
            time.sleep(1)
            prompt_message = f"{username} added to the chat"
            active_clients.append((username, client))
            dic_to_send = create_message_dic(
                'server', "all", 'informative', prompt_message)
            send_messages_to_all(str(dic_to_send))
            send_history_to_client(username, client)
            threading.Thread(target=listen_for_messages,
                             args=(client, username)).start()
    else:
        print("Client username is empty")


def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server.bind((HOST, PORT))
        print(f"Running the server on {HOST} {PORT}")
    except:
        print(f"Unable to bind to host {HOST} and port {PORT}")

    server.listen(LISTENER_LIMIT)

    while 1:
        client, address = server.accept()
        print(f"Successfully connected to client {address[0]} {address[1]}")

        threading.Thread(target=client_handler, args=(client,)).start()


if __name__ == '__main__':
    main()
