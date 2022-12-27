# Import required modules
import socket
import threading

HOST = '127.0.0.1'
PORT = 1111
LISTENER_LIMIT = 5
active_clients = []


def create_message_dic(sender, receiver, message_type, content):
    return {
        "sender": sender,
        "reveicer": receiver,
        "type": message_type,
        "content": content
    }


def save_message(message):
    with open("server/database/history.txt", "a") as file_object:
        file_object.write(message + '\n')


def listen_for_messages(client, username):
    while 1:

        message = client.recv(16394).decode()

        if message != '':
            send_messages_to_all(message)

        else:
            print(f"The message send from client {username} is empty")


def send_message_to_client(client, message):
    save_message(message)
    client.sendall(message.encode())


def send_messages_to_all(message):
    for user in active_clients:
        send_message_to_client(user[1], message)


def is_user_already_logged(username):
    for client in active_clients:
        if username in client:
            return True
    return False


def client_handler(client):
    message = client.recv(16384).decode()

    login_dic = eval(message)
    username = login_dic["sender"]
    if username != '':
        if is_user_already_logged(username):
            prompt_message = create_message_dic(
                'server', username, "error", f"{username} is already logged")
            send_message_to_client(client, prompt_message)
        else:
            prompt_message = "SERVER~" + f"{username} added to the chat"
            active_clients.append((username, client))
            dic_to_send = create_message_dic(
                'server', "all", 'informative', prompt_message)
            send_messages_to_all(str(dic_to_send))
            threading.Thread(target=listen_for_messages,
                             args=(client, username,)).start()
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
