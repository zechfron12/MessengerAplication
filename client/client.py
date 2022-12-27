# import required modules
import sys
import socket
import threading
import emoji
import io
import tkinter as tk
from base64 import b64encode, b64decode
from tkinter import scrolledtext, messagebox, filedialog
from PIL import Image, ImageTk

HOST = '127.0.0.1'
PORT = 1111

DEEP_PURPLE = '#78246f'
WHITE = '#ffffff'
LIGH_PURPLE = '#724a6d'
BLACK = "black"
FONT = ("Helvetica", 17)
BUTTON_FONT = ("Helvetica", 15)
SMALL_FONT = ("Helvetica", 13)

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)


def create_message_dic(sender, receiver, message_type, content):
    return {
        "sender": sender,
        "receiver": receiver,
        "type": message_type,
        "content": content
    }


def add_message(message):
    message_box.config(state=tk.NORMAL)
    message_box.insert(tk.END, emoji.emojize(message) + '\n')
    message_box.config(state=tk.DISABLED)


def connect():
    try:
        client.connect((HOST, PORT))
        print("Successfully connected to server")
        add_message("[SERVER] Successfully connected to the server")
    except:
        messagebox.showerror("Unable to connect to server",
                             f"Unable to connect to server {HOST} {PORT}")

    global username
    username = sys.argv[1]
    dic = create_message_dic(username, "server", "login", username)
    client.sendall(str(dic).encode())

    threading.Thread(target=listen_for_messages_from_server,
                     args=(client,)).start()


def send_text():
    message = message_textbox.get()

    if message != '':
        dic = create_message_dic(
            username, field_receiver.get() if field_receiver.get() != '' else 'all', "message", message)

        client.sendall(str(dic).encode())
        message_textbox.delete(0, len(message))
    else:
        messagebox.showerror("Empty message", "Message cannot be empty")


def send_image():
    path = filedialog.askopenfilename(filetypes=[("Image File", '.jpg')])

    image_handle = open(path, 'rb')
    raw_image_data = image_handle.read()

    encoded_data = b64encode(raw_image_data)

    dic = create_message_dic(
        username, field_receiver.get(), "image", encoded_data)
    client.sendall(str(dic).encode())
    im = Image.open(path)


def handle_img_received(b64image):
    raw_data = b64decode(b64image)
    stream = io.BytesIO(raw_data)
    img = Image.open(stream)

    global recv_img
    recv_img = ImageTk.PhotoImage(img)

    message_box.config(state=tk.NORMAL)
    message_box.image_create(tk.END, image=recv_img)
    message_box.config(state=tk.DISABLED)


def listen_for_messages_from_server(client):
    while 1:
        message = client.recv(16384).decode()
        if message != '':
            dic_received = eval(message)

            if dic_received["type"] == "login-error":
                messagebox.showerror(
                    "Server:", dic_received["content"])
                break

            if dic_received["type"] == "error":
                messagebox.showerror(
                    "Server:", dic_received["content"])

            sender = dic_received["sender"]
            receiver = dic_received["receiver"]
            content = dic_received["content"]

            if dic_received["type"] == "image":
                add_message(f"[From: {sender}][To: {receiver}]")
                handle_img_received(content)
            else:
                add_message(f"[From: {sender}][To: {receiver}] {content}")

        else:
            messagebox.showerror(
                "Error", "Message recevied from client is empty")


def onMessageReturnPress(*arg):
    send_text()


root = tk.Tk()
root.geometry("600x600")
root.title("Messenger Client")
root.resizable(False, False)

root.grid_rowconfigure(0, weight=1)
root.grid_rowconfigure(1, weight=4)
root.grid_rowconfigure(2, weight=1)

top_frame = tk.Frame(root, width=600, height=100, bg=DEEP_PURPLE)
top_frame.grid(row=0, column=0, sticky=tk.NSEW)

middle_frame = tk.Frame(root, width=600, height=400, bg=WHITE)
middle_frame.grid(row=1, column=0, sticky=tk.NSEW)

bottom_frame = tk.Frame(root, width=600, height=100, bg=DEEP_PURPLE)
bottom_frame.grid(row=2, column=0, sticky=tk.NSEW)

username_label = tk.Label(
    top_frame, text="Send message to:", font=FONT, bg=DEEP_PURPLE, fg=BLACK)
username_label.pack(side=tk.LEFT, padx=10)

field_receiver = tk.StringVar(value="all")
receiver_textbox = tk.Entry(
    top_frame, font=FONT, bg=WHITE, fg=BLACK, width=23, textvariable=field_receiver)
receiver_textbox.pack(side=tk.LEFT)

message_textbox = tk.Entry(bottom_frame, font=FONT,
                           bg=WHITE, fg=BLACK, width=28)
message_textbox.bind('<Return>', onMessageReturnPress)
message_textbox.pack(side=tk.LEFT, padx=10)

message_button = tk.Button(bottom_frame, text=emoji.emojize(
    "Send"), font=BUTTON_FONT, bg=LIGH_PURPLE, fg=BLACK, command=send_text)
message_button.pack(side=tk.LEFT, padx=10)

send_image_button = tk.Button(bottom_frame, text="Send Image",
                              font=BUTTON_FONT, bg=LIGH_PURPLE, fg=BLACK, command=send_image)
send_image_button.pack(side=tk.LEFT)

message_box = scrolledtext.ScrolledText(
    middle_frame, font=SMALL_FONT, bg=WHITE, fg=BLACK, width=67, height=26.5)
message_box.config(state=tk.DISABLED)
message_box.pack(side=tk.TOP)


# main function
def start_gui():
    root.mainloop()


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Please insert the correct format")
    else:
        connect()
        start_gui()
