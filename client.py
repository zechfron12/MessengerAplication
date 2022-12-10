# import required modules
import socket
import threading
import tkinter as tk
import emoji
from base64 import b64decode, b64encode
from tkinter import scrolledtext, messagebox ,filedialog
from PIL import Image, ImageTk

HOST = '127.0.0.1'
PORT = 1111

DARK_GREY = '#78246f'
MEDIUM_GREY = '#ffffff'
OCEAN_BLUE = '#724a6d'
BLACK = "black"
FONT = ("Helvetica", 17)
BUTTON_FONT = ("Helvetica", 15)
SMALL_FONT = ("Helvetica", 13)

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

def add_message(message):
    message_box.config(state=tk.NORMAL)
    message_box.insert(tk.END, emoji.emojize(message) + '\n')
    message_box.config(state=tk.DISABLED)
    
def add_image(image):
    message_box.config(state=tk.NORMAL)
    message_box.image_create(tk.END, image = sent_image)
    message_box.config(state=tk.DISABLED)

def connect():
    try:
        client.connect((HOST, PORT))
        print("Successfully connected to server")
        add_message("[SERVER] Successfully connected to the server")
    except:
        messagebox.showerror("Unable to connect to server", f"Unable to connect to server {HOST} {PORT}")

    username = username_textbox.get()
    if username != '':
        client.sendall(username.encode())
    else:
        messagebox.showerror("Invalid username", "Username cannot be empty")

    threading.Thread(target=listen_for_messages_from_server, args=(client, )).start()

    username_textbox.config(state=tk.DISABLED)
    username_button.config(state=tk.DISABLED)

def send_message():
    message = message_textbox.get()
    if message != '':
        client.sendall(message.encode())
        message_textbox.delete(0, len(message))
    else:
        messagebox.showerror("Empty message", "Message cannot be empty")
        
def send_image():
    path=filedialog.askopenfilename(filetypes=[("Image File",'.jpg')])
    
    image_handle = open(path, 'rb')
    raw_image_data = image_handle.read()
    
    encoded_data = b64encode(raw_image_data)
    # decoded_data = b64decode(encoded_data)
    
    print(encoded_data.decode("utf-8"))
    client.sendall(encoded_data)
    
    
    
    im = Image.open(path)
    global sent_image
    sent_image = ImageTk.PhotoImage(im)
    add_image(sent_image)
    
    
    

root = tk.Tk()
root.geometry("600x600")
root.title("Messenger Client")
root.resizable(False, False)

root.grid_rowconfigure(0, weight=1)
root.grid_rowconfigure(1, weight=4)
root.grid_rowconfigure(2, weight=1)

top_frame = tk.Frame(root, width=600, height=100, bg=DARK_GREY)
top_frame.grid(row=0, column=0, sticky=tk.NSEW)

middle_frame = tk.Frame(root, width=600, height=400, bg=MEDIUM_GREY)
middle_frame.grid(row=1, column=0, sticky=tk.NSEW)

bottom_frame = tk.Frame(root, width=600, height=100, bg=DARK_GREY)
bottom_frame.grid(row=2, column=0, sticky=tk.NSEW)

username_label = tk.Label(top_frame, text="Enter username:", font=FONT, bg=DARK_GREY, fg=BLACK)
username_label.pack(side=tk.LEFT, padx=10)

username_textbox = tk.Entry(top_frame, font=FONT, bg=MEDIUM_GREY, fg=BLACK, width=23)
username_textbox.pack(side=tk.LEFT)

username_button = tk.Button(top_frame, text="Join", font=BUTTON_FONT, bg=OCEAN_BLUE, fg=BLACK, command=connect)
username_button.pack(side=tk.LEFT, padx=15)

message_textbox = tk.Entry(bottom_frame, font=FONT, bg=MEDIUM_GREY, fg=BLACK, width=28)
message_textbox.pack(side=tk.LEFT, padx=10)

message_button = tk.Button(bottom_frame, text=emoji.emojize("Send"), font=BUTTON_FONT, bg=OCEAN_BLUE, fg=BLACK, command=send_message)
message_button.pack(side=tk.LEFT, padx=10)


send_image_button= tk.Button(bottom_frame, text= "Send Image", font=BUTTON_FONT, bg=OCEAN_BLUE, fg=BLACK, command=send_image)
send_image_button.pack(side= tk.LEFT)

message_box = scrolledtext.ScrolledText(middle_frame, font=SMALL_FONT, bg=MEDIUM_GREY, fg=BLACK, width=67, height=26.5)
message_box.config(state=tk.DISABLED)
message_box.pack(side=tk.TOP)


def listen_for_messages_from_server(client):

    while 1:

        message = client.recv(2048).decode()
        if message != '':
            username = message.split("~")[0]
            content = message.split('~')[1]

            add_message(f"[{username}] {content}")
            
        else:
            messagebox.showerror("Error", "Message recevied from client is empty")

# main function
def main():

    root.mainloop()
    
if __name__ == '__main__':
    main()