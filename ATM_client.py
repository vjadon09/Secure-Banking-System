import tkinter as tk
from tkinter import ttk, messagebox
import actions
import json
import socket
import hmac
import hashlib
import base64
from datetime import datetime
from cryptography.fernet import Fernet

#Socket Setup
HOST_NAME = "localhost"
PORT_NUM = 15000
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((HOST_NAME, PORT_NUM))
print(sock.recv(1024).decode())

#Global Variables
user = ""
key1 = None
key2 = None

#Key Generation and Initial Transmission
key = Fernet.generate_key()
f = Fernet(key)
keystr = key.decode()
time = str(datetime.now())
sock.send(json.dumps({"action": actions.KEY, "KEY": keystr, "time": time}).encode())

#UI Setup
root = tk.Tk()
root.title("COE817 Secure ATM System")
root.geometry("400x400")
root.resizable(False, False)

style = ttk.Style()
style.configure("TButton", font=("Segoe UI", 10))
style.configure("TLabel", font=("Segoe UI", 10))
style.configure("Header.TLabel", font=("Segoe UI", 16, "bold"))

#Title
title_frame = ttk.Frame(root, padding=10)
title_frame.pack()
ttk.Label(title_frame, text="💳 Secure ATM System", style="Header.TLabel").pack()

#Login/Register Frame
auth_frame = ttk.LabelFrame(root, text="Login / Register", padding=20)
auth_frame.pack(pady=20)

ttk.Label(auth_frame, text="Username:").grid(row=0, column=0, sticky="e", pady=5)
username_entry = ttk.Entry(auth_frame, width=25)
username_entry.grid(row=0, column=1, pady=5)

ttk.Label(auth_frame, text="Password:").grid(row=1, column=0, sticky="e", pady=5)
password_entry = ttk.Entry(auth_frame, show="*", width=25)
password_entry.grid(row=1, column=1, pady=5)

#Main Transaction Frame (initialized later)
transaction_frame = ttk.LabelFrame(root, text="Transactions", padding=20)

def post_login():
    auth_frame.forget()
    transaction_frame.pack(pady=20)

    time = str(datetime.now())
    f1 = Fernet(key1)
    data = {"action": actions.BALANCE, "time": time}
    token = f1.encrypt(json.dumps(data).encode())
    sock.send(token)
    ogbalance = sock.recv(1024).decode()

    current_balance = ttk.Label(transaction_frame, text=f"Current Balance: ${ogbalance}", font=("Segoe UI", 12))
    current_balance.grid(row=0, column=0, columnspan=2, pady=10)

    ttk.Label(transaction_frame, text="Withdraw:").grid(row=1, column=0, pady=5)
    withdraw_entry = ttk.Entry(transaction_frame)
    withdraw_entry.grid(row=1, column=1, pady=5)

    ttk.Label(transaction_frame, text="Deposit:").grid(row=2, column=0, pady=5)
    deposit_entry = ttk.Entry(transaction_frame)
    deposit_entry.grid(row=2, column=1, pady=5)

    def confirm():
        global user, key1, key2
        withdraw_amount = withdraw_entry.get()
        deposit_amount = deposit_entry.get()
        time = str(datetime.now())

        if deposit_amount:
            data = {"action": actions.DEPOSIT, "amount": deposit_amount, "time": time}
        elif withdraw_amount:
            data = {"action": actions.WITHDRAW, "amount": withdraw_amount, "time": time}
        else:
            messagebox.showerror("Error", "Please enter an amount.")
            return

        encoded = json.dumps(data).encode()
        hmac_digest = hmac.new(key2, encoded, hashlib.sha256).digest()
        sig = base64.b64encode(hmac_digest).decode()

        data["sig"] = sig
        token = Fernet(key1).encrypt(json.dumps(data).encode())
        sock.send(token)

        new_balance = sock.recv(1024).decode()
        current_balance.configure(text=f"Current Balance: ${new_balance}")

    ttk.Button(transaction_frame, text="Confirm", command=confirm).grid(row=3, column=0, columnspan=2, pady=15)

#Authentication Logic
def login():
    global user, key1, key2
    username, password = username_entry.get(), password_entry.get()

    if not username or not password:
        messagebox.showerror("Error", "Please fill in all fields.")
        return

    data = {"action": actions.LOGIN, "username": username, "password": password, "time": time}
    token = f.encrypt(json.dumps(data).encode())
    sock.send(token)

    response = f.decrypt(sock.recv(1024)).decode()

    if response == "Error":
        messagebox.showerror("Login Failed", "Invalid credentials.")
    else:
        user = username
        response_data = json.loads(response)
        key1, key2 = response_data["key1"].encode(), response_data["key2"].encode()
        post_login()

def register():
    global user, key1, key2
    username, password = username_entry.get(), password_entry.get()

    if not username or not password:
        messagebox.showerror("Error", "Please fill in all fields.")
        return

    data = {"action": actions.REGISTER, "username": username, "password": password, "time": time}
    token = f.encrypt(json.dumps(data).encode())
    sock.send(token)

    response = f.decrypt(sock.recv(1024)).decode()

    if response == "Username already exists":
        messagebox.showerror("Error", "Username already exists.")
    else:
        response_data = json.loads(response)
        user = username
        key1, key2 = response_data["key1"].encode(), response_data["key2"].encode()
        post_login()

#Buttons
ttk.Button(auth_frame, text="Login", width=15, command=login).grid(row=3, column=0, pady=15)
ttk.Button(auth_frame, text="Register", width=15, command=register).grid(row=3, column=1, pady=15)

root.mainloop()
