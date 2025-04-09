from tkinter import *
from tkinter import messagebox, filedialog
from cryptography.fernet import Fernet
import hashlib
import base64
import os
import datetime
import pyperclip
import pyttsx3

user_password = ""

def get_fernet_key(password: str):
    hash = hashlib.sha256(password.encode()).digest()
    return base64.urlsafe_b64encode(hash)

def encrypt_message(message: str, password: str) -> str:
    fernet = Fernet(get_fernet_key(password))
    return fernet.encrypt(message.encode()).decode()

def decrypt_message(token: str, password: str) -> str:
    fernet = Fernet(get_fernet_key(password))
    return fernet.decrypt(token.encode()).decode()

def log_action(action, content_preview):
    with open("encryption_log.txt", "a") as log_file:
        log_file.write(f"{datetime.datetime.now()} | {action}: {content_preview[:30]}...\n")

def encrypt():
    password = code.get()
    if password == user_password:
        message = text1.get(1.0, END).strip()
        if not message:
            messagebox.showerror("Error", "Text box is empty.")
            return
        try:
            encrypted = encrypt_message(message, password)
            log_action("ENCRYPTED TEXT", message)

            screen1 = Toplevel(main_screen_window)
            screen1.title("Encrypted Text")
            screen1.geometry("400x250")
            screen1.configure(bg="#ff6f61")

            Label(screen1, text="ENCRYPTED", font="arial", fg="white", bg="#ff6f61").pack()
            text2 = Text(screen1, font="Roboto 10", bg="#ffe0e0", fg="black", wrap=WORD, bd=2)
            text2.pack(padx=10, pady=10, fill=BOTH, expand=True)
            text2.insert(END, encrypted)

            Button(screen1, text="Copy to Clipboard", command=lambda: pyperclip.copy(encrypted),
                   bg="#1089ff", fg="white").pack(pady=5)

            engine = pyttsx3.init()
            engine.say("Encryption complete")
            engine.runAndWait()
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {e}")
    else:
        messagebox.showerror("Error", "Invalid password")

def decrypt():
    password = code.get()
    if password == user_password:
        message = text1.get(1.0, END).strip()
        if not message:
            messagebox.showerror("Error", "Text box is empty.")
            return
        try:
            decrypted = decrypt_message(message, password)
            log_action("DECRYPTED TEXT", decrypted)

            screen2 = Toplevel(main_screen_window)
            screen2.title("Decrypted Text")
            screen2.geometry("400x250")
            screen2.configure(bg="#00b894")

            Label(screen2, text="DECRYPTED", font="arial", fg="white", bg="#00b894").pack()
            text2 = Text(screen2, font="Roboto 10", bg="#d0fff3", fg="black", wrap=WORD, bd=2)
            text2.pack(padx=10, pady=10, fill=BOTH, expand=True)
            text2.insert(END, decrypted)

            Button(screen2, text="Copy to Clipboard", command=lambda: pyperclip.copy(decrypted),
                   bg="#1089ff", fg="white").pack(pady=5)

            engine = pyttsx3.init()
            engine.say("Decryption complete. The decrypted text is:")
            engine.say(decrypted)
            engine.runAndWait()

        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {e}")
    else:
        messagebox.showerror("Error", "Invalid password")

def encrypt_file():
    password = code.get()
    if password == user_password:
        file_path = filedialog.askopenfilename(title="Select File to Encrypt")
        if file_path:
            with open(file_path, "rb") as file:
                file_data = file.read()
            fernet = Fernet(get_fernet_key(password))
            encrypted_data = fernet.encrypt(file_data)
            save_path = file_path + ".enc"
            with open(save_path, "wb") as enc_file:
                enc_file.write(encrypted_data)
            messagebox.showinfo("Success", f"File encrypted and saved at:\n{save_path}")
            log_action("ENCRYPTED FILE", os.path.basename(file_path))
    else:
        messagebox.showerror("Error", "Invalid password")

def decrypt_file():
    password = code.get()
    if password == user_password:
        file_path = filedialog.askopenfilename(title="Select File to Decrypt")
        if file_path:
            with open(file_path, "rb") as file:
                enc_data = file.read()
            fernet = Fernet(get_fernet_key(password))
            try:
                decrypted_data = fernet.decrypt(enc_data)
                if file_path.endswith(".enc"):
                    save_path = file_path.replace(".enc", "_decrypted.txt")
                else:
                    save_path = file_path + "_decrypted.txt"
                with open(save_path, "wb") as dec_file:
                    dec_file.write(decrypted_data)
                messagebox.showinfo("Success", f"File decrypted and saved at:\n{save_path}")
                log_action("DECRYPTED FILE", os.path.basename(file_path))
            except Exception:
                messagebox.showerror("Error", "Invalid encrypted file format or wrong password!")
    else:
        messagebox.showerror("Error", "Invalid password")

def reset():
    code.set("")
    text1.delete(1.0, END)

def reset_password():
    def save_new_password():
        global user_password
        pw1 = new_pass.get()
        pw2 = confirm_pass.get()
        if pw1 == "" or pw2 == "":
            messagebox.showerror("Error", "Please fill both fields")
        elif pw1 != pw2:
            messagebox.showerror("Error", "Passwords do not match")
        elif len(pw1) < 6:
            messagebox.showerror("Weak Password", "Password must be at least 6 characters")
        else:
            user_password = pw1
            messagebox.showinfo("Success", "Password reset successfully!")
            reset_win.destroy()

    reset_win = Toplevel(main_screen_window)
    reset_win.title("Reset Password")
    reset_win.geometry("300x200")
    reset_win.configure(bg="#f7c59f")

    Label(reset_win, text="New Password", font=("arial", 12), bg="#f7c59f").pack(pady=5)
    new_pass = StringVar()
    Entry(reset_win, textvariable=new_pass, show="*", font=("arial", 12), bg="#fff0e6").pack(pady=5)

    Label(reset_win, text="Confirm Password", font=("arial", 12), bg="#f7c59f").pack(pady=5)
    confirm_pass = StringVar()
    Entry(reset_win, textvariable=confirm_pass, show="*", font=("arial", 12), bg="#fff0e6").pack(pady=5)

    Button(reset_win, text="Save", command=save_new_password, bg="#1089ff", fg="white").pack(pady=10)

def animate_bg():
    colors = ["#ff9a9e", "#fad0c4", "#fbc2eb", "#a1c4fd", "#c2e9fb", "#d4fc79", "#96e6a1"]
    current = colors.pop(0)
    colors.append(current)
    canvas.configure(bg=current)
    main_screen_window.after(1500, animate_bg)

def main_screen():
    global main_screen_window, code, text1, canvas
    main_screen_window = Tk()
    main_screen_window.geometry("600x700")
    main_screen_window.title("EncryptionApp")

    canvas = Canvas(main_screen_window, width=600, height=700, highlightthickness=0)
    canvas.pack(fill="both", expand=True)

    animate_bg()

    Label(canvas, text="Enter text for encryption and decryption", fg="black", bg="#d0f4de", font=("calibri", 13)).place(x=10, y=10)
    text1 = Text(canvas, font="Roboto 15", bg="#fcefee", fg="black", wrap=WORD, bd=2)
    text1.place(x=10, y=40, width=580, height=200)

    Label(canvas, text="Enter your secret key:", fg="black", bg="#fcefee", font=("calibri", 13)).place(x=10, y=260)
    code = StringVar()
    Entry(canvas, textvariable=code, width=25, font=("arial", 18), show="*", bg="#fcefee").place(x=10, y=290)

    Button(canvas, text="ENCRYPT", height=2, width=23, bg="#e17055", fg="white", bd=0, command=encrypt).place(x=10, y=340)
    Button(canvas, text="DECRYPT", height=2, width=23, bg="#00b894", fg="white", bd=0, command=decrypt).place(x=300, y=340)

    Button(canvas, text="ENCRYPT FILE", height=2, width=23, bg="#f39c12", fg="white", bd=0, command=encrypt_file).place(x=10, y=400)
    Button(canvas, text="DECRYPT FILE", height=2, width=23, bg="#6c5ce7", fg="white", bd=0, command=decrypt_file).place(x=300, y=400)

    Button(canvas, text="RESET", height=2, width=50, bg="#1089ff", fg="white", bd=0, command=reset).place(x=10, y=460)
    Button(canvas, text="RESET PASSWORD", height=2, width=50, bg="#d63031", fg="white", bd=0, command=reset_password).place(x=10, y=520)

    main_screen_window.mainloop()

def set_password_screen():
    def save_password():
        global user_password
        pw1 = new_pass.get()
        pw2 = confirm_pass.get()
        if pw1 == "" or pw2 == "":
            messagebox.showerror("Error", "Please fill both fields")
        elif pw1 != pw2:
            messagebox.showerror("Error", "Passwords do not match")
        elif len(pw1) < 6:
            messagebox.showerror("Weak Password", "Password should be at least 6 characters.")
        else:
            user_password = pw1
            password_screen.destroy()
            main_screen()

    password_screen = Tk()
    password_screen.geometry("400x250")
    password_screen.title("Set Password")
    password_screen.configure(bg="#fab1a0")

    Label(password_screen, text="Set your password", font=("arial", 16), bg="#fab1a0").pack(pady=10)
    new_pass = StringVar()
    confirm_pass = StringVar()

    Entry(password_screen, textvariable=new_pass, show="*", font=("arial", 14), width=25, bg="#ffeaa7").pack(pady=5)
    Entry(password_screen, textvariable=confirm_pass, show="*", font=("arial", 14), width=25, bg="#ffeaa7").pack(pady=5)

    Button(password_screen, text="Set Password", command=save_password, bg="#00b894", fg="white", font=("arial", 12)).pack(pady=20)

    password_screen.mainloop()

set_password_screen()
