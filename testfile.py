import tkinter as tk
from PIL import Image, ImageTk
import os
import re
import webbrowser
from tkinter import messagebox
import random
import string
import smtplib
from email.mime.text import MIMEText
import customtkinter as ctk
import requests
import platform
import sys
import subprocess
import tkinter.font as tkfont
import tkextrafont


VIRUSTOTAL_API_KEY = "5b771ea6fe0db333f9c2b37c677ad67faba29e9b9831a6d4a59dc130657bdf51"


window = ctk.CTk()
window.title("Malicious Website Blocker")
window.geometry("400x500")
window.config(bg="#222222")

# --------------------------- helpers --------------------------------
# Function to generate a random password
def open_hosts_file():
    system_name = platform.system()
    
    if system_name == "Windows":
        hosts_path = r"C:\Windows\System32\drivers\etc\hosts"
        # Open in Notepad
        try:
            subprocess.Popen(["notepad.exe", hosts_path])
        except Exception as e:
            print("Failed to open hosts file:", e)
    
    elif system_name == "Linux":
        hosts_path = "/etc/hosts"
        try:
            # Use xdg-open to open in default text editor
            subprocess.Popen(["xdg-open", hosts_path])
        except Exception as e:
            print("Failed to open hosts file:", e)
    
    elif system_name == "Darwin":  # macOS
        hosts_path = "/etc/hosts"
        try:
            subprocess.Popen(["open", "-a", "TextEdit", hosts_path])
        except Exception as e:
            print("Failed to open hosts file:", e)
    
    else:
        print(f"Unsupported OS: {system_name}")

def generate_password(length=12):
    chars = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(chars) for _ in range(length))

def is_valid_email(email):
    """Check if the email is in a valid format"""
    pattern = r"^[\w\.-]+@[\w\.-]+\.\w+$"
    return re.match(pattern, email) is not None

password = ''

def send_email():
    recipient = entry_email.get().strip()
    global password
    password = generate_password()
    
    if not recipient:
        messagebox.showerror("Error", "Please enter your email address.")
        return
    
    if not is_valid_email(recipient):
        messagebox.showerror("Error", "Please enter a valid email address.")
        return

    # Your sender email credentials
    sender_email = "mrgilli1514@gmail.com"       
    sender_password = "vsgz qreg nhfy ilzo"       

    subject = "Your Generated Password"
    body = f"Hello,\n\nHere is your randomly generated password:\n\n{password}\n\nKeep it safe!"

    # Prepare the email message
    msg = MIMEText(body)
    msg['From'] = sender_email
    msg['To'] = recipient
    msg['Subject'] = subject

    try:
        # Connect to Gmail SMTP server
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(sender_email, sender_password)
        server.send_message(msg)
        server.quit()
        messagebox.showinfo("Success", f"A password has been sent to {recipient}")
    except smtplib.SMTPAuthenticationError:
        messagebox.showerror("Error", "Failed to login. Check your email and App Password.")
    except smtplib.SMTPRecipientsRefused:
        messagebox.showerror("Error", f"The recipient email '{recipient}' was refused.")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to send email:\n{e}")

def open_file():
    if getattr(sys, 'frozen', False):
        base_path = sys._MEIPASS  # PyInstaller exe
    else:
        base_path = os.path.dirname(os.path.abspath(__file__))  # Script folder

    file_path = os.path.join(base_path, "info.pdf")
    if os.path.exists(file_path):
        webbrowser.open(f"file://{file_path}")
    else:
        print("File not found:", file_path)

def show_url_popup():
    urls = [
        "http://malicious-example1.com",
        "http://malicious-example2.com",
        "http://phishing-site.com",
        "http://dangerous-site.net",
        "http://suspicious-link.org"
    ]
    # Create a new popup window
    popup = tk.Toplevel(window)
    popup.title("Available URLs")
    popup.geometry("400x300")
    popup.configure(bg="#222222")

    # Instruction label
    tk.Label(popup, text="Select and copy the URLs you want:", 
             bg="#222222", fg="white", font=("Spline Sans Mono", 12)).pack(pady=10)

    # Text widget for URLs
    text_box = ctk.CTkTextbox(popup, font=("Spline Sans Mono", 12))
    text_box.pack(padx=20, pady=10, fill="both", expand=True)

    # Insert URLs
    text_box.insert("end", "\n".join(urls))
    
    text_box.configure(state="normal")  # user can select/copy

def resource_path(relative_path):
    """Get absolute path to resource, works in dev and PyInstaller"""
    if hasattr(sys, "_MEIPASS"):
        base_path = sys._MEIPASS
    else:
        base_path = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base_path, relative_path)


# ----- Check Website Safety with VirusTotal -----
def checksite():
    url = entry_url.get()
    if not url:
        messagebox.showwarning("Warning", "Please enter a website URL")
        return

    params = {"apikey": VIRUSTOTAL_API_KEY, "resource": url}

    try:
        response = requests.get("https://www.virustotal.com/vtapi/v2/url/report", params=params)
        result = response.json()

        if result.get("response_code") == 1:
            if result.get("positives", 0) > 0:
                messagebox.showwarning("Warning", "This website is malicious!")
                button6.configure(state="normal")
            else:
                messagebox.showinfo("Info", "This website is safe")
                button6.configure(state="disabled", fg_color="#c8052f")
                
        else:
            messagebox.showerror("Error", "Could not get scan result")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to check website: {e}")

# ----- Get hosts path based on OS -----
def get_hosts_path():
    system_name = platform.system()
    if system_name == "Windows":
        return r"C:\Windows\System32\drivers\etc\hosts"
    elif system_name in ("Linux", "Darwin"):  # Darwin = macOS
        return "/etc/hosts"
    else:
        messagebox.showerror("Error", f"Unsupported OS: {system_name}")
        return None
    
# ----- Block Website -----
def block_website():
    if entry_url.get() == "":
        messagebox.showerror("Error", "Please Enter a Website")
        return
    if entry_pass.get() == "":
        messagebox.showerror("Error", "Please Enter a Password")
        return
    if entry_pass.get() != password:
        messagebox.showerror("Error", "Please Enter a Valid Password")
        return

    hosts_path = get_hosts_path()
    if not hosts_path:
        return

    entry = "127.0.0.1" + entry_url.get() + "\n"
    try:
        with open(hosts_path, "a") as hosts_file:
            hosts_file.write(entry)
        messagebox.showinfo("Blocked", "Successfully Website Blocked")
        entry_pass.delete(0, tk.END)
    except PermissionError:
        messagebox.showerror("Error", "Run this script as Administrator/root!")

# ----- Unblock Website -----
def unblock_website():
    if entry_url.get() == "":
        messagebox.showerror("Error", "Please Enter a Website")
        return
    if entry_pass.get() == "":
        messagebox.showerror("Error", "Please Enter a Password")
        return
    if entry_pass.get() != password:
        messagebox.showerror("Error", "Please Enter a Valid Password")
        return

    hosts_path = get_hosts_path()
    if not hosts_path:
        return

    try:
        with open(hosts_path, "r") as hosts_file:
            lines = hosts_file.readlines()

        with open(hosts_path, "w") as hosts_file:
            for line in lines:
                if entry_url.get() not in line:
                    hosts_file.write(line)
        messagebox.showinfo("Unblocked", "Successfully Website Unblocked")
        entry_pass.delete(0, tk.END)
        button6.configure(state="disabled")
    except PermissionError:
        messagebox.showerror("Error", "Run this script as Administrator/root!")

# Show Frame 2
def go_to_frame2():
    body_frame.pack_forget()  # hide Frame 1
    body2_frame.pack(fill="both", expand=True, pady=15)  # show Frame 2

# Go back to Frame 1
def go_back_to_frame1():
    body2_frame.pack_forget()  # hide Frame 2
    body_frame.pack(fill="both", expand=True, pady=20)  # show Frame 1

# --------------------------- Header --------------------------------
frame = tk.Frame(window, bg="#222222")
frame.pack(pady=15, anchor="nw", side=tk.TOP, padx=30)


# Build image path (guaranteed to work if img.png is next to script)
script_dir = os.path.dirname(os.path.abspath(__file__))
img_path = resource_path("image.png")

# Load and resize image
img = Image.open(img_path)
img = img.resize((140, 16), Image.Resampling.LANCZOS)
img_tk = ImageTk.PhotoImage(img)

# VERY IMPORTANT: keep a reference so Python doesn’t GC it
img_label = tk.Label(frame, image=img_tk, bg="#222222")
img_label.image = img_tk  # <- keeps reference alive
img_label.pack(side=tk.LEFT)

hr = tk.Frame(window, bg="#FF043C", height=2)
hr.pack(fill=tk.X, padx=30)

# --------------------------- Body1 --------------------------------
splinesans = tkextrafont.Font(file=resource_path("splinesans.ttf"), family="Spline Sans Mono")
squada     = tkextrafont.Font(file=resource_path("squada.ttf"), family="Squada One")

tk_spline_normal  = tkfont.Font(family="Spline Sans Mono", size=12)
tk_spline_normal2 = tkfont.Font(family="Spline Sans Mono", size=10)
tk_spline_bold    = tkfont.Font(family="Spline Sans Mono", size=12, weight="bold")

tk_squada_normal = tkfont.Font(family="Squada One", size=55)
tk_squada_bold   = tkfont.Font(family="Squada One", size=12, weight="bold")

ctk_spline_normal = ctk.CTkFont(family="Spline Sans Mono", size=12)
ctk_spline_bold   = ctk.CTkFont(family="Spline Sans Mono", size=12, weight="bold")

ctk_squada_normal = ctk.CTkFont(family="Squada One", size=12)
ctk_squada_bold   = ctk.CTkFont(family="Squada One", size=12, weight="bold")



body_frame = tk.Frame(window, bg="#222222")
body_frame.grid_columnconfigure(0, weight=1)
body_frame.pack(fill="both", expand=True, padx=0, pady=20)

input_frame = tk.Frame(body_frame, bg="#222222")
input_frame.grid(row=3, column=0, padx=30, sticky="ew", pady=(0,20))
input_frame.grid_columnconfigure(1, weight=1)

label_head = tk.Label(body_frame, text="Welcome!", bg="#222222", fg="white", font=tk_squada_normal)

label_text = tk.Label(body_frame, text="This tool helps you block malicious websites and check their safety using VirusTotal API.", bg="#222222", fg="#7b7b7b", font=tk_spline_normal2, justify="left", wraplength=340)
label_head.grid(row=0,column=0,pady=(15, 0), padx=30, sticky="w")
label_text.grid(row=1,column=0,pady=10,sticky="w", padx=30)

label_email = tk.Label(input_frame, text="Email:", bg="#222222", fg="white", font=tk_spline_normal)
label_email.grid(row=2, column=0, sticky="w", pady=(20, 5))
entry_email = ctk.CTkEntry(input_frame, font=ctk_spline_normal, border_width=0, corner_radius=10, placeholder_text="Enter your email")
entry_email.grid(row=2, column=1, sticky="ew",pady=(20, 5), padx=(10, 0))

button = ctk.CTkButton(body_frame, command=send_email, font=ctk_spline_bold, border_width=0, corner_radius=10, text="Send Password", fg_color="#FF043C", hover_color="#c8052f")
button.grid(row=4, column=0, pady=(20,0), padx=30, sticky="ew")

button2 = ctk.CTkButton(body_frame,command=open_file, font=ctk_spline_bold, border_width=0, corner_radius=10, text="Project Info", fg_color="#FF043C", hover_color="#c8052f")
button2.grid(row=5, column=0, pady=(20,0), padx=30, sticky="ew")

button3 = ctk.CTkButton(body_frame,command=go_to_frame2 ,font=ctk_spline_bold, border_width=1, text="Next ->", fg_color="#222222", hover_color="#ffffff", border_color="#FF043C", text_color="#FF043C")
button3.grid(row=6, column=0, pady=(20,0), padx=30, sticky="ew")


# --------------------------- Body2 --------------------------------
body2_frame = tk.Frame(window, bg="#222222")
body2_frame.pack_forget()
body2_frame.grid_columnconfigure(0, weight=1)

button4 = ctk.CTkButton(body2_frame, command=show_url_popup, font=ctk_spline_bold, border_width=0, corner_radius=10, text="URLs for Testing", fg_color="#FF043C", hover_color="#c8052f")
button4.grid(row=0, column=0, pady=(20,0), padx=30, sticky="ew")

input_frame2 = tk.Frame(body2_frame, bg="#222222")
input_frame2.grid(row=1, column=0, padx=30, sticky="ew", pady=(40,10))
input_frame2.grid_columnconfigure(1, weight=1)

label_url = tk.Label(input_frame2, text="URL: ", bg="#222222", fg="white", font=tk_spline_normal)
label_url.grid(row=1, column=0, sticky="w", pady=(20, 5))
entry_url = ctk.CTkEntry(input_frame2, font=ctk_spline_normal, border_width=0, corner_radius=10, placeholder_text="Enter the URL")
entry_url.grid(row=1, column=1, sticky="ew",pady=(20, 5), padx=(10, 0))

label_pass = tk.Label(input_frame2, text="Password: ", bg="#222222", fg="white", font=tk_spline_normal)
label_pass.grid(row=2, column=0, sticky="w", pady=(15, 5))
entry_pass = ctk.CTkEntry(input_frame2, font=ctk_spline_normal, border_width=0, corner_radius=10, placeholder_text="Enter the Password", show="*")
entry_pass.grid(row=2, column=1, sticky="ew",pady=(15, 5), padx=(10, 0))

button5 = ctk.CTkButton(body2_frame, command=checksite, font=ctk_spline_bold, border_width=0, corner_radius=10, text="Check Website", fg_color="#FF043C", hover_color="#c8052f")
button5.grid(row=2, column=0, pady=(10,0))

input_frame3 = tk.Frame(body2_frame, bg="#222222")
input_frame3.grid(row=3, column=0, padx=30, sticky="ew", pady=10)
input_frame3.grid_columnconfigure(1, weight=1)
input_frame3.grid_columnconfigure(0, weight=1)


button6 = ctk.CTkButton(input_frame3, command=block_website, font=ctk_spline_bold, border_width=0, corner_radius=10, state="disabled", text="Block", fg_color="#FF043C", hover_color="#c8052f")
button6.grid(row=0, column=0, pady=(10,0), sticky="ew", padx=(0,5))

button7 = ctk.CTkButton(input_frame3, command=unblock_website, font=ctk_spline_bold, border_width=0, corner_radius=10, text="Unblock", fg_color="#FF043C", hover_color="#c8052f")
button7.grid(row=0, column=1, pady=(10,0), sticky="ew", padx=(5,0))

button8 = ctk.CTkButton(body2_frame, command=go_back_to_frame1, font=ctk_spline_bold, corner_radius=10, text="<- Back", fg_color="#222222", hover_color="#ffffff", border_color="#FF043C", border_width=1, text_color="#FF043C")
button8.grid(row=5, column=0, pady=(10,0), padx=30, sticky="ew")

button9 = ctk.CTkButton(body2_frame, command=open_hosts_file, font=ctk_spline_bold, border_width=0, corner_radius=10, text="Go to Host file", fg_color="#FF043C", hover_color="#c8052f")
button9.grid(row=4, column=0, pady=(40,0), padx=30, sticky="ew") 

window.resizable(False, False)
window.mainloop()
