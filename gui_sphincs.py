import os
import importlib
import tkinter as tk
from tkinter import messagebox, filedialog

# gaphic interface
root = tk.Tk()
root.title("SPHINCS+ GUI")
root.geometry("300x400")
button_width = 20

# global variables
secret_key = None
public_key = None
uploaded_message = None
generated_signature = None
keys_generated = False
message_selected = False 
message_signed = False
selected_version = tk.StringVar()

# list of different types of sphincs+ and selecting version
versions = [
    "shake_128f", "shake_128s","shake_192f", "shake_192s", "shake_256f", "shake_256s",
    "sha2_128f", "sha2_128s","sha2_192f", "sha2_192s", "sha2_256f", "sha2_256s",
    "haraka_128f", "haraka_128s","haraka_192f", "haraka_192s", "haraka_256f", "haraka_256s",
]


selected_version.set(versions[0])
tk.Label(root, text="select SPHINCS+ Version:").pack(pady=5)
option_menu = tk.OptionMenu(root, selected_version, *versions)
option_menu.pack(pady=5)

# generating seed and keypair
def generate_keys():
    global secret_key, public_key, keys_generated
    if keys_generated:
        messagebox.showinfo("Info", "Keypair already generated.")
        return
    try:
        module_name = selected_version.get()
        module = importlib.import_module(f"pyspx.{module_name}")

        # determining length of seed
        if "128" in module_name:
            seed_len = 48
        elif "192" in module_name:
            seed_len = 72
        elif "256" in module_name:
            seed_len = 96
        else:
            seed_len = 48

        seed = os.urandom(seed_len)
        public_key , secret_key = module.generate_keypair(seed)
        keys_generated = True
        option_menu.configure(state="disabled")
        messagebox.showinfo("Keys",f"Keypair generated using: {module_name}\n"
                            f"Seed: {len(seed)} bytes\n {seed.hex()}\n"
                            f"Public Key: {len(public_key)} bytes\n {public_key.hex()}\n"
                            f"Secret Key: {len(secret_key)} bytes\n {secret_key.hex()}\n")
    except Exception as e:
        messagebox.showerror("Error", f"Key generation failed:\n{e}")

# uploadind plaintext
def upload_message():
    global uploaded_message, message_selected
    if message_selected:
        messagebox.showinfo("Info", "Message already selected.")
        return
    file_path = filedialog.askopenfilename(title="Select a text file", filetypes=[("Text Files", "*.txt")])
    if not file_path:
        return
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            message_str = f.read()
            uploaded_message = message_str.encode('utf-8')
            message_selected = True
            messagebox.showinfo("Message Loaded", f"Message content: {len(message_str)} bytes\n{message_str}")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to read file:\n{e}")

# signing plaintext with selected version of sphincs+
def sign_message():
    global generated_signature, message_signed
    if message_signed:
        messagebox.showinfo("Info", "Message already signed.")
        return
    if not secret_key or not uploaded_message:
        messagebox.showwarning("Missing Data", "Make sure keypair and message are loaded.")
        return
    try:
        module = importlib.import_module(f"pyspx.{selected_version.get()}")
        if not secret_key or not uploaded_message:
            messagebox.showwarning("Warning", "Missing secret key or message.")
        generated_signature = module.sign(uploaded_message, secret_key)
        message_signed = True
        messagebox.showinfo("Signature", f"Signature (hex) {selected_version.get()}: {len(generated_signature)} bytes\n{generated_signature.hex()}")

    except Exception as e:
        messagebox.showerror("Error", f"Signature failed:\n{e}")

# saving signature for verification
def save_signature():
    if not generated_signature:
        messagebox.showwarning("No Signature", "Please sign a message first.")
        return
    file_path = filedialog.asksaveasfilename(defaultextension=".sig", filetypes=[("Signature Files", "*.sig")])
    if not file_path:
        return
    try:
        with open(file_path, 'wb') as f:
            f.write(generated_signature)
            messagebox.showinfo("Saved", f"Signature saved to:\n{file_path}")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to save signature:\n{e}")

# verifying signature by selecting plaintext and saved signature that return "Signature is VALID." or "Signature is INVALID."
def verify_signature():
    
    if not public_key:
        messagebox.showwarning("Missing Key", "At first you need to generate a keypair and sign a messsage.")
        return
    # uploading message
    msg_path = filedialog.askopenfilename(title="select message file", filetypes=[("Text File", "*.txt")])
    if not msg_path:
        return
    try:
        with open(msg_path, 'r', encoding='utf-8') as f:
            msg = f.read().encode('utf-8')
    except Exception as e:
        messagebox.showerror("Error", f"Could not read message:\n{e}")
        return
    
    # uploading signature
    sig_path = filedialog.askopenfilename(title="Select signature file", filetypes=[("Signature Files", "*.sig")])
    if not sig_path:
        return
    try:
        with open(sig_path, 'rb') as f:
            sig = f.read()
    except Exception as e:
        messagebox.showerror("Error", f"Could not read signature:\n{e}")
        return
    
    # verify
    try:
        module = importlib.import_module(f"pyspx.{selected_version.get()}")
        valid = module.verify(msg, sig, public_key)
        if valid:
            messagebox.showinfo("Verification", f"Signature {selected_version.get()} is VALID.")
        else:
            messagebox.showwarning("Verification", "Signature is INVALID.")
    except Exception as e:
        messagebox.showerror("Verification Error", f"Verification failed:\n{e}")
def reset_all():
    global public_key, secret_key, uploaded_message, generated_signature
    global keys_generated, message_selected, message_signed
    secret_key = None
    public_key = None
    uploaded_message = None
    generated_signature = None
    keys_generated = False
    message_selected = False 
    message_signed = False
    option_menu.configure(state="normal")
    messagebox.showinfo("Reset", "All data and states have been reset.")


# buttons in GUI
tk.Button(root, text="Generate Keypair", width=button_width, command=generate_keys).pack(pady=10)

tk.Button(root, text="Upload Message",  width=button_width, command=upload_message).pack(pady=10)

tk.Button(root, text="Sign Message",  width=button_width, command=sign_message).pack(pady=10)

tk.Button(root, text="Save Signature",  width=button_width, command=save_signature).pack(pady=10)

tk.Button(root, text="Verify Signature",  width=button_width, command=verify_signature).pack(pady=10)

tk.Button(root, text="Reset",  width=button_width, command=reset_all, fg="red").pack(pady=10)

root.mainloop()
