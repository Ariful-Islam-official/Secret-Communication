# Secret Communication Tool
### Overview
This tool allows you to send personal messages and information with privacy by encrypting and decrypting the text.

* **Encryption:** Translates plain text into ciphertext, making it unreadable without the decryption key.

* **Decryption:** Converts ciphertext back into plaintext using the correct key.

---

### Prerequisites
Ensure you have Python installed on your system and the following modules:

1. Tkinter: For the graphical user interface.
2. Base64: For encryption and decryption.

To install the modules, run:

```
pip install tk
pip install base64
```

---

### How It Works
1. Enter your message in the provided text area.
2. Provide a key for encryption or decryption.
3. Use the Encrypt button to encode your message.
4. Use the Decrypt button to decode a previously encrypted message.

---

### Code Implementation
**Step 1: Import Required Libraries**
```
from tkinter import *
import base64
```
**Step 2: Create the GUI Window**
```
screen = Tk()
screen.geometry("500x300")
screen.title("Secret Communication Tool")
```
Using `mainloop()` to check the GUI
**Step 3: Define Functions**
**Encryption Function:**
```
def encrypt_message():
    message = text_input.get("1.0", END)
    key = key_input.get()
    if not key:
        result_display.config(text="Key cannot be empty!")
        return
    try:
        encoded_bytes = base64.b64encode((message + key).encode("utf-8"))
        result_display.config(text=encoded_bytes.decode("utf-8"))
    except Exception as e:
        result_display.config(text=f"Error: {str(e)}")
```
**Decryption Function:**
```
def decrypt_message():
    encrypted_text = text_input.get("1.0", END)
    key = key_input.get()
    if not key:
        result_display.config(text="Key cannot be empty!")
        return
    try:
        decoded_bytes = base64.b64decode(encrypted_text.strip())
        decoded_message = decoded_bytes.decode("utf-8")
        if decoded_message.endswith(key):
            result_display.config(text=decoded_message[:-len(key)])
        else:
            result_display.config(text="Decryption failed: Incorrect key.")
    except Exception as e:
        result_display.config(text=f"Error: {str(e)}")
```
**Step 4: Design the GUI Layout**
```
# Input field for the message
Label(root, text="Enter your Message:", font=("Helvetica", 10)).pack(pady=5)
text_input = Text(root, height=5, width=40)
text_input.pack(pady=5)

# Input field for the key
Label(root, text="Enter Encryption Key:", font=("Helvetica", 10)).pack(pady=5)
key_input = Entry(root, show="*", width=40)
key_input.pack(pady=5)

# Buttons for encryption and decryption
Button(root, text="Encrypt", command=encrypt_message, bg="lightblue").pack(pady=5)
Button(root, text="Decrypt", command=decrypt_message, bg="lightgreen").pack(pady=5)

# Output display area
Label(root, text="Output:", font=("Helvetica", 10)).pack(pady=5)
result_display = Label(root, text="", font=("Helvetica", 10), wraplength=400)
result_display.pack(pady=5)
```
**Step 5: Run the Application**
```
root.mainloop()
```

---

### Full Code
```
from tkinter import *
import base64

def encrypt_message():
    message = text_input.get("1.0", END)
    key = key_input.get()
    if not key:
        result_display.config(text="Key cannot be empty!")
        return
    try:
        encoded_bytes = base64.b64encode((message + key).encode("utf-8"))
        result_display.config(text=encoded_bytes.decode("utf-8"))
    except Exception as e:
        result_display.config(text=f"Error: {str(e)}")

def decrypt_message():
    encrypted_text = text_input.get("1.0", END)
    key = key_input.get()
    if not key:
        result_display.config(text="Key cannot be empty!")
        return
    try:
        decoded_bytes = base64.b64decode(encrypted_text.strip())
        decoded_message = decoded_bytes.decode("utf-8")
        if decoded_message.endswith(key):
            result_display.config(text=decoded_message[:-len(key)])
        else:
            result_display.config(text="Decryption failed: Incorrect key.")
    except Exception as e:
        result_display.config(text=f"Error: {str(e)}")

root = Tk()
root.geometry("500x300")
root.title("Secret Communication Tool")

Label(root, text="Enter your Message:", font=("Helvetica", 10)).pack(pady=5)
text_input = Text(root, height=5, width=40)
text_input.pack(pady=5)

Label(root, text="Enter Encryption Key:", font=("Helvetica", 10)).pack(pady=5)
key_input = Entry(root, show="*", width=40)
key_input.pack(pady=5)

Button(root, text="Encrypt", command=encrypt_message, bg="lightblue").pack(pady=5)
Button(root, text="Decrypt", command=decrypt_message, bg="lightgreen").pack(pady=5)

Label(root, text="Output:", font=("Helvetica", 10)).pack(pady=5)
result_display = Label(root, text="", font=("Helvetica", 10), wraplength=400)
result_display.pack(pady=5)

root.mainloop()
```

---

### How to Run
1. Save the code to a file, e.g., `secret_tool.py`.
2. Run the file
```
python secret_tool.py
```
3. Enter a message and a key, then click **Encrypt** or **Decrypt**.
