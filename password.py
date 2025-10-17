import re
import random
import string
import tkinter as tk
from tkinter import ttk, messagebox

# ----------------------- FUNCTIONS ----------------------- #

def check_strength(event=None):
    """Checks password strength dynamically."""
    password = entry.get()
    strength_points = 0

    # Criteria checks
    if len(password) >= 8:
        strength_points += 1
    if re.search(r"[A-Z]", password):
        strength_points += 1
    if re.search(r"[a-z]", password):
        strength_points += 1
    if re.search(r"\d", password):
        strength_points += 1
    if re.search(r"[@$!%*?&]", password):
        strength_points += 1

    # Strength logic
    if strength_points <= 2:
        strength = "Weak"
        color = "red"
        progress['value'] = 25
    elif strength_points == 3:
        strength = "Moderate"
        color = "orange"
        progress['value'] = 50
    elif strength_points == 4:
        strength = "Strong"
        color = "blue"
        progress['value'] = 75
    else:
        strength = "Very Strong"
        color = "green"
        progress['value'] = 100

    label_result.config(text=f"Password Strength: {strength}", fg=color)


def clear_input():
    """Clears input and resets progress bar."""
    entry.delete(0, tk.END)
    progress['value'] = 0
    label_result.config(text="")
    show_var.set(False)
    entry.config(show="*")


def toggle_password():
    """Show or hide password text."""
    if show_var.get():
        entry.config(show="")
        btn_toggle.config(text="Hide")
    else:
        entry.config(show="*")
        btn_toggle.config(text="Show")


def copy_to_clipboard():
    """Copy password text to clipboard."""
    password = entry.get()
    if password:
        root.clipboard_clear()
        root.clipboard_append(password)
        messagebox.showinfo("Copied", "Password copied to clipboard!")
    else:
        messagebox.showwarning("Empty Field", "No password to copy.")


def generate_password():
    """Generate a random strong password."""
    length = 12  # Default password length
    characters = string.ascii_letters + string.digits + "@$!%*?&"
    password = ''.join(random.choice(characters) for _ in range(length))
    entry.delete(0, tk.END)
    entry.insert(0, password)
    check_strength()  # Auto-check generated password


# ----------------------- GUI SETUP ----------------------- #

root = tk.Tk()
root.title("Password Strength Checker & Generator")
root.geometry("470x420")
root.config(bg="#f5f5f5")

# Title
tk.Label(root, text="🔒 Password Strength Checker & Generator", 
         font=("Arial", 16, "bold"), bg="#f5f5f5").pack(pady=15)

# Entry Label
tk.Label(root, text="Enter or Generate Password:", 
         font=("Arial", 12), bg="#f5f5f5").pack()

# Password Entry + Show/Hide
entry_frame = tk.Frame(root, bg="#f5f5f5")
entry_frame.pack(pady=5)

entry = tk.Entry(entry_frame, width=28, show="*", font=("Arial", 12))
entry.grid(row=0, column=0, padx=5)
entry.bind("<KeyRelease>", check_strength)

show_var = tk.BooleanVar(value=False)
btn_toggle = tk.Checkbutton(entry_frame, text="Show", font=("Arial", 10),
                            variable=show_var, command=toggle_password, bg="#f5f5f5")
btn_toggle.grid(row=0, column=1)

# Progress Bar
progress = ttk.Progressbar(root, orient="horizontal", length=280, mode="determinate", maximum=100)
progress.pack(pady=10)

# Strength Label
label_result = tk.Label(root, text="", font=("Arial", 12, "bold"), bg="#f5f5f5")
label_result.pack(pady=10)

# Buttons
btn_frame = tk.Frame(root, bg="#f5f5f5")
btn_frame.pack(pady=10)

tk.Button(btn_frame, text="Check Strength", font=("Arial", 12),
          bg="#4CAF50", fg="white", command=check_strength).grid(row=0, column=0, padx=6)

tk.Button(btn_frame, text="Clear", font=("Arial", 12),
          bg="#FF5733", fg="white", command=clear_input).grid(row=0, column=1, padx=6)

tk.Button(btn_frame, text="Copy", font=("Arial", 12),
          bg="#007BFF", fg="white", command=copy_to_clipboard).grid(row=0, column=2, padx=6)

tk.Button(btn_frame, text="Generate", font=("Arial", 12),
          bg="#8E44AD", fg="white", command=generate_password).grid(row=0, column=3, padx=6)

# Footer Label
tk.Label(root, text="Developed by Anoushka Saha 💻", 
         font=("Arial", 10, "italic"), fg="gray", bg="#f5f5f5").pack(side="bottom", pady=10)

root.mainloop()