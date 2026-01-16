from tkinter import *
from tkinter import messagebox, filedialog
from PyPDF2 import PdfWriter, PdfReader
import os


def browse_file():
    filepath = filedialog.askopenfilename(
        title="Select PDF File",
        filetypes=[("PDF Files", "*.pdf")]
    )
    if filepath:
        pdf_path.set(filepath)


def protect_pdf():
    input_pdf = pdf_path.get()
    password = password_var.get()

    if not input_pdf:
        messagebox.showerror("Error", "Please select a PDF file.")
        return
    if not password:
        messagebox.showerror("Error", "Please enter a password.")
        return

    try:
        reader = PdfReader(input_pdf)
        writer = PdfWriter()

        for page in reader.pages:
            writer.add_page(page)

        writer.encrypt(password)

        # Save in same folder with '_protected' suffix
        output_pdf = os.path.splitext(input_pdf)[0] + "_protected.pdf"
        with open(output_pdf, "wb") as f:
            writer.write(f)
        messagebox.showinfo("Success", f"PDF protected successfully!\nSaved as:\n{output_pdf}")
        
    except Exception as e:
        messagebox.showerror("Error", f"Something went wrong:\n{e}")

def remove_password():
    input_pdf = pdf_path.get()
    password = password_var.get()

    if not input_pdf:
        messagebox.showerror("Error", "Please select a PDF file.")
        return
    if not password:
        messagebox.showerror("Error", "Please enter the current password.")
        return

    try:
        reader = PdfReader(input_pdf)

        # Check if file is encrypted
        if reader.is_encrypted:
            # Try decrypting with provided password
            if reader.decrypt(password) == 0:
                messagebox.showerror("Error", "Incorrect password! Cannot remove protection.")
                return
        else:
            messagebox.showwarning("Warning", "This PDF is not password protected.")
            return

        writer = PdfWriter()
        for page in reader.pages:
            writer.add_page(page)

        # Save unlocked version
        output_pdf = os.path.splitext(input_pdf)[0] + "_unlocked.pdf"
        with open(output_pdf, "wb") as f:
            writer.write(f)

        messagebox.showinfo("Success", f"Password removed successfully!\nSaved as:\n{output_pdf}")
    except Exception as e:
        messagebox.showerror("Error", f"Something went wrong:\n{e}")


root = Tk()
root.title("PDF Protector")
root.geometry("350x400")
root.resizable(False,False)
root.iconbitmap("icon.ico")

pdf_path = StringVar()
password_var = StringVar()

Label(root, text="Select PDF File:", font=("Arial", 14)).pack(pady=5)
Entry(root, textvariable=pdf_path, bg = 'white', width=40, state="readonly").pack(pady=5)
Button(root, text="Browse", command=browse_file).pack(pady=5)

Label(root, text="Enter Password:", font=("Arial", 12)).pack(pady=5)
Entry(root, textvariable=password_var, show="*").pack(pady=5)

# Buttons
btn_frame = Frame(root)
btn_frame.pack(pady=15)

Button(btn_frame, text="Protect PDF", command=protect_pdf, bg="green", fg="white").grid(row=0, column=0, padx=10)
Button(btn_frame, text="Remove Password", command=remove_password, bg="red", fg="white").grid(row=0, column=1, padx=10)

root.mainloop()