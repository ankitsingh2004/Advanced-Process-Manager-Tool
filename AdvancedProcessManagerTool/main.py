import tkinter as tk
from gui import LoginPage, ProcessManagerGUI

def main():
    root = tk.Tk()
    def on_login_success(username):
        for widget in root.winfo_children():
            widget.destroy()
        ProcessManagerGUI(root, username)
    LoginPage(root, on_login_success)
    root.mainloop()

if __name__ == "__main__":
    main()
