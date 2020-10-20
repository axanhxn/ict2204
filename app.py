import tkinter
import tkinter as tk
from tkinter import ttk

def greet():
    print(f"SE, {user_name.get() or 'World'} ") #username var doesnt change, it only used to call get, it will go to the text value

root = tk.Tk() # creating a TK object, main window

user_name = tk.StringVar()

name_label = ttk.Label(root, text="Name: ")
name_label.pack(side="left", padx = (0,10))
name_entry = ttk.Entry(root, width=15, textvariable=user_name) #textvariable link to our program
name_entry.pack(side="left")
name_entry.focus()



# ttk.Label(root, text="Hello, World!").pack() # creating label, text, and pack yourself into your parent

greet_button = ttk.Button(root, text="Student", command=greet) # create a button
greet_button.pack(side="left")

quit_button = ttk.Button(root, text="Quit", command=root.destroy)
quit_button.pack(side="right")

root.mainloop() # It does not proceed further from this code until you close window