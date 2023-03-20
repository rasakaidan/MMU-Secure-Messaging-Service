from tkinter import *

top = Tk()
top.title("Converse (not the shoes)")

BG_GRAY = "#FFFFFF"
BG_COLOR = "#FF0000"
TEXT_COLOR = "#FFFFFF"
 
FONT = "Helvetica 14"
FONT_BOLD = "Helvetica 13 bold"
 
def send():
    send = "You -> " + e.get()
    txt.insert(END, "\n" + send)
    
    user = Entry.get().lower()
    txt.insert(END, "\n" + user)

    e.delete(0, END)

txt = Text(top, bg=BG_COLOR, fg=TEXT_COLOR, font=FONT, width=60)
txt.grid(row=1, column=0, columnspan=2)
 
scrollbar = Scrollbar(txt)
scrollbar.place(relheight=1, relx=0.974)
 
e = Entry(top, bg="#8E1600", fg=TEXT_COLOR, font=FONT, width=55)
e.grid(row=2, column=1)

host = Button(top, text="host", font=FONT_BOLD, command = host).grid(row=3, column=1)

join = Button(top, text="join", font=FONT_BOLD, command = host).grid(row=3, column=2)
 
send = Button(top, text="Send", font=FONT_BOLD, bg=BG_GRAY, command=send).grid(row=2, column=2)


top.mainloop()