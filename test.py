import tkinter as tk




class HomeScreen(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller

        label = tk.Label(self, text="This is the Home Screen", font=("Helvetica", 16))
        label.pack(pady=20)

        button = tk.Button(self, text="Go to Second Screen",
                           command=lambda: controller.show_frame(SecondScreen))
        button.pack()


class SecondScreen(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller

        label = tk.Label(self, text="This is the Second Screen", font=("Helvetica", 16))
        label.pack(pady=20)

        button = tk.Button(self, text="Go to Home Screen",
                           command=lambda: controller.show_frame(HomeScreen))
        button.pack()

