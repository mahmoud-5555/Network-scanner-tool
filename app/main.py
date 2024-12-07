"""This is the main module of the program"""
from views.home import App, main
import sys





"""The main of the program"""
if __name__ == "__main__":

    if len(sys.argv) > 1:

        if sys.argv[1] == "-cli":
            main()
        else:
            print("Invalid argument")
            print("- Usage: python main.py [-cli]")
            print("- python main.py: to run the GUI version")
    else:
        app = App()
        app.mainloop()


