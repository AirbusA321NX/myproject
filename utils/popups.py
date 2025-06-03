import ctypes

def show_popup(title: str, message: str):
    # MB_SYSTEMMODAL = 0x1000, MB_OK = 0x0
    ctypes.windll.user32.MessageBoxW(0, message, title, 0x00001000)
