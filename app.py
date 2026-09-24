# import sys
# from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
#                              QHBoxLayout, QTabWidget, QLabel, QTextEdit, 
#                              QLineEdit, QPushButton, QSpinBox, QMessageBox)
# import kripto

# class KriptografiApp(QMainWindow):
#     def __init__(self):
#         super().__init__()
#         self.setWindowTitle("Aplikasi Kriptografi - 5 Menu")
#         self.setGeometry(100, 100, 700, 550)

#         # Main Layout & Tab Widget
#         self.tabs = QTabWidget()
#         self.setCentralWidget(self.tabs)

#         # Inisialisasi 5 Tab/Menu
#         self.tabs.addTab(self.create_caesar_tab(), "1. Caesar (Klasik)")
#         self.tabs.addTab(self.create_vigenere_tab(), "2. Vigenere (Klasik)")
#         self.tabs.addTab(self.create_aes_tab(), "3. AES (Modern)")
#         self.tabs.addTab(self.create_rsa_tab(), "4. RSA (Modern)")
#         self.tabs.addTab(self.create_super_tab(), "5. Super Enkripsi")