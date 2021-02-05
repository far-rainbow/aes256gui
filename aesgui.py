import os
import sys
from pathlib import Path
import hashlib
from base64 import b64encode, b64decode
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from PyQt5 import QtWidgets
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QMainWindow, QWidget, QGridLayout, QMessageBox, QFileDialog
from PyQt5.QtWidgets import QPushButton, QGroupBox, QHBoxLayout, QVBoxLayout, QScrollArea
from PyQt5.Qt import QLabel, QLineEdit, QTextBlock, QTextEdit

class App(QMainWindow):

    def __init__(self):
        super().__init__()
        self.title = "AES256 encrypt decrypt GUI"
        
        # window left top coord
        self.left = 32
        self.top = 32
        
        # initial windows width and height
        self.width = 600
        self.height = 400
        
        self.groupDesign = 'font-size:12px;color:#f0f0f0;border: 0px;'
        self.labelDesign = 'font-size:16px;color:#f0f0f0;border: 0px;'

        self.key = None
        self.keytext = None
        self.pwdInput = None
        self.filename = None

        self.initUI()
        
    def initUI(self):
        ''' UI init, window sections are in separate methods '''
        self.setWindowTitle(self.title)
        self.setGeometry(self.left, self.top, self.width, self.height)
        self.setStyleSheet('font-size:16px;background-color:#202020;color:#f0f0f0;')

        central_widget = QWidget(self)
        self.setCentralWidget(central_widget)

        grid = QGridLayout(self)
        grid.addWidget(self.fileselectorWidget(), 0, 0)
        grid.addWidget(self.keytextWidget(), 1, 0)
        grid.addWidget(self.buttonsWidget(), 2, 0)
        central_widget.setLayout(grid)

    def fileselectorWidget(self):
        ''' top section with file picker '''
        groupBox = QGroupBox()
        hbox = QHBoxLayout()
        label = QLabel("file:")
        label.setStyleSheet(self.labelDesign)
        self.filename = QLineEdit()
        self.filename.setStyleSheet('font-size:16px;color:#f0f0f0;background-color:#404040;border: 0px;')
        button = QPushButton("Choose file")
        button.setStyleSheet('font-size:16px;color:#f0f0f0;background-color:#808080;border: 0px;padding:4px;')
        button.clicked.connect(self.chooseFile)
        hbox.addWidget(label)
        hbox.addWidget(self.filename)
        hbox.addWidget(button)
        groupBox.setLayout(hbox)
        groupBox.setStyleSheet(self.groupDesign)
        return groupBox

    def buttonsWidget(self):
        ''' buttons section '''
        groupBox = QGroupBox()
        vbox = QVBoxLayout()
        hbox = QHBoxLayout()
        buttonEncrypt = QPushButton('Encrypt')
        buttonEncrypt.setStyleSheet('font-size:16px;color:#f0f0f0;background-color:#f06060;border: 1px solid #804040;padding:4px;')
        buttonEncrypt.clicked.connect(lambda: self.butclick('encrypt'))
        buttonDecrypt = QPushButton('Decrypt')
        buttonDecrypt.setStyleSheet('font-size:16px;color:#f0f0f0;background-color:#40f060;border: 1px solid #208040;padding:4px;')
        buttonDecrypt.clicked.connect(lambda: self.butclick('decrypt'))
        hbox.addWidget(buttonEncrypt)
        hbox.addWidget(buttonDecrypt)
        vbox.addLayout(hbox)
        buttonInit = QPushButton('Generate key')
        buttonInit.setStyleSheet('font-size:16px;color:#f0f0f0;background-color:#4070f0;border: 1px solid #204080;padding:4px;')
        buttonInit.clicked.connect(lambda: self.butclick('keygen'))
        vbox.addWidget(buttonInit)
        groupBox.setLayout(vbox)
        groupBox.setStyleSheet(self.groupDesign)
        return groupBox

    def keytextWidget(self):
        ''' key and password middle section '''
        groupBox = QGroupBox('Encryption key (Base64 encoding)')
        hbox = QHBoxLayout()
        vbox = QVBoxLayout()

        self.keytext = QTextEdit()
        self.keytext.setDisabled(False)
        self.keytext.setStyleSheet('font-size:16px;color:#f0f0f0;background-color:#404040;border: 0px;margin-top:8px')
        vbox.addWidget(self.keytext)

        pwdLabel = QLabel('Password:')
        pwdLabel.setStyleSheet(self.labelDesign)
        self.pwdInput = QLineEdit()
        self.pwdInput.setStyleSheet('font-size:16px;color:#f0f0f0;background-color:#404040;border: 0px;')
        hbox.addWidget(pwdLabel)
        hbox.addWidget(self.pwdInput)
        vbox.addLayout(hbox)

        groupBox.setLayout(vbox)
        groupBox.setStyleSheet(self.groupDesign)
        return groupBox

    def butclick(self,cmd):
        ''' button events (encrypt,decrypt,key generation) logic '''
        if cmd == 'encrypt':
            # is file excist check
            if os.path.isfile(self.filename.text()):
                try:
                    # if no password has entered then use empty password
                    key = b64decode(self.keytext.toPlainText())
                except:
                    key = ''
                # key lenght check, must be 32 bytes exactly!
                if len(key) == 32:
                    filename = self.filename.text()
                    data = self.getFile(filename)
                    cipher = AES.new(key, AES.MODE_ECB)
                    cipher_text = cipher.encrypt(pad(data,32))
                    self.saveFile(f'{filename}.crypted',cipher_text)
                    self.saveKeyfile(f'{filename}.key',self.keytext.toPlainText())
                    self.warning(f"Encrypted file was saved as {filename}.crypted\nEncryption key was saved as {filename}.key")
                else:
                    self.warning("WRONG KEY!")
            else:
                self.warning("File is not selected! Please choose a file.")
        elif cmd == 'decrypt':
            # is file excist check
            if os.path.isfile(self.filename.text()):
                try:
                    # if no password has entered then use empty password
                    key = b64decode(self.keytext.toPlainText())
                except:
                    key = ''
                # key lenght check, must be 32 bytes exactly!
                if len(key) == 32:
                    filename = self.filename.text()
                    filedata = self.getFile(f'{filename}')
                    cipher = AES.new(key, AES.MODE_ECB)
                    try:
                        # exception if decryption is not possible
                        # it means that file has wrong structure (not AES256)
                        data = cipher.decrypt(filedata)
                    except Exception as e:
                        print(e)
                        self.warning("This file can't be decrypted!")
                        return
                    try:
                        # the exception at this point is means that the file
                        # has good AES-256 structure but the key/pass is wrong
                        # Also there may be a disk i/o exception error while
                        # saving a file to disk but there is not sense of
                        # handling it becouse your disk must work well everytime
                        self.saveFile(f'{filename}.decrypted',unpad(data,32))
                    except Exception as e:
                        print(e)
                        self.warning("Wrong key/pass!")
                        return
                    self.warning(f"Decrypted file was saved as {filename}.decrypted")
                else:
                    self.warning("Wrong key/pass!")
            else:
                self.warning("File is not selected! Please choose a file.")
        elif cmd == 'keygen':
            self.keygen()

    def keygen(self):
        ''' key generation with empty salt ("easy mode", feel free to write salted algo) '''
        # "easy mode" has a salt of 16 zero bytes
        salt = 16 * b'\0'
        private_key = hashlib.scrypt(self.pwdInput.text().encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
        self.keytext.setText(b64encode(private_key).decode('utf-8'))

    def chooseFile(self):
        ''' file picker dialog '''
        fname = QFileDialog.getOpenFileName(self, "Open file", str(Path.home()))
        if fname[0]:
            self.filename.setText(fname[0])

    def getFile(self,filename):
        ''' binary mode file loader '''
        with open(filename,'rb') as f:
            data = f.read()
        return data

    def saveKeyfile(self,filename,data):
        ''' save text file to disk'''
        try:
            with open(filename,'w') as f:
                f.write(data)
        except Exception as e:
            print(e)

    def saveFile(self,filename,data):
        ''' save binary file to disk '''
        try:
            with open(filename,'wb') as f:
                f.write(data)
        except Exception as e:
            print(e)

    def warning(self,message):
        ''' warning floating window '''
        q = QMessageBox()
        q.setStyleSheet('QMessageBox {font-size:16px;background-color:#a0a0a0;} ')
        QMessageBox.question(q, "WARNING!", message, QMessageBox.Ok)

    def closeEvent(self, event):
        ''' application exit handler '''
        r = QMessageBox()
        r.setStyleSheet('QMessageBox {font-size:16px;background-color:#a0a0a0;}')
        reply = QMessageBox.question(r, "WARNING!",
            "Are you want to exit?", QMessageBox.Yes | 
            QMessageBox.No, QMessageBox.No)

        if reply == QMessageBox.Yes:
            event.accept()
        else:
            event.ignore()

APP = QtWidgets.QApplication([])
ex = App()
ex.show()
sys.exit(APP.exec_())
