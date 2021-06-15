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
        self.title = 'AES256 encrypt decrypt GUI'
        
        # координаты отображения окна программы при старте
        self.left = 32
        self.top = 32
        
        # высота и ширина окна при запуске
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
        ''' инициализация UI, блоки вынесены в отдельные методы '''
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
        ''' создание верхнего блока с выбором файла '''
        groupBox = QGroupBox()
        hbox = QHBoxLayout()
        label = QLabel("Файл:")
        label.setStyleSheet(self.labelDesign)
        self.filename = QLineEdit()
        self.filename.setStyleSheet('font-size:16px;color:#f0f0f0;background-color:#404040;border: 0px;')
        button = QPushButton("Выбор файла")
        button.setStyleSheet('font-size:16px;color:#f0f0f0;background-color:#808080;border: 0px;padding:4px;')
        button.clicked.connect(self.chooseFile)
        hbox.addWidget(label)
        hbox.addWidget(self.filename)
        hbox.addWidget(button)
        groupBox.setLayout(hbox)
        groupBox.setStyleSheet(self.groupDesign)
        return groupBox

    def buttonsWidget(self):
        ''' создание блока с конпками '''
        groupBox = QGroupBox()
        vbox = QVBoxLayout()
        hbox = QHBoxLayout()
        buttonEncrypt = QPushButton('Зашифровать')
        buttonEncrypt.setStyleSheet('font-size:16px;color:#f0f0f0;background-color:#f06060;border: 1px solid #804040;padding:4px;')
        buttonEncrypt.clicked.connect(lambda: self.butclick('encrypt'))
        buttonDecrypt = QPushButton('Расшифровать')
        buttonDecrypt.setStyleSheet('font-size:16px;color:#f0f0f0;background-color:#40f060;border: 1px solid #208040;padding:4px;')
        buttonDecrypt.clicked.connect(lambda: self.butclick('decrypt'))
        hbox.addWidget(buttonEncrypt)
        hbox.addWidget(buttonDecrypt)
        vbox.addLayout(hbox)
        buttonInit = QPushButton('Сгенерировать ключ')
        buttonInit.setStyleSheet('font-size:16px;color:#f0f0f0;background-color:#4070f0;border: 1px solid #204080;padding:4px;')
        buttonInit.clicked.connect(lambda: self.butclick('keygen'))
        vbox.addWidget(buttonInit)
        groupBox.setLayout(vbox)
        groupBox.setStyleSheet(self.groupDesign)
        return groupBox

    def keytextWidget(self):
        ''' создание центрального блока с представлением ключа и вводом пароля '''
        groupBox = QGroupBox('Ключ шифрования (кодировка Base64)')
        hbox = QHBoxLayout()
        vbox = QVBoxLayout()

        self.keytext = QTextEdit()
        self.keytext.setDisabled(False)
        self.keytext.setStyleSheet('font-size:16px;color:#f0f0f0;background-color:#404040;border: 0px;margin-top:8px')
        vbox.addWidget(self.keytext)

        pwdLabel = QLabel('Пароль:')
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
        ''' обработка кнопок шифрования, дешифрования и генерации '''
        if cmd == 'encrypt':
            #проверка существует ли введённый или выбранный файл на диске
            if os.path.isfile(self.filename.text()):
                try:
                    # если пароль не введён, то испольуем пустой пароль
                    key = b64decode(self.keytext.toPlainText())
                except:
                    key = ''
                # проверка длинны ключа, должен быть ровно 32 байта
                if len(key) == 32:
                    filename = self.filename.text()
                    data = self.getFile(filename)
                    cipher = AES.new(key, AES.MODE_ECB)
                    cipher_text = cipher.encrypt(pad(data,32))
                    self.saveFile(f'{filename}.crypted',cipher_text)
                    self.saveKeyfile(f'{filename}.key',self.keytext.toPlainText())
                    self.warning(f'Зашифрованный файл сохранён в {filename}.crypted\nКлюч сохранён в {filename}.key')
                else:
                    self.warning('Неверный ключ!')
            else:
                self.warning('Файл не выбран!')
        elif cmd == 'decrypt':
            #проверка существует ли введённый или выбранный файл на диске
            if os.path.isfile(self.filename.text()):
                try:
                    # если пароль не введён, то испольуем пустой пароль
                    key = b64decode(self.keytext.toPlainText())
                except:
                    key = ''
                # проверка длинны ключа, должен быть ровно 32 байта
                if len(key) == 32:
                    filename = self.filename.text()
                    filedata = self.getFile(f'{filename}')
                    cipher = AES.new(key, AES.MODE_ECB)
                    try:
                        # если дешифрация не удаётся, то возникает исключение
                        # это значит, что файл имеет неподходящую структуру
                        data = cipher.decrypt(filedata)
                    except Exception as e:
                        print(e)
                        self.warning('Файл не годится для дешифрования!')
                        return
                    try:
                        # если возникает исключение на этом этапе, значит
                        # файл имеет подходящую структуру, но ключ не годится
                        # для дешифрования. здесь также может возникнуть
                        # исключение по ошибке сохранения на диск, но в данном
                        # случае оно не обрабатывается как малозначимое
                        self.saveFile(f'{filename}.decrypted',unpad(data,32))
                    except Exception as e:
                        print(e)
                        self.warning('Неверный ключ!')
                        return
                    self.warning(f'Расшифрованный файл сохранён в {filename}.decrypted')
                else:
                    self.warning('Неверный ключ!')
            else:
                self.warning('Файл не выбран!')
        elif cmd == 'keygen':
            self.keygen()

    def keygen(self):
        ''' генерация ключа по паролю с пустой солью '''
        # в качестве соли используется 16 нулевых байтов
        # этот способ практикуется для упрощения шифрования с потерей сложности
        salt = 16 * b'\0'
        private_key = hashlib.scrypt(self.pwdInput.text().encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
        self.keytext.setText(b64encode(private_key).decode('utf-8'))

    def chooseFile(self):
        ''' диалог выбора файла '''
        fname = QFileDialog.getOpenFileName(self, 'Выбор файла', str(Path.home()))
        if fname[0]:
            self.filename.setText(fname[0])

    def getFile(self,filename):
        ''' загрузка файла в бинарном виде '''
        with open(filename,'rb') as f:
            data = f.read()
        return data

    def saveKeyfile(self,filename,data):
        ''' сохранить текстовый файл '''
        try:
            with open(filename,'w') as f:
                f.write(data)
        except Exception as e:
            print(e)

    def saveFile(self,filename,data):
        ''' сохранить бинарный файл '''
        try:
            with open(filename,'wb') as f:
                f.write(data)
        except Exception as e:
            print(e)

    def warning(self,message):
        ''' всплывающее окно предупреждения '''
        q = QMessageBox()
        q.setStyleSheet('QMessageBox {font-size:16px;background-color:#a0a0a0;} ')
        QMessageBox.question(q, 'ВНИМАНИЕ!', message, QMessageBox.Ok)

    def closeEvent(self, event):
        ''' обработка выхода из программы '''
        r = QMessageBox()
        r.setStyleSheet('QMessageBox {font-size:16px;background-color:#a0a0a0;}')
        reply = QMessageBox.question(r, 'ВНИМАНИЕ!',
            "Выход?", QMessageBox.Yes | 
            QMessageBox.No, QMessageBox.No)

        if reply == QMessageBox.Yes:
            event.accept()
        else:
            event.ignore()

APP = QtWidgets.QApplication([])
ex = App()
ex.show()
sys.exit(APP.exec_())
