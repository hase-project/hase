from PyQt5.QtWidgets import (
    QTableWidget, QTableWidgetItem, 
    QAbstractScrollArea,
    QAction, QMenu,
)
from PyQt5.QtGui import QCursor
from binascii import unhexlify
from struct import unpack


class RegTableWidget(QTableWidget):
    def __init__(self, parent=None):
        super(RegTableWidget, self).__init__(parent)
        # self.setSizeAdjustPolicy(QAbstractScrollArea.AdjustToContents)

    def append_reg(self, rname, value):
        rname_item = QTableWidgetItem()
        rname_item.setText(rname)
        value_item = QTableWidgetItem()
        value_item.setText(value)
        self.insertRow(self.rowCount())
        self.setItem(self.rowCount() - 1, 0, rname_item)
        self.setItem(self.rowCount() - 1, 1, value_item)


class VarTableWidget(QTableWidget):
    def __init__(self, parent=None):
        super(VarTableWidget, self).__init__(parent)
        # self.setSizeAdjustPolicy(QAbstractScrollArea.AdjustToContents)

    def set_var(self, i, attrs, value, value_type):
        name_item = QTableWidgetItem()
        name_item.setText(attrs['name'])
        self.setItem(i, 0, name_item)
        
        type_item = QTableWidgetItem()
        type_item.setText(attrs['type'].strip())
        self.setItem(i, 1, type_item)
        
        if attrs['loc'] == 1:
            addr_item = QTableWidgetItem()
            addr_item.setText(hex(attrs['addr']))
            self.setItem(i, 2, addr_item)            
        elif attrs['loc'] == 2:
            addr_item = QTableWidgetItem()
            addr_item.setText(attrs['addr'])
            self.setItem(i, 2, addr_item)
        
        value_item = QTableWidgetItem()
        value_item.setText(value)
        self.setItem(i, 3, value_item)

        value_item.value_type = value_type
        if value_type == 'hex':
            value_item.core_value = int(value, 16)
        elif value_type == 'array':
            arr = value.split(' ')
            for i in range(len(arr)):
                if arr[i] != '**' and arr[i] != 'Er':
                    arr[i] = int(arr[i], 16)
            value_item.core_value = arr

    def contextMenuEvent(self, event):
        col = self.columnAt(event.pos().x())
        row = self.rowAt(event.pos().y())
        if col == 3:
            item = self.item(row, col)
            vtype = item.value_type
            if vtype != 'unknown':
                menu = QMenu(self)
                as_int = QAction('repr as int', self)
                as_int.triggered.connect(lambda: self.repr_as_int(row, col))
                as_hex = QAction('repr as hex', self)
                as_hex.triggered.connect(lambda: self.repr_as_hex(row, col))
                as_flt = QAction('repr as floating', self)
                as_flt.triggered.connect(lambda: self.repr_as_floating(row, col))
                as_str = QAction('repr as str', self)
                as_str.triggered.connect(lambda: self.repr_as_str(row, col))
                as_bys = QAction('repr as bytes', self)
                as_bys.triggered.connect(lambda: self.repr_as_bytes(row, col))
                menu.addAction(as_int)
                menu.addAction(as_hex)
                menu.addAction(as_flt)
                menu.addAction(as_str)
                menu.addAction(as_bys)
                menu.popup(QCursor.pos())

    def repr_as_int(self, row, col):
        item = self.item(row, col)
        vtype = item.value_type
        dec_value = 0
        comment = ''
        if vtype == 'array':
            for i, v in enumerate(item.core_value):
                if v == '**' or v == 'Er':
                    comment = ' + unrecognizable'
                    break
                dec_value += v * 256 ** i
        elif vtype == 'hex':
            dec_value = item.core_value
        item.setText(str(dec_value) + comment)
    
    def repr_as_hex(self, row, col):
        item = self.item(row, col)
        vtype = item.value_type
        dec_value = 0
        comment = ''
        if vtype == 'array':
            for i, v in enumerate(item.core_value):
                if v == '**' or v == 'Er':
                    comment = ' + unrecognizable'
                    break
                dec_value += v * 256 ** i
        elif vtype == 'hex':
            dec_value = item.core_value
        item.setText(hex(dec_value) + comment)
        
    @staticmethod
    def nhex(n):
        h = hex(n)[2:]
        h = '0' + h if len(h) % 2 else h
        return h        

    def repr_as_str(self, row, col):
        item = self.item(row, col)
        vtype = item.value_type
        string = ''
        comment = ''
        if vtype == 'array':
            for v in item.core_value:
                if v == 0:
                    break
                if v == '**' or v == 'Er':
                    comment = ' + unrecognizable'
                    break
                string += chr(v)
        elif vtype == 'hex':
            h = self.nhex(item.core_value)
            string = unhexlify(h)[::-1]
            if '\x00' in string:
                string = string.partition('\x00')[0]
        item.setText(string + comment)
    
    def repr_as_bytes(self, row, col):
        item = self.item(row, col)
        vtype = item.value_type
        arr = []
        comment = ''
        if vtype == 'array':
            arr = [str(i) for i in item.value]
        elif vtype == 'hex':
            h = self.nhex(item.core_value)
            arr = [t[0] + t[1] for t in zip(h[0::2], h[1::2])][::-1]
        item.setText(' '.join(arr) + comment)
        
    def repr_as_floating(self, row, col):
        # TODO: seperate this into double / float
        item = self.item(row, col)
        vtype = item.value_type
        float_value = ''
        comment = ''
        if vtype == 'array':
            if len(item.core_value) != 8 and len(item.core_value) != 4:
                comment = 'Incompatitable size for floating number'
            elif '**' in item.core_value or 'Er' in item.core_value:
                comment = 'Unresolved'
            else:
                float_str = ''.join([self.nhex(i) for i in item.core_value])
                if len(item.core_value) == 8:
                    float_value = unpack('d', unhexlify(float_str))
                elif len(item.core_value) == 4:
                    float_value = unpack('f', unhexlify(float_str))
        elif vtype == 'hex':
            h = self.nhex(item.core_value)
            float_str = ''.join([t[0] + t[1] for t in zip(h[0::2], h[1::2])][::-1])
            float_value = unpack('d', unhexlify(float_str))
        item.setText(float_value + comment)
        