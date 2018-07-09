from PyQt5.QtWidgets import (
    QGraphicsItem, QGraphicsRectItem, 
    QGraphicsTextItem, QGraphicsPathItem,
    QGraphicsLineItem,
    QGraphicsScene, QGraphicsView,
)
from PyQt5.QtCore import QPointF, QLineF, QRectF, Qt
from PyQt5.QtGui import (
    QPainter, QPainterPath, QPen, QBrush, QColor
)

from typing import Tuple, Any

# FIXME: sometimes this will segfault, maybe weakref?


class StateEdgeText(QGraphicsTextItem):
    def __init__(self, state_index, from_addr, to_addr, manager):
        # type: (int, int, int, CallGraphManager) -> None
        text = '{} -> {}'.format(hex(from_addr), hex(to_addr))
        super(StateEdgeText, self).__init__(text)
        self.state_index = state_index
        self.manager = manager
        self.setFlag(QGraphicsItem.ItemIsSelectable)

    def update_pos(self, midpoint):
        # type: (QPointF) -> None
        self.setPos(midpoint)

    def mouseDoubleClickEvent(self, event):
        # type: (Any) -> None
        self.manager.double_click(self.state_index)
        event.accept()


class StateEdge(QGraphicsLineItem):
    def __init__(self, state_index, from_t, to_t, manager):
        # type: (int, Tuple[StateNode, QPointF, str, int], Tuple[StateNode, QPointF, str, int], CallGraphManager) -> None
        super(StateEdge, self).__init__(QLineF(from_t[1], to_t[1]))
        self.from_t = from_t
        self.to_t = to_t
        self.state_index = state_index
        self.manager = manager
        pen = QPen(QBrush(Qt.blue), 3, Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin)
        self.setPen(pen)
        self.setFlag(QGraphicsItem.ItemIsSelectable)
        self.text = StateEdgeText(state_index, from_t[3], to_t[3], manager)
        self.text.update_pos(self.midpoint())

    def midpoint(self):
        # type: () -> QPointF
        line = self.line()
        return QPointF(
            (line.x1() + line.x2()) / 2, 
            (line.y1() + line.y2()) / 2)

    def update_from(self, from_point):
        # type: (QPointF) -> None
        line = self.line()
        line.setP1(from_point)
        self.setLine(line)
        self.text.update_pos(self.midpoint())        

    def update_to(self, to_point):
        # type: (QPointF) -> None
        line = self.line()
        line.setP2(to_point)
        self.setLine(line)
        self.text.update_pos(self.midpoint())

    def mouseDoubleClickEvent(self, event):
        # type: (Any) -> None
        self.manager.double_click(self.state_index)
        event.accept()


class StateNode(QGraphicsRectItem):
    def __init__(self, name, index, addr, rect, text, manager):
        super(StateNode, self).__init__(rect)
        self.name = name
        self.index = index
        self.addr = addr
        self.text = QGraphicsTextItem(text)
        self.text.setPos(rect.topLeft())
        self.text.setTextWidth(rect.width() - 10)
        self.manager = manager
        self.setZValue(1)
        self.setFlag(QGraphicsItem.ItemIsMovable)
        self.setFlag(QGraphicsItem.ItemIsSelectable)
        self.setFlag(QGraphicsItem.ItemSendsGeometryChanges)
        self.edges = []
        self.str_to_node = {
            'right': self.right_node,
            'up': self.up_node,
            'left': self.left_node,
            'down': self.down_node
        }

    def set_text(self, text):
        # type: (str) -> None
        self.text.setPlainText(text)

    def right_node(self):
        # type: () -> QPointF
        rect = self.rect()
        return QPointF(self.x() + rect.x() + rect.width(), self.y() + rect.y() + rect.height() / 2)

    def up_node(self):
        # type: () -> QPointF
        rect = self.rect()
        return QPointF(self.x() + rect.x() + rect.width() / 2, self.y() + rect.y())

    def left_node(self):
        # type: () -> QPointF
        rect = self.rect()
        return QPointF(self.x() + rect.x(), self.y() + rect.y() + rect.height() / 2)

    def down_node(self):
        # type: () -> QPointF
        rect = self.rect()
        return QPointF(self.x() + rect.x()  + rect.width() / 2, self.y() + rect.y() + rect.height())

    def itemChange(self, change, value):
        # type: (Any, QPointF) -> None
        ret = QGraphicsRectItem.itemChange(self, change, value)        
        if change == QGraphicsItem.ItemPositionChange:
                self.text.setPos(self.rect().topLeft() + value)
                for edge in self.edges:
                    if edge.from_t[0] == self:
                        edge.update_from(self.str_to_node[edge.from_t[2]]())
                    else:
                        edge.update_to(self.str_to_node[edge.to_t[2]]())
        return ret 

    def __del__(self):
        # weird segfault
        del self.text


class CallGraphManager(object):
    NODE_MARGIN = 20
    NODE_WIDTH = 240
    NODE_HEIGHT = 100
    NODE_X = NODE_WIDTH + NODE_MARGIN
    NODE_Y = NODE_HEIGHT + NODE_MARGIN

    def __init__(self):
        self.scene = QGraphicsScene()
        self.nodes = []
        self.edges_index = []
        self.fname_to_index = {}
        self.size = 0
        self.view = None

    def double_click(self, state_index):
        # type: (int) -> None
        self.view.double_click(state_index)

    def create_node(self, fname, text, addr):
        # type: (str, str, int) -> StateNode
        rect = QRectF(
            self.NODE_X * (self.size % 8), 
            self.NODE_Y * (self.size // 8), 
            self.NODE_WIDTH, self.NODE_HEIGHT)
        node = StateNode(fname, self.size, addr, rect, text, self)
        self.nodes.append(node)
        self.fname_to_index[fname] = self.size
        self.size += 1
        self.scene.addItem(node)
        self.scene.addItem(node.text)
        return node

    def judge_ret(self, state):
        # type: (Any) -> bool
        insn = state.from_simstate.block().capstone.insns[0]
        return insn.mnemonic == 'ret'

    def get_text(self, fname, simstate):
        # type: (str, Any) -> str
        insns = simstate.block().capstone.insns
        text = fname
        '''
        for i in range(min(2, len(insns))):
            text += '\n' + str(insns[i])
        '''
        return text

    def get_func_node(self, state, tracer):
        # type: (Any, Any) -> Tuple[StateNode, StateNode]
        addr_sym = tracer.filter.find_function(state.branch.addr)
        ip_sym = tracer.filter.find_function(state.branch.ip)
        if not addr_sym or not ip_sym:
            raise Exception("Unable to find symbols for %x and %x", 
                state.branch.addr, state.branch.ip)
        addr_name = addr_sym.name
        ip_name = ip_sym.name
        addr_node = None
        ip_node = None
        if addr_name in self.fname_to_index.keys():
            addr_node = self.nodes[self.fname_to_index[addr_name]]
        else:
            text = self.get_text(addr_name, state.from_simstate)
            addr_node = self.create_node(addr_name, text, state.branch.addr)
        if ip_name in self.fname_to_index.keys():
            ip_node = self.nodes[self.fname_to_index[ip_name]]
        else:
            text = self.get_text(ip_name, state.to_simstate)
            ip_node = self.create_node(ip_name, text, state.branch.ip)
        return addr_node, ip_node

    def connect_node(self, state_index, addr_node, ip_node):
        # type: (int, StateNode, StateNode) -> None
        addr_index = addr_node.index
        ip_index = ip_node.index
        if addr_index == ip_index:
            return
        if addr_index > ip_index:
            addr_index, ip_index = ip_index, addr_index
        if (addr_index, ip_index) not in self.edges_index:
            edge = StateEdge(
                state_index,
                (addr_node, addr_node.right_node(), 'right', addr_node.addr),
                (ip_node, ip_node.left_node(), 'left', ip_node.addr),
                self
            )
            self.scene.addItem(edge)
            self.scene.addItem(edge.text)
            self.edges_index.append((addr_index, ip_index))
            addr_node.edges.append(edge)
            ip_node.edges.append(edge)

    def add_node(self, state, tracer):
        # type: (Any, Any) -> None
        if not self.judge_ret(state):
            addr_node, ip_node = self.get_func_node(state, tracer)
            self.connect_node(state.index, addr_node, ip_node)


class CallGraphView(QGraphicsView):
    def __init__(self, manager, window, parent=None):
        super(CallGraphView, self).__init__(parent)
        manager.view = self
        self.setScene(manager.scene)
        self.setRenderHint(QPainter.Antialiasing)
        self.resize(800, 600)
        self.window = window
        self.show()

    def double_click(self, state_index):
        # type: (int) -> None
        self.window.update_active_index(state_index)
        self.close()