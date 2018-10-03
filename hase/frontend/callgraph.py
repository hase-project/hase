from __future__ import absolute_import, division, print_function

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
# NOTE: requires matplotlib, scipy
from networkx import Graph, kamada_kawai_layout
from math import hypot

from typing import Tuple, Any, List, Union, Optional

from ..errors import HaseError

class StateEdgeArrow(QGraphicsLineItem):
    def __init__(self, line):
        # type: (QLineF) -> None
        super(StateEdgeArrow, self).__init__(line)
        pen = QPen(QBrush(Qt.blue), 2, Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin)
        self.setPen(pen)

    def update_pos(self, line):
        # type: (QLineF) -> None
        self.setLine(line)


class StateEdgeText(QGraphicsTextItem):
    def __init__(self, state_index, from_addr, to_addr, times, manager):
        # type: (List[int], int, int, int, CallGraphManager) -> None
        # text = '{} -> {}'.format(hex(from_addr), hex(to_addr))
        self.times = times
        text = '[{} times]'.format(self.times)
        super(StateEdgeText, self).__init__(text)
        self.state_index = state_index
        self.manager = manager
        self.setFlag(QGraphicsItem.ItemIsSelectable)

    def update_text(self, times):
        text = '[{} times]'.format(times)
        self.setPlainText(text)

    def update_pos(self, midpoint):
        # type: (QPointF) -> None
        self.setPos(midpoint)

    def mouseDoubleClickEvent(self, event):
        # type: (Any) -> None
        self.manager.double_click(self.state_index[0])
        event.accept()


class StateEdge(QGraphicsLineItem):
    def __init__(self, state_index, from_t, to_t, times, manager):
        # type: (List[int], list, list, int, CallGraphManager) -> None
        super(StateEdge, self).__init__(QLineF(from_t[1], to_t[1]))
        self.from_t = from_t
        self.to_t = to_t
        self.state_index = state_index
        self.manager = manager
        self.times = times
        pen = QPen(QBrush(Qt.blue), 2, Qt.DotLine, Qt.RoundCap, Qt.RoundJoin)
        self.setPen(pen)
        self.setFlag(QGraphicsItem.ItemIsSelectable)
        self.text = StateEdgeText(state_index, from_t[3], to_t[3], self.times, manager)
        self.text.update_pos(self.midpoint())
        # self.text.hide()
        up_line, down_line = self.arrow_line()
        self.up_line = StateEdgeArrow(up_line)
        self.down_line = StateEdgeArrow(down_line)

    def arrow_line(self):
        # type: () -> Tuple[QLineF, QLineF]
        line = self.line()
        angle = line.angle()
        up_line = QLineF.fromPolar(10, angle + 165)
        down_line = QLineF.fromPolar(10, angle - 165)
        up_line.setP1(self.to_t[1])
        down_line.setP1(self.to_t[1])
        up_line.setP2(self.to_t[1] + up_line.p2())
        down_line.setP2(self.to_t[1] + down_line.p2())
        return up_line, down_line

    def midpoint(self):
        # type: () -> QPointF
        line = self.line()
        return QPointF(
            (line.x1() + line.x2()) / 2,
            (line.y1() + line.y2()) / 2)

    def update_pos(self):
        # type: () -> None
        addr_node = self.from_t[0]
        ip_node = self.to_t[0]
        edge_dir = CallGraphManager.edge_direction(addr_node, ip_node)
        self.from_t = list((addr_node,) +  edge_dir[0] + (addr_node.addr,))
        self.to_t = list((ip_node,) +  edge_dir[1] + (ip_node.addr,))
        self.setLine(QLineF(self.from_t[1], self.to_t[1]))
        self.text.update_pos(self.midpoint())
        up_line, down_line = self.arrow_line()
        self.up_line.update_pos(up_line)
        self.down_line.update_pos(down_line)

    def mouseDoubleClickEvent(self, event):
        # type: (Any) -> None
        self.manager.double_click(self.state_index[0])
        event.accept()


class StateNode(QGraphicsRectItem):
    def __init__(self, name, index, addr, rect, text, manager):
        # type: (str, int, int, QRectF, str, CallGraphManager) -> None
        self.text = QGraphicsTextItem(text)
        self.text_width = self.text.boundingRect().width()
        if self.text_width > rect.width() - 6:
            rect.setWidth(self.text_width + 6)
        self.text_height = self.text.boundingRect().height()
        if self.text_height > rect.height() - 6:
            rect.setHeight(self.text_height + 6)
        super(StateNode, self).__init__(rect)
        self.name = name
        self.index = index
        self.addr = addr
        self.text.setPos(rect.topLeft() + QPointF((rect.width() - self.text_width) / 2, 0))
        self.manager = manager
        self.setZValue(1)
        self.setFlag(QGraphicsItem.ItemIsMovable)
        self.setFlag(QGraphicsItem.ItemIsSelectable)
        self.setFlag(QGraphicsItem.ItemSendsGeometryChanges)
        self.edges = []  # type: List[StateEdge]
        self.str_to_node = {
            'right': self.right_node,
            'top': self.top_node,
            'left': self.left_node,
            'down': self.down_node,
            'top_left': self.tl_node,
            'top_right': self.tr_node,
            'down_left': self.dl_node,
            'down_right': self.dr_node,
        }

    def set_text(self, text):
        # type: (str) -> None
        self.text.setPlainText(text)

    def right_node(self):
        # type: () -> QPointF
        rect = self.rect()
        return QPointF(self.x() + rect.x() + rect.width(), self.y() + rect.y() + rect.height() / 2)

    def top_node(self):
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

    def tl_node(self):
        # type: () -> QPointF
        rect = self.rect()
        return QPointF(self.x() + rect.x(), self.y() + rect.y())

    def tr_node(self):
        # type: () -> QPointF
        rect = self.rect()
        return QPointF(self.x() + rect.x() + rect.width(), self.y() + rect.y())

    def dl_node(self):
        # type: () -> QPointF
        rect = self.rect()
        return QPointF(self.x() + rect.x(), self.y() + rect.y() + rect.height())

    def dr_node(self):
        # type: () -> QPointF
        rect = self.rect()
        return QPointF(self.x() + rect.x() + rect.width(), self.y() + rect.y() + rect.height())

    def set_text_edge(self, x, y):
        # type: (float, float) -> None
        self.text.setPos(self.rect().topLeft() + QPointF(x, y) + QPointF((self.rect().width() - self.text_width) / 2, 0))
        for edge in self.edges:
            edge.update_pos()

    def itemChange(self, change, value):
        # type: (Any, QPointF) -> None
        if change == QGraphicsItem.ItemPositionChange:
            self.set_text_edge(value.x(), value.y())
        return QGraphicsRectItem.itemChange(self, change, value)

    def __del__(self):
        # weird segfault
        del self.text

    def __hash__(self):
        return hash((self.name, self.addr))


class CallGraphManager(object):
    NODE_MARGIN = 20
    NODE_WIDTH = 100
    NODE_HEIGHT = 30
    NODE_X = NODE_WIDTH + NODE_MARGIN
    NODE_Y = NODE_HEIGHT + NODE_MARGIN

    def __init__(self):
        self.scene = None
        self.nodes = []
        self.edges_index = []
        self.fname_to_index = {}
        self.size = 0
        self.view = None
        self.graph = Graph()
        self.valid_scene = True

    def double_click(self, state_index):
        # type: (int) -> None
        self.view.double_click(state_index)

    @staticmethod
    def edge_direction(addr_node, ip_node):
        # type: (StateNode, StateNode) -> Tuple[Tuple[QPointF, str], Tuple[QPointF, str]]
        edge_selections = [
            ('top', 'down'),
            # ('top_right', 'down_left'),
            ('right', 'left'),
            # ('down_right', 'top_left'),
            ('down', 'top'),
            # ('down_left', 'top_right'),
            ('left', 'right'),
            # ('top_left', 'down_right'),
        ]
        min_dis = 0x7FFFFFFF + 0.1
        min_select = ('top', 'down')
        min_pos = (addr_node.top_node(), ip_node.down_node())
        for select in edge_selections:
            addr_pos = addr_node.str_to_node[select[0]]()
            ip_pos = ip_node.str_to_node[select[1]]()
            dis = hypot(addr_pos.x() - ip_pos.x(), addr_pos.y() - ip_pos.y())
            if dis < min_dis:
                min_dis = dis
                min_select = select
                min_pos = (addr_pos, ip_pos)
        return ((min_pos[0], min_select[0]), (min_pos[1], min_select[1]))

    def create_node(self, fname, text, addr):
        # type: (str, str, int) -> StateNode
        rect = QRectF(
            0, 0,
            self.NODE_WIDTH, self.NODE_HEIGHT)
        node = StateNode(fname, self.size, addr, rect, text, self)
        self.nodes.append(node)
        self.graph.add_node(node)
        self.fname_to_index[fname] = self.size
        self.size += 1
        self.valid_scene = False
        return node

    def clear_cache(self):
        self.nodes = []
        self.edges_index = {}
        self.fname_to_index = {}
        self.size = 0
        self.view = None
        self.graph = Graph()
        self.valid_scene = True

    def create_edge(self, addr_index, ip_index, state_index, times):
        addr_node = self.nodes[addr_index]
        ip_node = self.nodes[ip_index]
        edge_dir = CallGraphManager.edge_direction(addr_node, ip_node)
        edge = StateEdge(
            state_index,
            list((addr_node,) +  edge_dir[0] + (addr_node.addr,)),
            list((ip_node,) +  edge_dir[1] + (ip_node.addr,)),
            times,
            self
        )
        addr_node.edges.append(edge)
        ip_node.edges.append(edge)
        return edge

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
            raise HaseError("Unable to find symbols for %x and %x",
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
        if (addr_index, ip_index) not in self.edges_index.keys():
            self.graph.add_edge(addr_node, ip_node)
            self.edges_index[(addr_index, ip_index)] = [[state_index], 1]
        else:
            self.edges_index[(addr_index, ip_index)][0].append(state_index)
            self.edges_index[(addr_index, ip_index)][1] += 1
        self.valid_scene = False

    def add_node(self, state, tracer):
        # type: (Any, Any) -> None
        if not self.judge_ret(state):
            addr_node, ip_node = self.get_func_node(state, tracer)
            self.connect_node(state.index, addr_node, ip_node)

    def create_scene(self, scale):
        # we need to create everytime, since C++ wrapper will delete this scene
        self.scene = QGraphicsScene()
        # best among networkx algorithms (boost has a Gursoy-Atun)
        layout = kamada_kawai_layout(self.graph, scale=scale)
        for node, pos in layout.items():
            node.setPos(pos[0], pos[1])
            node.edges = []
            self.scene.addItem(node)
            self.scene.addItem(node.text)
        for edge_index, v in self.edges_index.items():
            edge = self.create_edge(edge_index[0], edge_index[1], v[0], v[1])
            self.scene.addItem(edge)
            self.scene.addItem(edge.text)
            self.scene.addItem(edge.up_line)
            self.scene.addItem(edge.down_line)
        return self.scene


class CallGraphView(QGraphicsView):
    def __init__(self, manager, window, parent=None):
        # type: (CallGraphManager, Any, Optional[Any]) -> None
        super(CallGraphView, self).__init__(parent)
        manager.view = self
        self.setScene(manager.create_scene(400 + len(manager.nodes) * 20))
        self.setRenderHint(QPainter.Antialiasing)
        self.resize(1000, 1000)
        self.window = window
        self.show()

    def double_click(self, state_index):
        # type: (int) -> None
        self.window.update_active_index(state_index)
        self.close()
