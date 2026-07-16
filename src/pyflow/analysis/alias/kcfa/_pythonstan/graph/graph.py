from abc import ABC, abstractmethod
from typing import Collection


class Node(ABC):
    @abstractmethod
    def get_idx(self) -> int:
        pass

    @abstractmethod
    def get_name(self) -> str:
        pass


class Edge(ABC):
    @abstractmethod
    def set_src(self, node: Node):
        pass

    @abstractmethod
    def set_tgt(self, node: Node):
        pass

    @abstractmethod
    def get_src(self) -> Node:
        pass

    @abstractmethod
    def get_tgt(self) -> Node:
        pass

    @abstractmethod
    def get_name(self) -> str:
        pass


class Graph(ABC):
    @abstractmethod
    def in_degree_of(self, node: Node) -> int:
        pass

    @abstractmethod
    def out_degree_of(self, node: Node) -> int:
        pass

    @abstractmethod
    def preds_of(self, node: Node) -> Collection[Node]:
        pass

    @abstractmethod
    def succs_of(self, node: Node) -> Collection[Node]:
        pass

    @abstractmethod
    def get_entry(self) -> Node:
        pass

    @abstractmethod
    def get_exit(self) -> Node:
        pass

    @abstractmethod
    def add_node(self, node: Node):
        pass

    @abstractmethod
    def add_edge(self, edge: Edge):
        pass

    @abstractmethod
    def delete_node(self, node: Node):
        pass

    @abstractmethod
    def delete_edge(self, edge: Edge):
        pass

    @abstractmethod
    def get_nodes(self) -> Collection[Node]:
        pass
    