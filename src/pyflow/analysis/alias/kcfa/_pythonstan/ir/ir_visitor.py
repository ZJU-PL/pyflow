from abc import ABC
from .ir_statements import IRStatement

__all__ = ['IRVisitor']


class IRVisitor(ABC):
    def visit(self, ir: IRStatement):
        # Try to find a visitor method for this class or any of its parent classes
        for cls in ir.__class__.__mro__:
            cls_name = cls.__name__
            m_name = f"visit_{cls_name}"
            if hasattr(self, m_name):
                m = getattr(self, m_name)
                return m(ir)
        
        # If no visitor method was found, use the default
        return self.visit_default(ir)

    def visit_default(self, ir: IRStatement):
        pass
