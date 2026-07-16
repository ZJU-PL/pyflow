"""Context selection strategy for different sensitivity policies.

This module implements context selection for various context-sensitive policies.
"""

from enum import Enum
from typing import Optional, Tuple
from .context import (
    AbstractContext,
    CallStringContext,
    ObjectContext,
    TypeContext,
    ReceiverContext,
    HybridContext,
    ParamContext,
    CallSite,
)
from .object import AbstractObject, InstanceObject

__all__ = ["ContextPolicy", "ContextSelector", "parse_policy"]


class ContextPolicy(Enum):
    """Available context sensitivity policies."""
    
    INSENSITIVE = "0-cfa"
    CALL_1 = "1-cfa"
    CALL_2 = "2-cfa"
    CALL_3 = "3-cfa"
    OBJ_1 = "1-obj"
    OBJ_2 = "2-obj"
    OBJ_3 = "3-obj"
    TYPE_1 = "1-type"
    TYPE_2 = "2-type"
    TYPE_3 = "3-type"
    RECEIVER_1 = "1-rcv"
    RECEIVER_2 = "2-rcv"
    RECEIVER_3 = "3-rcv"
    PARAM_1 = "1-param"
    PARAM_2 = "2-param"
    PARAM_3 = "3-param"
    HYBRID_CALL1_OBJ1 = "1c1o"
    HYBRID_CALL2_OBJ1 = "2c1o"
    HYBRID_CALL1_OBJ2 = "1c2o"


class ContextSelector:
    """Selects contexts based on policy."""
    
    def __init__(self, policy: ContextPolicy = ContextPolicy.CALL_2):
        """Initialize context selector.
        
        Args:
            policy: Context sensitivity policy
        """
        self.policy = policy
        self._empty_context = self._create_empty_context()
    
    def _create_empty_context(self) -> AbstractContext:
        """Create empty context for policy."""
        if self.policy == ContextPolicy.INSENSITIVE:
            return CallStringContext((), 0)
        elif self.policy == ContextPolicy.CALL_1:
            return CallStringContext((), 1)
        elif self.policy == ContextPolicy.CALL_2:
            return CallStringContext((), 2)
        elif self.policy == ContextPolicy.CALL_3:
            return CallStringContext((), 3)
        elif self.policy == ContextPolicy.OBJ_1:
            return ObjectContext((), 1)
        elif self.policy == ContextPolicy.OBJ_2:
            return ObjectContext((), 2)
        elif self.policy == ContextPolicy.OBJ_3:
            return ObjectContext((), 3)
        elif self.policy == ContextPolicy.TYPE_1:
            return TypeContext((), 1)
        elif self.policy == ContextPolicy.TYPE_2:
            return TypeContext((), 2)
        elif self.policy == ContextPolicy.TYPE_3:
            return TypeContext((), 3)
        elif self.policy == ContextPolicy.RECEIVER_1:
            return ReceiverContext((), 1)
        elif self.policy == ContextPolicy.RECEIVER_2:
            return ReceiverContext((), 2)
        elif self.policy == ContextPolicy.RECEIVER_3:
            return ReceiverContext((), 3)        
        elif self.policy == ContextPolicy.PARAM_1:
            return ParamContext((), 1)
        elif self.policy == ContextPolicy.PARAM_2:
            return ParamContext((), 2)
        elif self.policy == ContextPolicy.PARAM_3:
            return ParamContext((), 3)
        elif self.policy == ContextPolicy.HYBRID_CALL1_OBJ1:
            return HybridContext((), (), 1, 1)
        elif self.policy == ContextPolicy.HYBRID_CALL2_OBJ1:
            return HybridContext((), (), 2, 1)
        elif self.policy == ContextPolicy.HYBRID_CALL1_OBJ2:
            return HybridContext((), (), 1, 2)
        else:
            raise ValueError(f"Unknown policy: {self.policy}")
    
    def empty_context(self) -> AbstractContext:
        """Get empty context."""
        return self._empty_context
    
    def select_call_context(
        self,
        call_site: CallSite,
        caller_ctx: AbstractContext,
        callee_obj: Optional['AbstractObject']=None,
        params: Optional[Tuple['AbstractObject', ...]]=None,
    ) -> AbstractContext:
        """Select context for function call.
        
        Args:
            caller_ctx: Current calling context
            call_site: Call site being invoked
            callee: Name of the called function
            receiver_alloc: Allocation site of receiver (for method calls)
            receiver_type: Type of receiver (for method calls)
        
        Returns:
            New context for the called function
        """
        if self.policy == ContextPolicy.INSENSITIVE:
            return caller_ctx
        
        elif self.policy in (ContextPolicy.CALL_1, ContextPolicy.CALL_2, ContextPolicy.CALL_3):
            if isinstance(caller_ctx, CallStringContext):
                return caller_ctx.append(call_site)
            else:
                return self._empty_context.append(call_site)
        
        elif self.policy in (ContextPolicy.OBJ_1, ContextPolicy.OBJ_2, ContextPolicy.OBJ_3):
            if not isinstance(caller_ctx, ObjectContext):
                caller_ctx = ObjectContext((), self._get_depth())
            if callee_obj:
                return caller_ctx.append(callee_obj)
            else:
                return caller_ctx.append(call_site)
        
        elif self.policy in (ContextPolicy.TYPE_1, ContextPolicy.TYPE_2, ContextPolicy.TYPE_3):
            if not isinstance(caller_ctx, TypeContext):
                caller_ctx = TypeContext((), self._get_depth())
            if callee_obj:
                if isinstance(callee_obj, InstanceObject):
                    return caller_ctx.append(callee_obj.class_obj)
                else:
                    return caller_ctx.append(callee_obj)
            else:
                return caller_ctx.append(call_site)
        
        elif self.policy in (ContextPolicy.RECEIVER_1, ContextPolicy.RECEIVER_2, ContextPolicy.RECEIVER_3):
            if not isinstance(caller_ctx, ReceiverContext):
                caller_ctx = ReceiverContext((), self._get_depth())
            if callee_obj:
                return caller_ctx.append(callee_obj.alloc_site)
            else:
                return caller_ctx.append(call_site)
        
        elif self.policy in (ContextPolicy.PARAM_1, ContextPolicy.PARAM_2, ContextPolicy.PARAM_3):
            if not isinstance(caller_ctx, ParamContext):
                caller_ctx = ParamContext((), self._get_depth())
            if params and len(params) > 0:
                return caller_ctx.append(params)
            else:
                # return caller_ctx.append(call_site)
                return caller_ctx

        elif self.policy in (ContextPolicy.HYBRID_CALL1_OBJ1, 
                            ContextPolicy.HYBRID_CALL2_OBJ1,
                            ContextPolicy.HYBRID_CALL1_OBJ2):
            if not isinstance(caller_ctx, HybridContext):
                caller_ctx = HybridContext((), (), self._get_call_k(), self._get_obj_depth())
            if callee_obj:
                return caller_ctx.append(call_site, callee_obj)
            else:
                return caller_ctx.append(call_site, None)
        else:
            raise ValueError(f"Unknown policy: {self.policy}")
    
    def select_alloc_context(
        self,
        current_ctx: AbstractContext,
        alloc_site: 'AbstractObject',
        alloc_type: Optional['AbstractObject'] = None
    ) -> AbstractContext:
        """Select context for object allocation.
        
        Args:
            current_ctx: Current context
            alloc_site: Allocation site identifier
            alloc_type: Type being allocated (optional)
        
        Returns:
            Context for the allocated object
        """
        if self.policy in (ContextPolicy.OBJ_1, ContextPolicy.OBJ_2, ContextPolicy.OBJ_3):
            if isinstance(current_ctx, ObjectContext):
                return current_ctx.append(alloc_site)
            else:
                ctx = ObjectContext((), self._get_depth())
                return ctx.append(alloc_site)
        
        elif self.policy in (ContextPolicy.TYPE_1, ContextPolicy.TYPE_2, ContextPolicy.TYPE_3):
            # For TYPE-sensitive policies, use alloc_type if provided, otherwise alloc_site
            type_elem = alloc_type if alloc_type is not None else alloc_site
            if isinstance(current_ctx, TypeContext):
                return current_ctx.append(type_elem)
            else:
                ctx = TypeContext((), self._get_depth())
                return ctx.append(type_elem)
        
        elif self.policy in (ContextPolicy.HYBRID_CALL1_OBJ1,
                            ContextPolicy.HYBRID_CALL2_OBJ1,
                            ContextPolicy.HYBRID_CALL1_OBJ2):
            if isinstance(current_ctx, HybridContext):
                return current_ctx.append_object(alloc_site)
            else:
                ctx = HybridContext((), (), self._get_call_k(), self._get_obj_depth())
                return ctx.append_object(alloc_site)
        
        else:
            return current_ctx
    
    def _get_depth(self) -> int:
        """Get depth parameter for current policy."""
        if self.policy in (ContextPolicy.OBJ_1, ContextPolicy.TYPE_1, ContextPolicy.PARAM_1, ContextPolicy.HYBRID_CALL1_OBJ1, ContextPolicy.RECEIVER_1):
            return 1
        elif self.policy in (ContextPolicy.OBJ_2, ContextPolicy.TYPE_2, ContextPolicy.PARAM_2, ContextPolicy.RECEIVER_2):
            return 2
        elif self.policy in (ContextPolicy.OBJ_3, ContextPolicy.TYPE_3, ContextPolicy.PARAM_3, ContextPolicy.RECEIVER_3):
            return 3
        elif self.policy in (ContextPolicy.HYBRID_CALL1_OBJ2, ContextPolicy.HYBRID_CALL2_OBJ1):
            return 2
        else:
            return 1
    
    def _get_call_k(self) -> int:
        """Get call-string depth for hybrid policies."""
        if self.policy in (ContextPolicy.HYBRID_CALL2_OBJ1,):
            return 2
        else:
            return 1
    
    def _get_obj_depth(self) -> int:
        """Get object depth for hybrid policies."""
        if self.policy == ContextPolicy.HYBRID_CALL1_OBJ2:
            return 2
        else:
            return 1
    
    def __repr__(self) -> str:
        return f"ContextSelector(policy={self.policy.value})"


def parse_policy(policy_str: str) -> ContextPolicy:
    """Parse policy string to enum.
    
    Args:
        policy_str: Policy string (e.g., "2-cfa", "1-obj")
    
    Returns:
        ContextPolicy enum value
    
    Raises:
        ValueError: If policy string is not recognized
    """
    policy_map = {
        "0-cfa": ContextPolicy.INSENSITIVE,
        "1-cfa": ContextPolicy.CALL_1,
        "2-cfa": ContextPolicy.CALL_2,
        "3-cfa": ContextPolicy.CALL_3,
        "1-obj": ContextPolicy.OBJ_1,
        "2-obj": ContextPolicy.OBJ_2,
        "3-obj": ContextPolicy.OBJ_3,
        "1-type": ContextPolicy.TYPE_1,
        "2-type": ContextPolicy.TYPE_2,
        "3-type": ContextPolicy.TYPE_3,
        "1-rcv": ContextPolicy.RECEIVER_1,
        "2-rcv": ContextPolicy.RECEIVER_2,
        "3-rcv": ContextPolicy.RECEIVER_3,
        "1-param": ContextPolicy.PARAM_1,
        "2-param": ContextPolicy.PARAM_2,
        "3-param": ContextPolicy.PARAM_3,
        "1c1o": ContextPolicy.HYBRID_CALL1_OBJ1,
        "2c1o": ContextPolicy.HYBRID_CALL2_OBJ1,
        "1c2o": ContextPolicy.HYBRID_CALL1_OBJ2,
    }
    
    if policy_str not in policy_map:
        raise ValueError(
            f"Unknown policy: {policy_str}. "
            f"Available policies: {', '.join(policy_map.keys())}"
        )
    
    return policy_map[policy_str]
