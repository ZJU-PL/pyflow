"""
B611: Test for unsafe PyTorch model loading.

PyTorch model loading with pickle can execute arbitrary code
during deserialization. Use weights_only=True when available.
"""
from ..core import issue
from ..core import test_properties as test


@test.checks("Call")
@test.with_id("B611")
def pytorch_load_unsafe(context):
    qualname = context.call_function_name_qual
    if qualname not in {
        "torch.load", "torch.hub.load",
        "torch.hub.download_url_to_file",
    }:
        return None

    if qualname == "torch.load":
        for kw in context.node.keywords:
            if kw.arg == "weights_only" and (
                (hasattr(kw.value, "value") and kw.value.value is True)
                or (hasattr(kw.value, "id") and kw.value.id == "True")
            ):
                return None
        return issue.Issue(
            severity="HIGH",
            confidence="MEDIUM",
            cwe=issue.Cwe.DOWNLOAD_OF_CODE_WITHOUT_INTEGRITY_CHECK,
            text="PyTorch model loading without weights_only=True. "
            "torch.load() uses pickle internally which can execute "
            "arbitrary code during deserialization. Use "
            "torch.load(weights_only=True) to mitigate this risk.",
        )

    return issue.Issue(
        severity="MEDIUM",
        confidence="MEDIUM",
        cwe=issue.Cwe.DOWNLOAD_OF_CODE_WITHOUT_INTEGRITY_CHECK,
        text="PyTorch hub loading from URL. Loading models from "
        "untrusted sources can execute arbitrary code. "
        "Verify the source integrity before loading.",
    )
