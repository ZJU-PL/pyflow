"""
B612: Test for unsafe HuggingFace model/download usage.

HuggingFace model loading and dataset operations can execute
arbitrary code from untrusted sources.
"""
from ..core import issue
from ..core import test_properties as test

HF_UNTRUSTED_FUNCTIONS = {
    "transformers.pipeline",
    "transformers.AutoModel.from_pretrained",
    "transformers.AutoTokenizer.from_pretrained",
    "transformers.AutoModelForSequenceClassification.from_pretrained",
    "transformers.TFAutoModel.from_pretrained",
    "datasets.load_dataset",
    "datasets.load_from_disk",
}


@test.checks("Call")
@test.with_id("B612")
def huggingface_unsafe_load(context):
    qualname = context.call_function_name_qual
    if qualname not in HF_UNTRUSTED_FUNCTIONS:
        return None
    for kw in context.node.keywords:
        if kw.arg == "use_auth_token" and (
            (hasattr(kw.value, "value") and kw.value.value is True)
            or (hasattr(kw.value, "id") and kw.value.id == "True")
        ):
            return issue.Issue(
                severity="LOW",
                confidence="MEDIUM",
                cwe=issue.Cwe.DOWNLOAD_OF_CODE_WITHOUT_INTEGRITY_CHECK,
                text="HuggingFace model/dataset loading with "
                "authentication token. Ensure the token is not "
                "hardcoded and the source is trusted.",
            )
    return issue.Issue(
        severity="MEDIUM",
        confidence="MEDIUM",
        cwe=issue.Cwe.DOWNLOAD_OF_CODE_WITHOUT_INTEGRITY_CHECK,
        text="HuggingFace model/dataset loading from potentially "
        "untrusted source. Pretrained models can execute arbitrary "
        "code. Always verify the model source and use trusted "
        "repositories only.",
    )
