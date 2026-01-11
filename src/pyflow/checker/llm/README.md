# LLM-based Bug Report Analysis

At present, we do not use an agent-based approach where an LLM leverages tools to automatically extract related code context.

Our approach is deliberately straightforward: the static analyzer provides the bug report (which may include bug descriptions, relevant source code snippets, documentation, etc.) directly to the LLM.