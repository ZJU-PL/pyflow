"""
@description
---------------------
Holds the known exceptions for the codeql_driver module.
"""

class CodeQLDriverExceptions:
  """
  Given the raw stderr output of a CodeQL command, we do the error attribution here.
  """
  @staticmethod
  def handle_build_exception(stderr):
    """
    Check if the stderr is an error message from CodeQL.

    Known error messages:
    - <NoPythonCodeFoundException>

    @param stderr: The stderr output from a CodeQL command.
    @return error_log_message: The error message to log.
    """
    error_log_message = None
    if "CodeQL did not detect any code written in languages" in stderr:
      error_log_message = "NoPythonCodeFoundException: No Python code found in the repository."
    elif "but not any written in Python" in stderr:
      error_log_message = "NoPythonCodeFoundException: No Python code found in the repository."
    elif "CodeQL did not detect any code written in languages supported by this CodeQL distribution" in stderr:
      error_log_message = "NoSupportedCodeFoundException: No supported code found in the repository."
    elif "CodeQL detected code written in Python but could not process any of it." in stderr:
      error_log_message = "NoSupportedPythonCodeFound: No supported code found in the repository."
    else:
      error_log_message = f"UnknownError: {stderr}"

    return error_log_message
  
  @staticmethod
  def handle_query_exception(stderr):
    """
    Check if the stderr is an error message from CodeQL.

    Known error messages:
    - <TimeoutExpired>

    @param stderr: The stderr output from a CodeQL command.
    @return error_log_message: The error message to log.
    """

    error_log_message = None

    if "timed out" in stderr:
      error_log_message = "TimeoutExpired: CodeQL command timed out."
    else:
      error_log_message = f"UnknownError: {stderr}"
    
    return error_log_message
  