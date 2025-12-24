"""
Blacklist System for Security Checkers.

This module provides a blacklist system for identifying dangerous function
calls and module imports. The blacklist contains patterns for functions,
methods, and modules that are known to have security implications.

**Blacklist Categories:**
- Deserialization: pickle, marshal, etc.
- Weak Cryptography: MD5, SHA1, weak ciphers
- Command Injection: eval, subprocess with shell=True
- XML Attacks: Vulnerable XML parsers
- Insecure Protocols: telnet, FTP
- And many more...

**Pattern Matching:**
Blacklist items support both exact matches and wildcard patterns (using
fnmatch), allowing flexible matching of function/module names.
"""

import fnmatch
import logging
from . import issue

LOG = logging.getLogger(__name__)


class BlacklistItem:
    """
    Represents a single blacklist item (dangerous function/import).
    
    A blacklist item defines:
    - A set of qualified names (patterns) to match
    - A test ID (e.g., "B301")
    - A CWE classification
    - A severity level
    - A message template
    
    **Pattern Matching:**
    Supports both exact matches and wildcard patterns (e.g., "pickle.*")
    using fnmatch for flexible matching.
    
    Attributes:
        name: Human-readable name for this blacklist item
        id: Test ID (e.g., "B301")
        cwe: CWE identifier
        message: Message template (may include {name} placeholder)
        qualnames: List of qualified name patterns to match
        level: Severity level (HIGH, MEDIUM, LOW)
    """
    def __init__(self, name, bid, cwe, qualnames, message, level="MEDIUM"):
        """
        Initialize a blacklist item.
        
        Args:
            name: Human-readable name
            bid: Test ID (e.g., "B301")
            cwe: CWE identifier
            qualnames: List of qualified name patterns
            message: Message template
            level: Severity level (default: MEDIUM)
        """
        self.name = name
        self.id = bid
        self.cwe = cwe
        self.message = message
        self.qualnames = qualnames
        self.level = level

    def matches(self, qualname):
        """
        Check if a qualified name matches this blacklist item.
        
        Tests the qualified name against all patterns in this item.
        
        Args:
            qualname: Qualified name to check (e.g., "pickle.loads")
            
        Returns:
            True if any pattern matches, False otherwise
        """
        return any(self._matches_pattern(qualname, pattern) for pattern in self.qualnames)

    def _matches_pattern(self, qualname, pattern):
        """
        Check if qualname matches a specific pattern.
        
        Uses fnmatch for wildcard patterns, exact match otherwise.
        
        Args:
            qualname: Qualified name to check
            pattern: Pattern to match against
            
        Returns:
            True if matches, False otherwise
        """
        return fnmatch.fnmatch(qualname, pattern) if "*" in pattern else qualname == pattern

    def create_issue(self, context, qualname):
        """
        Create a security issue for this blacklist item.
        
        Creates an Issue object with HIGH confidence (blacklist matches
        are considered high confidence since they're based on known patterns).
        
        Args:
            context: Context object with node information
            qualname: Qualified name that matched
            
        Returns:
            Issue object
        """
        return issue.Issue(
            severity=self.level,
            confidence="HIGH",
            cwe=self.cwe,
            text=self.message.format(name=qualname),
            test_id=self.id,
            ident=qualname,
            lineno=context.node.lineno if hasattr(context, 'node') else None,
            col_offset=context.node.col_offset if hasattr(context, 'node') else -1,
        )


class BlacklistManager:
    """
    Manages blacklist items for different node types.
    
    The BlacklistManager maintains separate blacklists for:
    - Call: Function/method calls (e.g., pickle.loads)
    - Import: Module imports (e.g., import pickle)
    - ImportFrom: From imports (e.g., from pickle import loads)
    
    **Blacklist Categories:**
    - Deserialization vulnerabilities (pickle, marshal)
    - Weak cryptography (MD5, SHA1, weak ciphers)
    - Command injection (eval, subprocess)
    - XML vulnerabilities (vulnerable parsers)
    - Insecure protocols (telnet, FTP)
    - And many more security issues
    
    Attributes:
        blacklists: Dictionary mapping node types to lists of BlacklistItem
    """
    
    def __init__(self):
        """Initialize the blacklist manager and load all blacklists."""
        self.blacklists = {"Call": [], "Import": [], "ImportFrom": []}
        self._load_blacklists()

    def _load_blacklists(self):
        """Load all blacklist items from internal definitions."""
        self._load_call_blacklists()
        self._load_import_blacklists()

    def _load_call_blacklists(self):
        """Load blacklist items for function calls"""
        call_data = [
            ("pickle", "B301", issue.Cwe.DESERIALIZATION_OF_UNTRUSTED_DATA, "MEDIUM",
             ["pickle.loads", "pickle.load", "pickle.Unpickler", "dill.loads", "dill.load", 
              "dill.Unpickler", "shelve.open", "shelve.DbfilenameShelf", "jsonpickle.decode",
              "jsonpickle.unpickler.decode", "jsonpickle.unpickler.Unpickler", "pandas.read_pickle"],
             "Pickle and modules that wrap it can be unsafe when used to deserialize untrusted data, possible security issue."),
            
            ("marshal", "B302", issue.Cwe.DESERIALIZATION_OF_UNTRUSTED_DATA, "MEDIUM",
             ["marshal.load", "marshal.loads"],
             "Deserialization with the marshal module is possibly dangerous."),
            
            ("md5", "B303", issue.Cwe.BROKEN_CRYPTO, "MEDIUM",
             ["Crypto.Hash.MD2.new", "Crypto.Hash.MD4.new", "Crypto.Hash.MD5.new", "Crypto.Hash.SHA.new",
              "Cryptodome.Hash.MD2.new", "Cryptodome.Hash.MD4.new", "Cryptodome.Hash.MD5.new", "Cryptodome.Hash.SHA.new",
              "cryptography.hazmat.primitives.hashes.MD5", "cryptography.hazmat.primitives.hashes.SHA1"],
             "Use of insecure MD2, MD4, MD5, or SHA1 hash function."),
            
            ("ciphers", "B304", issue.Cwe.BROKEN_CRYPTO, "HIGH",
             ["Crypto.Cipher.ARC2.new", "Crypto.Cipher.ARC4.new", "Crypto.Cipher.Blowfish.new", "Crypto.Cipher.DES.new", "Crypto.Cipher.XOR.new",
              "Cryptodome.Cipher.ARC2.new", "Cryptodome.Cipher.ARC4.new", "Cryptodome.Cipher.Blowfish.new", "Cryptodome.Cipher.DES.new", "Cryptodome.Cipher.XOR.new",
              "cryptography.hazmat.primitives.ciphers.algorithms.ARC4", "cryptography.hazmat.primitives.ciphers.algorithms.Blowfish",
              "cryptography.hazmat.primitives.ciphers.algorithms.CAST5", "cryptography.hazmat.primitives.ciphers.algorithms.IDEA",
              "cryptography.hazmat.primitives.ciphers.algorithms.SEED", "cryptography.hazmat.primitives.ciphers.algorithms.TripleDES"],
             "Use of insecure cipher {name}. Replace with a known secure cipher such as AES."),
            
            ("cipher_modes", "B305", issue.Cwe.BROKEN_CRYPTO, "MEDIUM",
             ["cryptography.hazmat.primitives.ciphers.modes.ECB"],
             "Use of insecure cipher mode {name}."),
            
            ("mktemp_q", "B306", issue.Cwe.INSECURE_TEMP_FILE, "MEDIUM",
             ["tempfile.mktemp"],
             "Use of insecure and deprecated function (mktemp)."),
            
            ("eval", "B307", issue.Cwe.OS_COMMAND_INJECTION, "MEDIUM",
             ["eval"],
             "Use of possibly insecure function - consider using safer ast.literal_eval."),
            
            ("mark_safe", "B308", issue.Cwe.XSS, "MEDIUM",
             ["django.utils.safestring.mark_safe"],
             "Use of mark_safe() may expose cross-site scripting vulnerabilities and should be reviewed."),
            
            ("urllib_urlopen", "B310", issue.Cwe.PATH_TRAVERSAL, "MEDIUM",
             ["urllib.request.urlopen", "urllib.request.urlretrieve", "urllib.request.URLopener", "urllib.request.FancyURLopener",
              "six.moves.urllib.request.urlopen", "six.moves.urllib.request.urlretrieve", "six.moves.urllib.request.URLopener", "six.moves.urllib.request.FancyURLopener"],
             "Audit url open for permitted schemes. Allowing use of file:/ or custom schemes is often unexpected."),
            
            ("random", "B311", issue.Cwe.INSUFFICIENT_RANDOM_VALUES, "LOW",
             ["random.Random", "random.random", "random.randrange", "random.randint", "random.choice", "random.choices",
              "random.uniform", "random.triangular", "random.randbytes", "random.sample", "random.getrandbits"],
             "Standard pseudo-random generators are not suitable for security/cryptographic purposes."),
            
            ("telnetlib", "B312", issue.Cwe.CLEARTEXT_TRANSMISSION, "HIGH",
             ["telnetlib.Telnet"],
             "Telnet-related functions are being called. Telnet is considered insecure. Use SSH or some other encrypted protocol."),
            
            ("xml_bad_cElementTree", "B313", issue.Cwe.IMPROPER_INPUT_VALIDATION, "MEDIUM",
             ["xml.etree.cElementTree.parse", "xml.etree.cElementTree.iterparse", "xml.etree.cElementTree.fromstring", "xml.etree.cElementTree.XMLParser"],
             "Using {name} to parse untrusted XML data is known to be vulnerable to XML attacks. Replace {name} with its defusedxml equivalent function or make sure defusedxml.defuse_stdlib() is called"),
            
            ("xml_bad_ElementTree", "B314", issue.Cwe.IMPROPER_INPUT_VALIDATION, "MEDIUM",
             ["xml.etree.ElementTree.parse", "xml.etree.ElementTree.iterparse", "xml.etree.ElementTree.fromstring", "xml.etree.ElementTree.XMLParser"],
             "Using {name} to parse untrusted XML data is known to be vulnerable to XML attacks. Replace {name} with its defusedxml equivalent function or make sure defusedxml.defuse_stdlib() is called"),
            
            ("xml_bad_expatreader", "B315", issue.Cwe.IMPROPER_INPUT_VALIDATION, "MEDIUM",
             ["xml.sax.expatreader.create_parser"],
             "Using {name} to parse untrusted XML data is known to be vulnerable to XML attacks. Replace {name} with its defusedxml equivalent function or make sure defusedxml.defuse_stdlib() is called"),
            
            ("xml_bad_expatbuilder", "B316", issue.Cwe.IMPROPER_INPUT_VALIDATION, "MEDIUM",
             ["xml.dom.expatbuilder.parse", "xml.dom.expatbuilder.parseString"],
             "Using {name} to parse untrusted XML data is known to be vulnerable to XML attacks. Replace {name} with its defusedxml equivalent function or make sure defusedxml.defuse_stdlib() is called"),
            
            ("xml_bad_sax", "B317", issue.Cwe.IMPROPER_INPUT_VALIDATION, "MEDIUM",
             ["xml.sax.parse", "xml.sax.parseString", "xml.sax.make_parser"],
             "Using {name} to parse untrusted XML data is known to be vulnerable to XML attacks. Replace {name} with its defusedxml equivalent function or make sure defusedxml.defuse_stdlib() is called"),
            
            ("xml_bad_minidom", "B318", issue.Cwe.IMPROPER_INPUT_VALIDATION, "MEDIUM",
             ["xml.dom.minidom.parse", "xml.dom.minidom.parseString"],
             "Using {name} to parse untrusted XML data is known to be vulnerable to XML attacks. Replace {name} with its defusedxml equivalent function or make sure defusedxml.defuse_stdlib() is called"),
            
            ("xml_bad_pulldom", "B319", issue.Cwe.IMPROPER_INPUT_VALIDATION, "MEDIUM",
             ["xml.dom.pulldom.parse", "xml.dom.pulldom.parseString"],
             "Using {name} to parse untrusted XML data is known to be vulnerable to XML attacks. Replace {name} with its defusedxml equivalent function or make sure defusedxml.defuse_stdlib() is called"),
            
            ("ftplib", "B321", issue.Cwe.CLEARTEXT_TRANSMISSION, "HIGH",
             ["ftplib.FTP"],
             "FTP-related functions are being called. FTP is considered insecure. Use SSH/SFTP/SCP or some other encrypted protocol."),
            
            ("unverified_context", "B323", issue.Cwe.IMPROPER_CERT_VALIDATION, "MEDIUM",
             ["ssl._create_unverified_context"],
             "By default, Python will create a secure, verified ssl context for use in such classes as HTTPSConnection. However, it still allows using an insecure context via the _create_unverified_context that reverts to the previous behavior that does not validate certificates or perform hostname checks."),
        ]
        
        self.blacklists["Call"] = [BlacklistItem(name, bid, cwe, qualnames, message, level) 
                                  for name, bid, cwe, level, qualnames, message in call_data]

    def _load_import_blacklists(self):
        """Load blacklist items for imports"""
        import_data = [
            ("import_telnetlib", "B401", issue.Cwe.CLEARTEXT_TRANSMISSION, "HIGH",
             ["telnetlib"], "A telnet-related module is being imported. Telnet is considered insecure. Use SSH or some other encrypted protocol."),
            
            ("import_ftplib", "B402", issue.Cwe.CLEARTEXT_TRANSMISSION, "HIGH",
             ["ftplib"], "A FTP-related module is being imported. FTP is considered insecure. Use SSH/SFTP/SCP or some other encrypted protocol."),
            
            ("import_pickle", "B403", issue.Cwe.DESERIALIZATION_OF_UNTRUSTED_DATA, "LOW",
             ["pickle", "cPickle", "dill", "shelve"], "Consider possible security implications associated with {name} module."),
            
            ("import_subprocess", "B404", issue.Cwe.OS_COMMAND_INJECTION, "LOW",
             ["subprocess"], "Consider possible security implications associated with the subprocess module."),
            
            ("import_xml_etree", "B405", issue.Cwe.IMPROPER_INPUT_VALIDATION, "LOW",
             ["xml.etree.cElementTree", "xml.etree.ElementTree"], "Using {name} to parse untrusted XML data is known to be vulnerable to XML attacks. Replace {name} with the equivalent defusedxml package, or make sure defusedxml.defuse_stdlib() is called."),
            
            ("import_xml_sax", "B406", issue.Cwe.IMPROPER_INPUT_VALIDATION, "LOW",
             ["xml.sax"], "Using {name} to parse untrusted XML data is known to be vulnerable to XML attacks. Replace {name} with the equivalent defusedxml package, or make sure defusedxml.defuse_stdlib() is called."),
            
            ("import_xml_expat", "B407", issue.Cwe.IMPROPER_INPUT_VALIDATION, "LOW",
             ["xml.dom.expatbuilder"], "Using {name} to parse untrusted XML data is known to be vulnerable to XML attacks. Replace {name} with the equivalent defusedxml package, or make sure defusedxml.defuse_stdlib() is called."),
            
            ("import_xml_minidom", "B408", issue.Cwe.IMPROPER_INPUT_VALIDATION, "LOW",
             ["xml.dom.minidom"], "Using {name} to parse untrusted XML data is known to be vulnerable to XML attacks. Replace {name} with the equivalent defusedxml package, or make sure defusedxml.defuse_stdlib() is called."),
            
            ("import_xml_pulldom", "B409", issue.Cwe.IMPROPER_INPUT_VALIDATION, "LOW",
             ["xml.dom.pulldom"], "Using {name} to parse untrusted XML data is known to be vulnerable to XML attacks. Replace {name} with the equivalent defusedxml package, or make sure defusedxml.defuse_stdlib() is called."),
            
            ("import_xmlrpclib", "B411", issue.Cwe.IMPROPER_INPUT_VALIDATION, "HIGH",
             ["xmlrpc"], "Using {name} to parse untrusted XML data is known to be vulnerable to XML attacks. Use defusedxml.xmlrpc.monkey_patch() function to monkey-patch xmlrpclib and mitigate XML vulnerabilities."),
            
            ("import_httpoxy", "B412", issue.Cwe.IMPROPER_ACCESS_CONTROL, "HIGH",
             ["wsgiref.handlers.CGIHandler", "twisted.web.twcgi.CGIScript", "twisted.web.twcgi.CGIDirectory"],
             "Consider possible security implications associated with {name} module."),
            
            ("import_pycrypto", "B413", issue.Cwe.BROKEN_CRYPTO, "HIGH",
             ["Crypto.Cipher", "Crypto.Hash", "Crypto.IO", "Crypto.Protocol", "Crypto.PublicKey", "Crypto.Random", "Crypto.Signature", "Crypto.Util"],
             "The pyCrypto library and its module {name} are no longer actively maintained and have been deprecated. Consider using pyca/cryptography library."),
            
            ("import_pyghmi", "B415", issue.Cwe.CLEARTEXT_TRANSMISSION, "HIGH",
             ["pyghmi"], "An IPMI-related module is being imported. IPMI is considered insecure. Use an encrypted protocol."),
        ]
        
        import_items = [BlacklistItem(name, bid, cwe, qualnames, message, level) 
                       for name, bid, cwe, level, qualnames, message in import_data]
        self.blacklists["Import"] = import_items
        self.blacklists["ImportFrom"] = import_items

    def get_blacklist_items(self, node_type):
        """
        Get blacklist items for a specific node type.
        
        Args:
            node_type: Node type ("Call", "Import", or "ImportFrom")
            
        Returns:
            List of BlacklistItem objects for that node type
        """
        return self.blacklists.get(node_type, [])

    def check_blacklist(self, node_type, qualname, context):
        """
        Check if a qualified name is blacklisted.
        
        Tests the qualified name against all blacklist items for the
        given node type. Returns the first matching issue found.
        
        Args:
            node_type: Node type ("Call", "Import", or "ImportFrom")
            qualname: Qualified name to check
            context: Context object with node information
            
        Returns:
            Issue object if blacklisted, None otherwise
        """
        items = self.get_blacklist_items(node_type)
        for item in items:
            if item.matches(qualname):
                return item.create_issue(context, qualname)
        return None


# Global blacklist manager instance (singleton)
blacklist_manager = BlacklistManager()
