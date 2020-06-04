import re

from wfuzz.plugin_api.base import BasePlugin
from wfuzz.externals.moduleman.plugin import moduleman_plugin


@moduleman_plugin
class errors(BasePlugin):
    name = "errors"
    author = ("Xavi Mendez (@xmendez)",)
    version = "0.1"
    summary = "Looks for error messages"
    description = ("Looks for common error messages",)
    category = ["default", "passive"]
    priority = 99

    parameters = ()

    def __init__(self):
        BasePlugin.__init__(self)

        regex_list = [
            "A syntax error has occurred",
            "ADODB.Field error",
            "ASP.NET is configured to show verbose error messages",
            "ASP.NET_SessionId",
            "Active Server Pages error",
            "An illegal character has been found in the statement",
            'An unexpected token "END-OF-STATEMENT" was found',
            "Can't connect to local",
            "Custom Error Message",
            "DB2 Driver",
            "DB2 Error",
            "DB2 ODBC",
            "Disallowed Parent Path",
            "Error Diagnostic Information",
            "Error Message : Error loading required libraries.",
            "Error Report",
            "Error converting data type varchar to numeric",
            "Fatal error",
            "Incorrect syntax near",
            "Internal Server Error",
            "Invalid Path Character",
            "Invalid procedure call or argument",
            "Invision Power Board Database Error",
            "JDBC Driver",
            "JDBC Error",
            "JDBC MySQL",
            "JDBC Oracle",
            "JDBC SQL",
            "Microsoft OLE DB Provider for ODBC Drivers",
            "Microsoft VBScript compilation error",
            "Microsoft VBScript error",
            "MySQL Driver",
            "MySQL Error",
            "MySQL ODBC",
            "ODBC DB2",
            "ODBC Driver",
            "ODBC Error",
            "ODBC Microsoft Access",
            "ODBC Oracle",
            "ODBC SQL",
            "ODBC SQL Server",
            "OLE/DB provider returned message",
            "ORA-0",
            "ORA-1",
            "Oracle DB2",
            "Oracle Driver",
            "Oracle Error",
            "Oracle ODBC",
            "PHP Error",
            "PHP Parse error",
            "PHP Warning",
            "Permission denied: 'GetObject'",
            "PostgreSQL query failed: ERROR: parser: parse error",
            r"SQL Server Driver\]\[SQL Server",
            "SQL command not properly ended",
            "SQLException",
            "Supplied argument is not a valid PostgreSQL result",
            "Syntax error in query expression",
            "The error occurred in",
            "The script whose uid is",
            "Type mismatch",
            "Unable to jump to row",
            "Unclosed quotation mark before the character string",
            "Unterminated string constant",
            "Warning: Cannot modify header information - headers already sent",
            "Warning: Supplied argument is not a valid File-Handle resource in",
            r"Warning: mysql_query\(\)",
            r"Warning: mysql_fetch_array\(\)",
            r"Warning: pg_connect\(\): Unable to connect to PostgreSQL server: FATAL",
            "You have an error in your SQL syntax near",
            "data source=",
            "detected an internal error [IBM][CLI Driver][DB2/6000]",
            "invalid query",
            "is not allowed to access",
            "missing expression",
            "mySQL error with query",
            "mysql error",
            "on MySQL result index",
            "supplied argument is not a valid MySQL result resource",
        ]

        self.error_regex = []
        for regex in regex_list:
            self.error_regex.append(re.compile(regex, re.MULTILINE | re.DOTALL))

    def validate(self, fuzzresult):
        return True

    def process(self, fuzzresult):
        for regex in self.error_regex:
            for regex_match in regex.findall(fuzzresult.history.content):
                self.add_result("Error identified: {}".format(regex_match))
