# code by n3ko1 2015 - @n3ko101
from WrapMapModule import WrapMapModule
import subprocess

# This modules enumerates users on SMTP Services using the smtp-user-enum.pl script
# http://pentestmonkey.net/tools/smtp-user-enum

# Options
# WORDLIST: String (user list to enumerate)
# METHODS: List[String] (methods to use: VRFY, EXPN) default is VRFY

# SMTPScanner class to enumerate SMTP Services
class SMTPScanner(WrapMapModule):
    __supportedMethods = ['VRFY', 'EXPN']
        
    # SMTP User Enumeration
    def enumerate( self, args, host, port ):
        scan_status = ""
        scan_result = ""
        smtp_scan = ""
        
        # options include explicit method (if none is given, default is VRFY, multiple methods can be defined as a list)
        # and a wordlist (mandatory)
        if self.options == None or 'WORDLIST' not in self.options.keys() or self.options['WORDLIST'] == "":
            print "- ERROR: No User Wordlist given for SMTP Enumeration"
            scan_status = "ERROR"
            self.callbackWithResults(host, scan_status, "- ERROR: No User Wordlist given for SMTP Enumeration")
        
        if self.options != None and 'METHODS' in self.options.keys():
            for method in self.options['METHODS']:
                if method in self.__supportedMethods:
                    print "+ Enumerating SMTP Users with %s Method on %s port %s" % (method, host, port)
                    smtp_scan = "smtp-user-enum -U %s -M %s -t %s" % (self.options['WORDLIST'], method, host)
                    smtp_result += "SMTP USER ENUM METHOD %s :" % (method)
                    smtp_result += subprocess.check_output(smtp_scan, shell=True)
        
        if smtp_result != "" and "Usage" not in smtp_result:
            scan_status = "SUCCESS"
        else:
            scan_status = "ERROR"
        
        self.callbackWithResults(host, scan_status, scan_result)
        return