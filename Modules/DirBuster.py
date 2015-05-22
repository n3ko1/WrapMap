# code by n3ko1 2015 - @n3ko101
from WrapMapModule import WrapMapModule
import subprocess

# OPTIONS
# SSL: Boolean: Use SSL for dirb scan (optional)
# WORDLIST: String: Wordlist for dirb scan (optional)

# DirBuster class to enumerate HTTP Servers
class DirBuster(WrapMapModule):
        
    # Enumeration
    def enumerate( self, args, host, port ):
        scan_status = ""
        scan_result = ""
        
        dirb_cmd = ""
        
        print "+ Starting dirb scan against %s on port %s" % (host, port)
		print "+ SSL: %s" % (self.options['SSL'])
        
        if self.options != None and 'SSL' in self.options.keys() and self.options['SSL'] == True:
            dirb_cmd = "dirb https://%s:%s" % (host, port)
        else:
            dirb_cmd = "dirb http://%s:%s" % (host, port)
            
        if self.options != None and 'WORDLIST' in self.options.keys() != None and self.options['WORDLIST'] != "":
            print "+ using wordlist %s for dirb." % (self.options['WORDLIST'])
            dirb_cmd += " %s" % (self.options['WORDLIST'])
        
        dirb_result = subprocess.check_output(dirb_cmd, shell=True)
        
        if dirb_result != "" and "FATAL" not in dirb_result:
            scan_status = "SUCCESS"
        else:
            scan_status = "ERROR"
            
        scan_result += "DIRB SCAN:\n\n"
        scan_result += dirb_result
        
        self.callbackWithResults(host, scan_status, scan_result)
        return