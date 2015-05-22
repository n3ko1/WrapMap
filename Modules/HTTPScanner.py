# code by n3ko1 2015 - @n3ko101
from WrapMapModule import WrapMapModule
import subprocess

# HTTPScanner class to enumerate HTTP services
class HTTPScanner(WrapMapModule):
        
    # Implementing the enumerate method, returning Nmap output in XML format to WrapMap
    def enumerate( self, args, host, port ):
        scan_status = ""
        scan_result = ""
        print "+ HTTP Scan for %s started." % (host)
        
        # Since no additional callback funcitonality is required, we start an nmap script scan using the os module
        print "+ Performing nmap web script scan for %s:%s" % (host, port)  
        http_scan = "nmap -sV -oX - -p %s " \
                "--script=http-vhosts,http-userdir-enum,http-apache-negotiation," \
                "http-backup-finder,http-config-backup,http-default-accounts," \
                "http-email-harvest,http-methods,http-method-tamper,http-passwd,http-robots.txt %s" % (port, host)
        
        nmap_result = subprocess.check_output(http_scan, shell=True)
        
        # perform an additional default nikto scan
        print "+ Performing nikto web scan for %s:%s" % (host, port)  
        nikto_scan = "nikto -h %s -p %s" % (host, port)
        
        nikto_result = subprocess.check_output(nikto_scan, shell=True)
        
        if nikto_result != "" and nmap_result != "":
            scan_status = "SUCCESS"
        elif nikto_result == "" and nmap_result == "":
            scan_status = "ERROR"
        else:
            scan_status = "WARNING"
            
        scan_result += "\n\n NMAP HTTP SCAN: \n\n"
        scan_result += nmap_result
        
        scan_result += "\n\n NIKTO HTTP SCAN: \n\n"
        scan_result += nikto_result
        
        self.callbackWithResults(host, scan_status, scan_result)
        return