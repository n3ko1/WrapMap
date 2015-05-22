# code by n3ko1 2015 - @n3ko101
from WrapMapModule import WrapMapModule

# DNSScanner class to enumerate DNS Services
class DNSScanner(WrapMapModule):
        
    # DNS Enumeration using dnsenum.pl
    # Requires dnsenum to be in the path
    # Can take a wordlist for DNS brute force in the self.options structure: self.options['WORDLIST']
    def enumerate( self, args, host, port ):
        scan_result = ""
        scan_status = ""
        print "+ DNS ENUMERATION STARTED."
        
        # Get host name
        host_cmd = "host %s | cut -d' ' -f1" % (host)
        host_name = subprocess.check_output(host_cmd, shell=True)
        
        if host_name != None and host_name != "":
            print "+ Host Name is: %s" % (host_name)
            dns_scan = "dnsenum "
            
            # Set a wordlist if option is given
            if self.options != None and self.options['WORDLIST'] != None:
                dns_scan += "-f %s " % (self.options['WORDLIST'])
        
            dns_scan += host
            
            print "+ Starting dnsenum with following cmd line: %s" % (dns_scan)
            scan_result = subprocess.check_output(dns_scan, shell=True)
            scan_status = "SUCCESS"

        else:
            scan_result = "- ERROR: Could not retrieve host name for DNS Enumeration."
            scan_status = "ERROR"
            print scan_result
        
        self.callbackWithResults(host, scan_status, scan_result)
        return