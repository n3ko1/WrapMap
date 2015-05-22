# code by n3ko1 2015 - @n3ko101
from WrapMapModule import WrapMapModule

# TEMPLATE CODE FOR NEW MODULES

# MODULE class to enumerate XX Services
class MODULE(WrapMapModule):
        
    # Enumeration
    def enumerate( self, args, host, port ):
        scan_status = ""
        scan_result = ""
        
        self.callbackWithResults(host, scan_status, scan_result)
        return