# code by n3ko1 2015 - @n3ko101
from WrapMapModule import WrapMapModule

# TEMPLATE CODE FOR NEW MODULES
# PLEASE DOCUMENT OPTIONS HERE
# Option1: String: Description for Option1
# Option2: List: Description for List Option2

# MODULE class to enumerate XX Services
class MODULE(WrapMapModule):
        
    # Enumeration
    def enumerate( self, args, host, port ):
        scan_status = ""
        scan_result = ""
        
        self.callbackWithResults(host, scan_status, scan_result)
        return