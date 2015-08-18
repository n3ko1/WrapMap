# code by Lucas Bader 2015 - @n3ko101

# This script is a modular approach to host enumeration during a penetration test.
# See README.md for further information

'''
License

This program is free software; 
you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; 
either version 3 of the License, or any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; 
without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program; 
if not, write to the Free Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

WARNING
This program was strictly written for personal use. It comes as-is with no guarantee of full functionality. No liability can be given for damages
resulting in the use of this program. Port scanning and other enumeration techniques are ILLEGAL to use against systems that are not your own.
Use responsibly!
'''

# Usage: $ python WrapMap.py
# Check Configuration before running! Use responsibly!

import nmap
import os, subprocess
import time, datetime

# Custom imports
from WrapMapConfig import WrapMapConfig

class WrapMap(object):
    def __init__(self):
        self.config = WrapMapConfig() # Instance of config class
        self.modules = self.importModules()
        self.asyncScanner = nmap.PortScannerAsync() # singleton scanner instance
        # self.currBaseDir: base output folder
        return


    # Main scan method. Initializes new nmap scan with given configuration
    def scan(self):
        # initialize output folder
        self.createOutputFolders()
        
        # Start asynchronous nmap scans for hosts defined in config
        nmap_args = self.config.nmap_args
    
        # Define arguments depending on protocol
        if self.config.tcp and self.config.udp:
            nmap_args += ' -sT -sU -p T:%s,U:%s' % (self.config.nmap_tcp, self.config.nmap_udp)
        elif self.config.tcp:
            nmap_args += ' -sT -p %s' % (self.config.nmap_tcp)
        elif self.config.udp:
            nmap_args += ' -sU -p %s' % (self.config.nmap_udp)
    
        # Run asynchronous nmap scan with specified options and nmapScanComplete as a callback function to do post scanning
        print "\n+ Starting asynchronous nmap scan with %s" % ( nmap_args )
        self.asyncScanner.scan(hosts=self.config.nmap_hosts, arguments=nmap_args, callback=self.nmapScanComplete)
        while self.asyncScanner.still_scanning():
            print "..."
            self.asyncScanner.wait(2)
        
        return

    # This method initializes the output folder for a new scan with the current timestamp
    def createOutputFolders(self):
        ts = time.time()
        self.currBaseDir = self.config.output_dir \
                    + '_' \
                    + datetime.datetime.fromtimestamp(ts).strftime('%Y_%m_%d_%H_%M_%S') #save as member for later use
    
        os.makedirs(self.currBaseDir)
        return
    
    # This method loads all modules as specified in the config and saves instances to self.modules
    def importModules(self):
        print "\n+ Importing modules..."
        modules = {}
        for port in self.config.modules:
            for module in self.config.modules[port]:
                try:
                    # import module from Modules package 
                    mod = __import__("Modules.%s" % (module['name']), 
                                        fromlist=[module['name']])
                    # get class with same name and save instance to self.modules
                    clazz = getattr(mod, module['name'])
                    modules[module['name']] = clazz(module)
                except ImportError:
                    print "- ERROR: could not import %s" % ( module )
        return modules
                    
    # Callback method for completed post scans, this writes the module results to the desired output folder
    def postScanComplete(self, host, scan_result):
        print "+ Finished scan for %s" % scan_result['stats']['module']
        
        # Do not write output file if an error occured in the Module
        if scan_result['stats']['status'] == "ERROR":
            print "- ERROR occurred in %s" % scan_result['stats']['module']
            print "- Aborting writing to output file."
            print "- Module returned results: %s" % scan_result['result']
            return
        
        elif scan_result['stats']['status'] == "WARNING":
            print "- WARNING occurred in %s" % scan_result['stats']['module']
            print "- Module returned results: %s" % scan_result['result']
        
        # Write results to a file
        out_file = os.path.join(self.currBaseDir, host, 'modules', scan_result['stats']['module'], '%s_out.xml' % (scan_result['stats']['module']))
        print "+ Writing results to %s" %(out_file)
        with open(out_file, 'w') as f:
            f.write(scan_result['result'])
            f.close()
        return
        
    # Callback method for completed nmap scans
    def nmapScanComplete(self, host, scan_result):
        print "\n"
        print "+ Finished nmap scan for %s" % (host)
        print "+ Command was: %s" % (scan_result['nmap']['command_line'])
        
        # validate nmap result
        if scan_result['scan']:
            # host exists
            host_result = scan_result['scan'][host]
        else:
            # host does not exist or ist down. scan_result['scan'][host].state() is not reliable
            print "- ERROR Host %s is down or does not exist." % (host)
            return
                
        print "+ Host : %s (%s)" % (host, host_result.hostname())
        print "+ State : %s" % (host_result.state())
        
        # Create host folder in current working output directory
        os.makedirs(os.path.join(self.currBaseDir, host))
        
        # Write nmap result
        raw_output = self.asyncScanner._nm.get_nmap_last_output()
        with open(os.path.join(self.currBaseDir, host, 'nmap_out.xml'), 'w') as f:
            f.write(raw_output)
            f.close()
    
        # Iterate over all open ports to find applicable modules by checking the nmap output against the CSV-formatted indicator list
        # from the WrapMap Config. If an applicable module is found, it will be run against the given port.
        # Parse list of open ports / services
        for proto in host_result.all_protocols():
            lport = host_result[proto].keys()
            lport.sort()
            for port in lport:
                modStarted = [] # list of started Modules to avoid duplicate execution on a per port basis
                
                # iterate over open ports
                if host_result[proto][port]['state'] == "open":
                    # Run applicable post modules
                    # Split module indicators on ',' to be able to compare against all indicators individually
                    lmodindicators = [ x.split(',') for x in self.config.modules.keys() ]
                    print "\n+ Checking for applicable module for OPEN port %s on %s" % (port, host)
                    for lindicator in lmodindicators:
                        for indicator in lindicator:
                            # check if indicator matches proto AND port OR some other value for the nmap result (e.g. service name)
                            if (str(port) in str(indicator) and str(proto) in str(indicator)) or str(indicator) in host_result[proto][port].values():
                                print "+ Found match with indicator: %s" % (indicator)
                                # iterate over modules with given indicator list, join indicator list to enable key lookup
                                for module in self.config.modules[','.join(lindicator)]:
                                    # Check if module has already been started
                                    if module['name'] in modStarted:
                                        print "+ Module %s already started for target" % (module['name'])
                                        continue
                                    
                                    # Run post module asynchronously
                                    if module['name'] in self.modules.keys():
                                        # Create output folder for module in current host directory
                                        os.makedirs(os.path.join(self.currBaseDir, host, 'modules', module['name']))
                                        print "+ Running Post Module %s" % (module['name'])
                                        self.modules[module['name']].scan(host, port, self.postScanComplete)
                                        modStarted.append(module['name'])
                                    else:
                                        print "- ERROR: %s not available." % (module['name'])
        return

# Script execution
if __name__ == "__main__":
    print "################################################"
    print "### WrapMap host enumeration script by Lucas Bader - @n3ko101 ###"
    print "################################################"
    
    WrapMap().scan()
    
