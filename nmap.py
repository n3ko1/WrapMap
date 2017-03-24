#!/usr/bin/env python
# -*- coding: latin-1 -*-

"""
nmap.py - v0.1.4 - 2010.06.20

Author : Alexandre Norman - norman@xael.org
Contributor: Steve 'Ashcrow' Milner - steve@gnulinux.net
Licence : GPL v3 or any later version


This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.


Test strings :
^^^^^^^^^^^^
>>> import nmap
>>> nm = nmap.PortScanner()
>>> r=nm.scan('127.0.0.1', '22-443')
>>> nm.command_line()
u'nmap -oX - -p 22-443 -sV 127.0.0.1'
>>> nm.scaninfo()
{u'tcp': {'services': u'22-443', 'method': u'connect'}}
>>> nm.all_hosts()
[u'127.0.0.1']
>>> nm['127.0.0.1'].hostname()
u'localhost'
>>> nm['127.0.0.1'].state()
u'up'
>>> nm['127.0.0.1'].all_protocols()
[u'tcp']
>>> nm['127.0.0.1']['tcp'].keys()
[80, 25, 443, 22, 111]
>>> nm['127.0.0.1'].has_tcp(22)
True
>>> nm['127.0.0.1'].has_tcp(23)
False
>>> nm['127.0.0.1']['tcp'][22]
{'state': u'open', 'reason': u'syn-ack', 'name': u'ssh'}
>>> nm['127.0.0.1'].tcp(22)
{'state': u'open', 'reason': u'syn-ack', 'name': u'ssh'}
>>> nm['127.0.0.1']['tcp'][22]['state']
u'open'
>>> nm.scanstats()['uphosts']
u'1'
>>> nm.scanstats()['downhosts']
u'0'
>>> nm.scanstats()['totalhosts']
u'1'
>>> 'timestr' in nm.scanstats().keys()
True
>>> 'elapsed' in nm.scanstats().keys()
True
>>> nm.listscan('192.168.1.0/30')
[u'192.168.1.0', u'192.168.1.1', u'192.168.1.2', u'192.168.1.3']
>>> nm.listscan('localhost/30')
[u'127.0.0.0', u'127.0.0.1', u'127.0.0.2', u'127.0.0.3']
"""


__author__ = 'Alexandre Norman (norman@xael.org)'
__version__ = '0.1.4'


import os
import re
import string
import subprocess
import sys
import types
import xml.dom.minidom
import shlex



try:
    from multiprocessing import Process
except ImportError:
    # For pre 2.6 releases
    from threading import Thread as Process

############################################################################

class PortScanner(object):
    """
    PortScanner allows to use nmap from python
    """
    
    def __init__(self):
        """
        Initialize the module
        detects nmap on the system and nmap version
        may raise PortScannerError exception if nmap is not found in the path
        """

        self._scan_result = {}
        self._nmap_version_number = 0       # nmap version number
        self._nmap_subversion_number = 0    # nmap subversion number
        self._nmap_last_output = ''  # last full ascii nmap output
        is_nmap_found = False       # true if we have found nmap

        self.__process = None

        # regex used to detect nmap
        regex = re.compile('Nmap version [0-9]*\.[0-9]*[^ ]* \( https?://nmap\.org \)')
        # launch 'nmap -V', we wait after 'Nmap version 5.0 ( http://nmap.org )'
        p = subprocess.Popen(['nmap', '-V'], bufsize=10000, stdout=subprocess.PIPE)
        self._nmap_last_output = p.communicate()[0] # store stdout
        for line in self._nmap_last_output.split('\n'):
            if regex.match(line) is not None:
                is_nmap_found = True
                # Search for version number
                regex_version = re.compile('[0-9]+')
                regex_subversion = re.compile('\.[0-9]+')

                rv = regex_version.search(line)
                rsv = regex_subversion.search(line)

                if rv is not None and rsv is not None:
                    # extract version/subversion
                    self._nmap_version_number = int(line[rv.start():rv.end()])
                    self._nmap_subversion_number = int(line[rsv.start()+1:rsv.end()])
                break

        if is_nmap_found == False:
            raise PortScannerError('nmap program was not found in path')

        return


    def get_nmap_last_output(self):
        """
        returns the last text output of nmap in raw text
        this may be used for debugging purpose
        """
        return self._nmap_last_output



    def nmap_version(self):
        """
        returns nmap version if detected (int version, int subversion)
        or (0, 0) if unknown
        """
        return (self._nmap_version_number, self._nmap_subversion_number)



    def listscan(self, hosts='127.0.0.1'):
        """
        do not scan but interpret target hosts and return a list a hosts
        """
        assert type(hosts) in types.StringTypes, 'Wrong type for [hosts], should be a string [was {0}]'.format(type(hosts))
        
        self.scan(hosts, arguments='-sL')
        return self.all_hosts()



    def scan(self, hosts='127.0.0.1', ports=None, arguments='-sV'):
        """
        Scan given hosts

        May raise PortScannerError exception if nmap output something on stderr

        hosts = string for hosts as nmap use it 'scanme.nmap.org' or '198.116.0-255.1-127' or '216.163.128.20/20'
        ports = string for ports as nmap use it '22,53,110,143-4564'
        arguments = string of arguments for nmap '-sU -sX -sC'
        """
        assert type(hosts) in types.StringTypes, 'Wrong type for [hosts], should be a string [was {0}]'.format(type(hosts))
        assert type(ports) in types.StringTypes+(types.NoneType,), 'Wrong type for [ports], should be a string [was {0}]'.format(type(ports))
        assert type(arguments) in types.StringTypes, 'Wrong type for [arguments], should be a string [was {0}]'.format(type(arguments))

        f_args = shlex.split(arguments)
        
        # Launch scan
        args = ['nmap', '-oX', '-', hosts] + ['-p', ports]*(ports!=None) + f_args

        p = subprocess.Popen(args, bufsize=100000, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        # wait until finished
        # get output
        (self._nmap_last_output, nmap_err) = p.communicate()

        # If there was something on stderr, there was a problem so abort...
        if len(nmap_err) > 0:
            regex_warning = re.compile('^Warning: .*')
            for line in nmap_err.split('\n'):
                if len(line) > 0:
                    rgw = regex_warning.search(line)
                    if rgw is not None:
                        sys.stderr.write(line+'\n')
                        pass
                    else:
                        raise PortScannerError(nmap_err)


        # nmap xml output looks like :
        #  <host starttime="1267974521" endtime="1267974522">
        #  <status state="up" reason="user-set"/>
        #  <address addr="192.168.1.1" addrtype="ipv4" />
        #  <hostnames><hostname name="neufbox" type="PTR" /></hostnames>
        #  <ports>
        #    <port protocol="tcp" portid="22">
        #      <state state="filtered" reason="no-response" reason_ttl="0"/>
        #      <service name="ssh" method="table" conf="3" />
        #    </port>
        #    <port protocol="tcp" portid="25">
        #      <state state="filtered" reason="no-response" reason_ttl="0"/>
        #      <service name="smtp" method="table" conf="3" />
        #    </port>
        #  </ports>
        #  <times srtt="-1" rttvar="-1" to="1000000" />
        #  </host>



        scan_result = {}
        
        dom = xml.dom.minidom.parseString(self._nmap_last_output)

        # nmap command line
        scan_result['nmap'] = {
            'command_line': dom.getElementsByTagName('nmaprun')[0].getAttributeNode('args').value,
            'scaninfo': {},
            'scanstats':{'timestr':dom.getElementsByTagName("finished")[0].getAttributeNode('timestr').value,
                         'elapsed':dom.getElementsByTagName("finished")[0].getAttributeNode('elapsed').value,
                         'uphosts':dom.getElementsByTagName("hosts")[0].getAttributeNode('up').value,
                         'downhosts':dom.getElementsByTagName("hosts")[0].getAttributeNode('down').value,
                         'totalhosts':dom.getElementsByTagName("hosts")[0].getAttributeNode('total').value}
            }
        # info about scan
        for dsci in dom.getElementsByTagName('scaninfo'):
            scan_result['nmap']['scaninfo'][dsci.getAttributeNode('protocol').value] = {                
                'method': dsci.getAttributeNode('type').value,
                'services': dsci.getAttributeNode('services').value
                }


        scan_result['scan'] = {}
        
        for dhost in  dom.getElementsByTagName('host'):
            # host ip
            host = dhost.getElementsByTagName('address')[0].getAttributeNode('addr').value
            hostname = ''
            for dhostname in dhost.getElementsByTagName('hostname'):
                hostname = dhostname.getAttributeNode('name').value
            scan_result['scan'][host] = PortScannerHostDict({'hostname': hostname})
            for dstatus in dhost.getElementsByTagName('status'):
                # status : up...
                scan_result['scan'][host]['status'] = {'state': dstatus.getAttributeNode('state').value,
                                               'reason': dstatus.getAttributeNode('reason').value}
            for dport in dhost.getElementsByTagName('port'):
                # protocol
                proto = dport.getAttributeNode('protocol').value
                # port number converted as integer
                port =  int(dport.getAttributeNode('portid').value)
                # state of the port
                state = dport.getElementsByTagName('state')[0].getAttributeNode('state').value
                # reason
                reason = dport.getElementsByTagName('state')[0].getAttributeNode('reason').value
                # name if any
                name = ''
                for dname in dport.getElementsByTagName('service'):
                    name = dname.getAttributeNode('name').value
                # store everything
                if not proto in scan_result['scan'][host].keys():
                    scan_result['scan'][host][proto] = {}
                scan_result['scan'][host][proto][port] = {'state': state,
                                                  'reason': reason,
                                                  'name': name}
                script_id = ''
                script_out = ''
                # get script output if any
                for dscript in dport.getElementsByTagName('script'):
                    script_id = dscript.getAttributeNode('id').value
                    script_out = dscript.getAttributeNode('output').value
                    if not 'script' in scan_result['scan'][host][proto][port].keys():
                        scan_result['scan'][host][proto][port]['script'] = {}

                    scan_result['scan'][host][proto][port]['script'][script_id] = script_out


        self._scan_result = scan_result # store for later use
        return scan_result


    
    def __getitem__(self, host):
        """
        returns a host detail
        """
        assert type(host) in types.StringTypes, 'Wrong type for [host], should be a string [was {0}]'.format(type(host))
        return self._scan_result['scan'][host]


    def all_hosts(self):
        """
        returns a sorted list of all hosts
        """
        if not 'scan' in self._scan_result.keys():
            return []
        listh = self._scan_result['scan'].keys()
        listh.sort()
        return listh
        

    def command_line(self):
        """
        returns command line used for the scan
        """
        return self._scan_result['nmap']['command_line']


    def scaninfo(self):
        """
        returns scaninfo structure
        {u'tcp': {'services': u'22', 'method': u'connect'}}
        """
        return self._scan_result['nmap']['scaninfo']
        

    def scanstats(self):
        """
        returns scanstats structure
        {'uphosts': u'3', 'timestr': u'Thu Jun  3 21:45:07 2010', 'downhosts': u'253', 'totalhosts': u'256', 'elapsed': u'5.79'}
        """
        return self._scan_result['nmap']['scanstats']        


    def has_host(self, host):
        """
        returns True if host has result, False otherwise
        """
        assert type(host) is types.StringTypes, 'Wrong type for [host], should be a string [was {0}]'.format(type(host))

        if host in self._scan_result['scan'].keys():
            return True

        return False




############################################################################


class PortScannerAsync(object):
    """
    PortScannerAsync allows to use nmap from python asynchronously
    for each host scanned, callback is called with scan result for the host
    """

    def __init__(self):
        """
        Initialize the module
        detects nmap on the system and nmap version
        may raise PortScannerError exception if nmap is not found in the path
        """
        self._process = None
        self._nm = PortScanner()
        return


    def __del__(self):
        """
        Cleanup when deleted
        """
        if self._process is not None and self._process.is_alive():
            self._process.terminate()
        return


    def scan(self, hosts='127.0.0.1', ports=None, arguments='-sV', callback=None):
        """
        Scan given hosts in a separate process and return host by host result using callback function

        PortScannerError exception from standard nmap is catched and you won't know about it

        hosts = string for hosts as nmap use it 'scanme.nmap.org' or '198.116.0-255.1-127' or '216.163.128.20/20'
        ports = string for ports as nmap use it '22,53,110,143-4564'
        arguments = string of arguments for nmap '-sU -sX -sC'
        callback = callback function which takes (host, scan_data) as arguments
        """

        assert type(hosts) in types.StringTypes, 'Wrong type for [hosts], should be a string [was {0}]'.format(type(hosts))
        assert type(ports) in types.StringTypes+(types.NoneType,), 'Wrong type for [ports], should be a string [was {0}]'.format(type(ports))
        assert type(arguments) in types.StringTypes, 'Wrong type for [arguments], should be a string [was {0}]'.format(type(arguments))
        #assert type(callback) in (types.FunctionType, types.NoneType), 'Wrong type for [callback], should be a function or None [was {0}]'.format(type(callback))
        
        def scan_progressive(self, hosts, ports, arguments, callback):
            for host in self._nm.listscan(hosts):
                try:
                    scan_data = self._nm.scan(host, ports, arguments)
                except PortScannerError:
                    print "error"
                    pass
                if callback is not None and callable(callback):
                    callback(host, scan_data)
            return

        self._process = Process(
            target=scan_progressive,
            args=(self, hosts, ports, arguments, callback)
            )
        self._process.daemon = False
        self._process.start()
        return


    def stop(self):
        """
        Stop the current scan process
        """
        if self._process is not None:
            self._process.terminate()
        return


    def wait(self, timeout=None):
        """
        Wait for the current scan process to finish, or timeout
        """

        assert type(timeout) in (types.IntType, types.NoneType), 'Wrong type for [timeout], should be an int or None [was {0}]'.format(type(timeout))

        self._process.join(timeout)
        return

    

    def still_scanning(self):
        """
        Return True if a scan is currently running, False otherwise
        """
        try:
            return self._process.is_alive()
        except:
            return False

    

############################################################################
    


class PortScannerHostDict(dict):
    """
    Special dictionnary class for storing and accessing host scan result
    """
    def hostname(self):
        """
        returns hostname
        """
        return self['hostname']


    def state(self):
        """
        returns host state
        """
        return self['status']['state']


    def all_protocols(self):
        """
        returns a list of all scanned protocols
        """
        lp = self.keys()
        lp.remove('status')
        lp.remove('hostname')
        lp.sort()
        return lp



    def all_tcp(self):
        """
        returns list of tcp ports
        """
        if 'tcp' in self.keys():
            ltcp = self['tcp'].keys()
            ltcp.sort()
            return ltcp
        return []
            
    
    def has_tcp(self, port):
        """
        returns True if tcp port has info, False otherwise
        """
        assert type(port) is types.IntType, 'Wrong type for [port], should be an int [was {0}]'.format(type(port))
        
        if ('tcp' in self.keys()
            and port in self['tcp'].keys()):
            return True
        return False


    def tcp(self, port):
        """
        returns info for tpc port
        """
        assert type(port) is types.IntType, 'Wrong type for [port], should be an int [was {0}]'.format(type(port))
        return self['tcp'][port]


    def all_udp(self):
        """
        returns list of udp ports
        """
        if 'udp' in self.keys():
            ludp = self['udp'].keys()
            ludp.sort()
            return ludp
        return []


    def has_udp(self, port):
        """
        returns True if udp port has info, False otherwise
        """
        assert type(port) is types.IntType, 'Wrong type for [port], should be an int [was {0}]'.format(type(port))

        if ('udp' in self.keys()
            and 'port' in self['udp'].keys()):
            return True
        return False


    def udp(self, port):
        """
        returns info for udp port
        """
        assert type(port) is types.IntType, 'Wrong type for [port], should be an int [was {0}]'.format(type(port))

        return self['udp'][port]


    def all_ip(self):
        """
        returns list of ip ports
        """
        if 'ip' in self.keys():
            lip = self['ip'].keys()
            lip.sort()
            return lip
        return []


    def has_ip(self, port):
        """
        returns True if ip port has info, False otherwise
        """
        assert type(port) is types.IntType, 'Wrong type for [port], should be an int [was {0}]'.format(type(port))

        if ('ip' in self.keys()
            and port in self['ip'].keys()):
            return True
        return False


    def ip(self, port):
        """
        returns info for ip port
        """
        assert type(port) is types.IntType, 'Wrong type for [port], should be an int [was {0}]'.format(type(port))

        return self['ip'][port]


    def all_sctp(self):
        """
        returns list of sctp ports
        """
        if 'sctp' in self.keys():
            lsctp = self['sctp'].keys()
            lsctp.sort()
            return lsctp
        return []


    def has_sctp(self, port):
        """
        returns True if sctp port has info, False otherwise
        """
        assert type(port) is types.IntType, 'Wrong type for [port], should be an int [was {0}]'.format(type(port))

        if ('sctp' in self.keys()
            and port in self['sctp'].keys()):
            return True
        return False


    def sctp(self, port):
        """
        returns info for sctp port
        """
        assert type(port) is types.IntType, 'Wrong type for [port], should be an int [was {0}]'.format(type(port))

        return self['sctp'][port]


    
############################################################################


class PortScannerError(Exception):
    """
    Exception error class for PortScanner class
    """
    def __init__(self, value):
        self.value = value


    def __str__(self):
        return repr(self.value)


############################################################################


# MAIN -------------------
if __name__ == '__main__':
    import doctest
    # non regression test
    doctest.testmod()


#<EOF>######################################################################
