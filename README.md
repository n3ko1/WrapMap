<b>WrapMap - A modular wrapper for nmap written in Python</b><br>
WrapMap is a Python script intended for use during a penetration test. Often, a basic nmap scan is the first piece
in the puzzle of service enumeration against a target. However, using the results from this initial nmap scan, the tester
most certainly needs to run additional tools and custom scripts against open ports. WrapMap essentially runs custom Python modules against discovered ports and services.
This script is not intended to be an alternative to professional tools but to gain an quick, initial understanding of a target system. Custom modules can be integrated
very quickly.

WrapMap offers a wrapper around nmap using the python-nmap library (http://xael.org/norman/python/python-nmap/) in a slightly modified version. It presents
a modular approach in which for each service discovered during the nmap scan, optional modules will be run against that particular target service.
The nmap scans are run asynchronously to allow that modules are executed as soon as a single host has been scanned with nmap.
Each module is also run in a sub-process to speed up the scan process. In a separate blog post I will chat about the technical details of the tool.

The tool can be easily configured using the WrapMapConfig class distributed with WrapMap. Additional nmap parameters, output directories,
ports to be scanned and modules to be used can be configured there. Further, the tool can be extended with Modules that implement the
abstract WrapMapModule class. Using this abstraction, the new module only needs to implement the enumerate method and return it's raw results to WrapMap.
The main WrapMap script then evaluates the results and writes them to the appropriate output folder.

Modules are executed based on an indicator list including proto, port and basically anything that could appear in the nmap result.

NOTE: For now, there are only some basic modules available. However, it is simple to write your custom modules with your favorite tools. Over time, I hope
to get a nice library of post modules including everything from HTTP brute force to SMB Share enumeration.
Some Modules may be not fully functional since not all of them are fully tested against qualified targets.

<b>WARNING</b><br>
This program was strictly written for personal use. It comes as-is with no guarantee of full functionality. No liability can be given for damages
resulting in the use of this program. Port scanning and other enumeration techniques are ILLEGAL to use against systems that are not your own.
Use responsibly!

Thanks to http://www.securitysift.com/offsec-pwb-oscp/. Mike Czumak's Recon Scan script and his great OSCP writeup inspired me to write this tool!
Also thanks to Alexandre Norman - norman@xael.org for writing the python-nmap library!

<b>Installation</b><br>

Prerequisites:
- Have nmap installed on your machine (which I hope you already have!)
- Install additional scripts and tools that the modules you want to use depend on

All you then need to do is clone the repo:

$ git clone https://github.com/n3ko1/WrapMap.git

<b>Configuration</b><br>
Have a look at the sample config in WrapMapConfig.py. Configuration is realized as a simple Python class.
Nmap hosts can be configured just as you would do in nmap itself. So for example "192.168.0.1-255" is a valid configuration.
In the modules variable, all modules you want to use can be configured using a list of so called "indicators" that determine if 
a module is run after an open port has been found. WrapMap checks if either proto and port match the open port, or if any of the other
comma-separated indicators matches a value within the scan result. For example, if you specify "Apache" and nmap grabs the banner for an Apache service,
the module is run even if it's on some different port.

For more information, check the WrapMapConfig.py file.

<b>Writing additional Modules</b><br>

Every module needs to implement the WrapMapModule class which abstracts all the boilerplate code, e.g. for handling the subprocesses.
The module itself needs to implement only the "enumerate" method which can do anything you want it to do.
From the WrapMapModule class you can access the module configuration as specified in the WrapMapConfig class. Also you have direct access to 
additional options such as wordlists.

To Access the WORDLIST option from within a module

self.options['WORDLIST']

To Access the name of the module

self.module['name']

Every module should return its results by calling its callback function which creates a certain dict which has the following structure:

{ 'stats': { 'module': MODNAME, 'status': SUCCESS/WARNING/ERROR}, 'results' : RAW RESULT STRING }

The creation of the dict is encapsulated within the abstract WrapMapModule class, as well. The module only has to call the callback method specifiying the scan result (SUCCESS/WARNING/ERROR)
and the raw scan output (results) which should be in a writeable format as it will be written to an output file:

callbackWithResults( self, host, status, results )

A MODULE_TEMPLATE.py file is ready in the Modules directory to be used for your own modules! Please document the required options for the Module.

<b>Usage</b><br>
After configuration, usage is fairly straightforward:

$ python WrapMap.py

In future releases, there may be some flags to set here ;-) Especially verbosity is pretty high at the moment.

<b>License</b><br>
This program is free software; 
you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; 
either version 3 of the License, or any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; 
without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program; 
if not, write to the Free Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

<b>TODO</b><br>
- Write more post scripts (Currently working on FTP, SNMP, SMB and SSH modules)
- Implement automation for module installation (+ other config) as part of the main script (reading config, reading Module Name and indicator, adding module to config class file)
- Incorporate latest python-nmap release
