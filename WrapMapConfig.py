# code by n3ko1 2015 - @n3ko101

class WrapMapConfig(object):
    # Base Configuration
    output_dir = 'output'

    # Nmap Configuration
    tcp = True # Scan tcp ports
    udp = False # Scan udp ports
    nmap_hosts = '127.0.0.1'
    nmap_tcp = '1-65535'
    nmap_udp = '1-65535'
    nmap_args = ''

    # Module configuration. The modules dict contains a mapping between ports, service names or other indicators and lists of modules
    # The indicators in the CSV-formatted key are evaluated with a logical OR. This means, all modules for the indicator list will be executed
    # if one match is found (Either port 80 or http for example)
    # Each module is a dict with a name and an optional dict of option names
    # Each module must exist within the %WRAPMAP_DIR%/Modules/ directory and implement the WrapMapModule class
    # For tcp modules: tcp_PORT For udp modules: udp_PORT
    modules = { 
    'tcp_25,smtp,SMTP': [ {
        'name': 'SMTPScanner',
        'options': {
            'WORDLIST': '/usr/share/wordlists/metasploit/namelist.txt',
            'METHODS': ['VRFY', 'EXPN']
            } 
        }
    ],
    'tcp_80,http,HTTP': [ { 
        'name': 'DirBuster',
        'options': { # dict with additional options
            'SSL': False
            } 
        }, { 
        'name': 'HTTPScanner' # second module for same port, no options
        }
    ],
    'tcp_443,https,HTTPS': [ {
        'name': 'DirBuster',
        'options': {
            'SSL': True
            } 
        }
    ]
}
