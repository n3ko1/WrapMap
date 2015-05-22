# code by n3ko1 2015 - @n3ko101

# Abstract async module class for WrapMap script
# Each module has to provide a enumerate method to the scan method which will be run asynchronously
# Modules need to implement the enumerate method which is intended to run scans and return the results in a writable format (e.g. XML)
# 
# The dict structure is as follows and is created in the callbackWithResults method:
# { 'stats': { 'module': MODNAME, 'status': SUCCESS/WARNING/ERROR}, 'results' : RAW RESULT STRING }

# After completion, the given callback method in self.callback is called using the callbackWithResults method. The callback mechanism is also encapsulated
# from the actual Module Implementation

import os, subprocess

try:
    from multiprocessing import Process
except ImportError:
    # For pre 2.6 releases
    from threading import Thread as Process

class WrapMapModule(object):
    def __init__ ( self, module ):
        self.__lstates = ["SUCCESS", "WARNING", "ERROR"]
        self.module = module # save module config
        # some modules may require additonal options
        self.options = None
        if 'options' in module.keys():
            self.options = module['options']
        self._process = None
        return
        
    # Each module needs to implement the enumerate method which should call the specified
    # callback method and return results as a dict
    def enumerate( self, args, host, port ):
        raise NotImplementedError( "- ERROR: enumerate method not implemented for %s module." % (self.__class__.__name__))
    
    # creates result dict with a given status and raw_results and calls the given callback function
    # status: String, can be either of SUCCESS/WARNING/ERROR (see self.__lstates)
    # results: String
    def callbackWithResults( self, host, status, results ):
        if status in self.__lstates:
            self.callback(host, { 'stats': { 'module': self.module['name'], 'status': status }, 'result' : results })
        else:
            self.callback(host, { 'stats': { 'module': self.module['name'], 'status': 'ERROR' }, 
                                 'result' : "ERROR: Module did not return with valid state" })
        
    def scan(self, host, port, callback):
        self.callback = callback
        
        # Check if callback is callable and run asynchronous process
        if self.callback is not None and callable(self.callback):
            self._process = Process(
                target=self.enumerate,
                args=(self, host, port)
                )
            self._process.daemon = False
            self._process.start()
        else:
            print "- ERROR: callback function is either None or not callable."
        return

    def stop(self):
        if self._process is not None:
            self._process.terminate()
        return

    def wait(self, timeout=None):
        self._process.join(timeout)
        return

    def still_scanning(self):
        try:
            return self._process.is_alive()
        except:
            return False
