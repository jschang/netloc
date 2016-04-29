#!/usr/bin/python

import sys
import select
import time
import struct
import hmac
import os
import atexit
try:
    import fcntl
except ImportError:
    pass

from random import random
from contextlib import closing
from socket import *
from optparse import OptionParser
from signal import SIGTERM

def log(msg):
    if options.quiet == False:
        print msg

def get_ip_address(ifname):
    s = socket(AF_INET, SOCK_DGRAM)
    return inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', ifname[:15])
    )[20:24])

class Daemon:
	"""
	A generic daemon class.
	
	Usage: subclass the Daemon class and override the run() method
	"""
	def __init__(self, pidfile, stdin='/dev/null', stdout='/dev/null', stderr='/dev/null'):
		self.stdin = stdin
		self.stdout = stdout
		self.stderr = stderr
		self.pidfile = pidfile
	
	def daemonize(self):
		"""
		do the UNIX double-fork magic, see Stevens' "Advanced 
		Programming in the UNIX Environment" for details (ISBN 0201563177)
		http://www.erlenstar.demon.co.uk/unix/faq_2.html#SEC16
		"""
		try: 
			pid = os.fork() 
			if pid > 0:
				# exit first parent
				sys.exit(0) 
		except OSError, e: 
			sys.stderr.write("fork #1 failed: %d (%s)\n" % (e.errno, e.strerror))
			sys.exit(1)
	
		# decouple from parent environment
		os.chdir("/") 
		os.setsid() 
		os.umask(0) 
	
		# do second fork
		try: 
			pid = os.fork() 
			if pid > 0:
				# exit from second parent
				sys.exit(0) 
		except OSError, e: 
			sys.stderr.write("fork #2 failed: %d (%s)\n" % (e.errno, e.strerror))
			sys.exit(1) 
	
		# redirect standard file descriptors
		sys.stdout.flush()
		sys.stderr.flush()
		si = file(self.stdin, 'r')
		so = file(self.stdout, 'a+')
		se = file(self.stderr, 'a+', 0)
		os.dup2(si.fileno(), sys.stdin.fileno())
		os.dup2(so.fileno(), sys.stdout.fileno())
		os.dup2(se.fileno(), sys.stderr.fileno())
	
		# write pidfile
		atexit.register(self.delpid)
		pid = str(os.getpid())
		file(self.pidfile,'w+').write("%s\n" % pid)
	
	def delpid(self):
		os.remove(self.pidfile)

	def start(self):
		"""
		Start the daemon
		"""
		# Check for a pidfile to see if the daemon already runs
		try:
			pf = file(self.pidfile,'r')
			pid = int(pf.read().strip())
			log ("started with pid %d" % pid)
			pf.close()
		except IOError:
			pid = None
	
		if pid:
			message = "pidfile %s already exist. Daemon already running?\n"
			sys.stderr.write(message % self.pidfile)
			sys.exit(1)
		
		# Start the daemon
		self.daemonize()
		self.run()

	def stop(self):
		"""
		Stop the daemon
		"""
		# Get the pid from the pidfile
		try:
			pf = file(self.pidfile,'r')
			pid = int(pf.read().strip())
			log ("stopping pid %d" % pid)
			pf.close()
		except IOError:
			pid = None
	
		if not pid:
			message = "pidfile %s does not exist. Daemon not running?\n"
			sys.stderr.write(message % self.pidfile)
			return # not an error in a restart

		# Try killing the daemon process	
		try:
			while 1:
				log ("trying to kill %d" % pid)
				os.kill(pid, SIGTERM)
				time.sleep(0.1)
				if os.path.exists(self.pidfile):
					log ("removing pid file %s" % self.pidfile)
					os.remove(self.pidfile)
		except OSError, err:
			err = str(err)
			if err.find("No such process") > 0:
				if os.path.exists(self.pidfile):
					os.remove(self.pidfile)
			else:
				print str(err)
				sys.exit(1)

	def restart(self):
		"""
		Restart the daemon
		"""
		self.stop()
		self.start()

	def run(self):
		"""
		You should override this method when you subclass Daemon. It will be called after the process has been
		daemonized by start() or restart().
		"""

class NetLocDaemon(Daemon):
    
    def __init__(self, pidfile, options, stdin='/dev/stdin', stdout='/dev/stdout', stderr='/dev/stderr'):
        if options.quiet == True:
            Daemon.__init__(self, pidfile, '/dev/null', '/dev/null', stderr)
        else:
            Daemon.__init__(self, pidfile, stdin, stdout, stderr)
        self.options = options
        
    def run(self):
        options = self.options
        # create the socket
        with closing(socket(AF_INET, SOCK_DGRAM)) as s:
            s.bind(('',options.port))
            s.setblocking(0)
            log ("listening on %s:%d" % ('',options.port))
            # enter the server loop
            while True:
                result = select.select([s],[],[])
                data, (address,port) = result[0][0].recvfrom(1024)
                log ("from %s, received: \"%s\"" % (address, data))
                if data == options.service: 
                    with closing(socket(AF_INET, SOCK_DGRAM)) as r:
                        randomNumber = random()
                        signature = hmac.new(options.secret, "%f" % randomNumber)
                        response = "%f:%s" % (randomNumber,signature.hexdigest())
                        r.sendto(response, (address,options.port))
                        log ("responded to %s with \"%s\"" % (address,response))

parser = OptionParser()

# server only options
parser.add_option("-s", "--server", dest="server", default=False,
                  help="to run in server mode", metavar="SERVER_FLAG")
parser.add_option("-b", "--bind", dest="bindAddr", default='0.0.0.0',
                  help="server option, for address to bind to", metavar="INTERFACE")
parser.add_option("-i", "--interface", dest="interface", default="wlan0",
                  help="server option, for address to bind to", metavar="BIND_ADDR")
parser.add_option("-P", "--pid-file", dest="pidFile", default="/tmp/netloc.pid",
                  help="server option, pid file of the server daemon", metavar="PID_FILE")
parser.add_option("-a", "--daemon-action", dest="action", default="start",
                  help="server option, start|stop|restart", metavar="DAEMON_ACTION")
# client only
parser.add_option("-c", "--client", dest="client", default=False,
                  help="to run in client mode", metavar="CLIENT_FLAG")
# client and server options
parser.add_option("-p", "--port", dest="port", default=54231,
                  help="server and client option, port to listen/transmit to", metavar="PORT")
parser.add_option("-n", "--service", dest="service", default="spartapi",
                  help="server and client option, service fqn", metavar="SERVICE_FQN")
parser.add_option("-x", "--secret", dest="secret", default="389235#$%^*EWWR9e2nfd34",
                  help="server and client option, service shared secret between client and server", metavar="SECRET_KEY")
parser.add_option("-q", "--quiet", dest="quiet", default=False,
                  help="server and client option, display no output", metavar="QUIET_MODE")

(options, args) = parser.parse_args()

if options.server:
    daemon = NetLocDaemon(pidfile=options.pidFile,options=options)
    log ("action is \"%s\"" % options.action)
    if 'start' == options.action:
        log ('starting...')
        log ("using %s" % options.interface)
        options.ipAddress = get_ip_address(options.interface)
        log ("ip address is %s" % options.ipAddress)
        daemon.start()
    elif 'stop' == options.action:
        log ('stopping...')
        daemon.stop()
    elif 'restart' == options.action:
        log ('restarting...')
        daemon.restart()
    else:
        print "Unknown command"
        sys.exit(2)
    sys.exit(0)
elif options.client:
    # wait for response
    with closing(socket(AF_INET, SOCK_DGRAM)) as r:
        # start listening
        r.bind((options.bindAddr,options.port))
        r.setblocking(0)
        done = False
        log ("broadcasting \"%s\" to %s:%d" % (options.service, '255.255.255.255', options.port))
        while done != True:
            # broadcast service query
            with closing(socket(AF_INET, SOCK_DGRAM)) as s:
                s.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)
                s.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
                s.sendto(options.service, ('255.255.255.255', options.port))
            # wait for response
            result = select.select([r],[],[],30.0)
            time.sleep(.10/1000000.0)
            if len(result[0]) != 0:
                (data, (address,port)) = result[0][0].recvfrom(1024)
                if data == options.service:
                    continue
                log ("\"%s\" received from %s" % (data, address))
                responseParts = data.split(':')
                # determine if signed valid
                randomNumber = responseParts[0]
                if len(responseParts) == 2:
                    signature = hmac.new(options.secret, randomNumber)
                    if signature.hexdigest() == responseParts[1]:
                        print "VALID:IP=%s" % address
                        done = True
                    else:
                        print "FAIL:IP=%s" % address
else:
    parser.print_help()
        

