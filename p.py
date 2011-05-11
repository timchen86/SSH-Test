#!/usr/bin/env python
import signal
import subprocess
import sys

class Alarm(Exception):
	print('in class Alarm()')
	pass

def alarm_handler(signum, frame):
	print('in alarm_handler()')
	raise Alarm

if(len(sys.argv)!=3):
	print('argv!=3')
	sys.exit(1)

proc = subprocess.Popen(sys.argv[1], stdout=subprocess.PIPE,\
									 stderr=subprocess.PIPE)

signal.signal(signal.SIGALRM, alarm_handler)
signal.alarm(int(sys.argv[2]))

try:
	stdoutdata, stderrdata = proc.communicate()
	signal.alarm(0)  # reset the alarm
except Alarm:
	print "Oops, taking too long!"
	# whatever else
