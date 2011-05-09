#!/usr/bin/env python
import subprocess
import signal
import os
import argparse

def main():
	class Alarm(Exception):
		pass

	def alarm_handler(signum, frame):
		raise Alarm

	SSHPASS='/usr/bin/sshpass'
	SSHKEYGEN='/usr/bin/ssh-keygen'
	SSHKEYSCAN='/usr/bin/ssh-keyscan'
	SSHDIR=os.getenv('HOME')+'/.ssh'
	PASSFILE=os.getcwd()+'/password'	# XXX: insecure
	KNOWNHOSTS=SSHDIR+'/known_hosts'
	SSHD='/sshd'
	USER=os.getlogin()
	AUTHNAME='SSH password authentication'
	HOSTNAME='localhost'


	# check all necessary executables
	for f in [SSHPASS,SSHKEYGEN,SSHKEYSCAN]:
		if(os.path.isfile(f)==False) or (os.access(f, os.X_OK)==False):
			print('{0} is not available.'.format(f))
			return False
	
	# check all necessary files for read 
	for f in [PASSFILE]:
		if(os.path.isfile(f)==False) or (os.access(f, os.R_OK)==False):
			print('{0} is not available.'.format(f))
			return False
	
	# check all directories
	for d in [SSHDIR]:
		if(os.path.isdir(d)==False) or (os.access(f, os.R_OK)==False):
			print('{0} is not available.'.format(f))
			return False

	# check if key files available under .ssh
	f = os.listdir(SSHDIR)
	if len(f) < 2:	# at least we need public key and private key
		print('The public/private key files are not available.')
		return False

	# check if the host in known_hosts
	proc = subprocess.Popen([SSHKEYGEN,'-H','-F',HOSTNAME], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	signal.signal(signal.SIGALRM, alarm_handler)
	signal.alarm(5)	# in seconds
	
	output = proc.stdout.read()

	try:
		proc.communicate()
		signal.alarm(0)
	except Alarm:
		print('subprocess.Popen() takes too long. Return.')
		return False

	if HOSTNAME not in output:
		print('Host {0} is not in {1}.'.format(HOSTNAME,KNOWNHOSTS))
		print('Run: {0} -H -t rsa {1} >> {2}'.format(SSHKEYSCAN,HOSTNAME,KNOWNHOSTS))
		return False

	# check if sshd is running
	proc = subprocess.Popen(['ps','ax'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	signal.signal(signal.SIGALRM, alarm_handler)
	signal.alarm(5)	# in seconds

	output = proc.stdout.read()

	try:
		proc.communicate()
		signal.alarm(0)
	except Alarm:
		print('subprocess.Popen() takes too long. Return.')
		return False

	if SSHD not in output:
		print('sshd is not running.')
		return False

	# password authentication with sshpass
	# sshpass -f password ssh -q -o PreferredAuthentications=password ctf@localhost /bin/sh -c exit
	ARG=[SSHPASS,'-f',PASSFILE,'ssh','-q','-o','PreferredAuthentications=password',USER+'@localhost','/bin/sh','-c','exit']

	print(ARG)
	proc = subprocess.Popen(ARG, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	signal.signal(signal.SIGALRM, alarm_handler)
	signal.alarm(5)	# in seconds

	try:
		proc.communicate()
		signal.alarm(0)
	except Alarm:
		print('subprocess.Popen() takes too long. Return.')
		return False

	if proc.returncode == 0:
		print(AUTHNAME+' successful.')
	else:
		print('{0} failed, code={1}.'.format(AUTHNAME,proc.returncode))
		return False



if __name__ == '__main__':
    main()

