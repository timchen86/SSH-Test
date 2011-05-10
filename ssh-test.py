#!/usr/bin/env python
import subprocess
import signal
import os
import sys
import argparse

class Alarm(Exception):
	pass

def alarm_handler(signum, frame):
	raise Alarm

# global
AUTHTYPES = ['public key','password','host-based']
SSH='/usr/bin/ssh'

def runproc(command,seconds):
	proc = subprocess.Popen(command, stdout=subprocess.PIPE,\
                                         stderr=subprocess.PIPE)
	signal.signal(signal.SIGALRM, alarm_handler)
	signal.alarm(seconds)
	
	output = proc.stdout.read()

	try:
		proc.communicate()
		signal.alarm(0)
	except Alarm:
		print('subprocess.Popen() takes too long. Exit.')
		sys.exit(1)
	
	return output, proc.returncode


def check_exe(files):
	for f in files:
		if(not os.path.isfile(f)) or (not os.access(f, os.X_OK)):
			print('{0} is not available.'.format(f))
			return False
	return True

def password_auth(user,host):
	SSHPASS='/usr/bin/sshpass'
	PASSFILE=os.getcwd()+'/password'
	AUTHNAME='password authentication'

	# check all necessary executables
	if( not check_exe([SSHPASS]) ):
		return False
	
	# check all necessary files for read 
	for f in [PASSFILE]:
		if(not os.path.isfile(f)) or (not os.access(f, os.R_OK)):
			print('{0} is not available. Store the user password in this file'.format(f))
			return False

	# password authentication with sshpass
	# sshpass -f password ssh -q -o \
        # PreferredAuthentications=password ctf@localhost /bin/sh -c exit
	ARG=[SSHPASS,'-f',PASSFILE,SSH,'-q','-o','StrictHostKeyChecking=no',\
				       '-o','PreferredAuthentications=password',\
				       '{0}@{1}'.format(user,host),'/bin/sh','-c','exit']
	# print(ARG)

	o,r = runproc(ARG,5)

	if r == 0:
		print('{0} successful.'.format(AUTHNAME))
	else:
		print('{0} failed, code={1}.'.format(AUTHNAME,r))
		print('\'man sshpass\' for return code.')
		return False


def publickey_auth(user,host):
	AUTHNAME='public key authentication'
	ARG=[SSH,'-q','-o','StrictHostKeyChecking=no',\
                 '-o','PreferredAuthentications=publickey',\
                 '{0}@{1}'.format(user,host),'/bin/sh','-c','exit']
	# print(ARG)

	o,r = runproc(ARG,5)

	if r == 0:
		print('{0} successful.'.format(AUTHNAME))
	else:
		print('{0} failed, code={1}.'.format(AUTHNAME,r))
		return False


def hostbased_auth(host):
	AUTHNAME='host-based authentication'
	ARG=[SSH,'-q','-o','StrictHostKeyChecking=no',\
                 '-o','PreferredAuthentications=hostbased',\
                 host,'/bin/sh','-c','exit']
	# print(ARG)

	o,r = runproc(ARG,5)

	if r == 0:
		print('{0} successful.'.format(AUTHNAME))
	else:
		print('{0} failed, code={1}.'.format(AUTHNAME,r))
		return False



def main():
	# arguments parsing
	parser = argparse.ArgumentParser(description='SSH authentication test.')

	# format the help string for authtype
	h=''
	for a in range(len(AUTHTYPES)):
		h += '{0}: {1}, '.format(a,AUTHTYPES[a])
	h=h[:-2]+'.'

	parser.add_argument('-a', type=int, dest='authtype', required=True,\
                            choices=range(len(AUTHTYPES)),\
                            help='the authentication type, {0}'.format(h))

	parser.add_argument('user', type=str, metavar='USER', \
                            help='the user for public key and password authentication.')

	parser.add_argument('host', type=str, metavar='HOST',\
                            default='localhost.localdomain', nargs='?', \
                            help='the host to perform the SSH test, for host-based authenticaion, \
                            the host name must be in FQDN. default: localhost.localdomain')

	args = parser.parse_args()
	authtype, user, host = args.authtype, args.user, args.host
	
	print('user is {0}'.format(user))
	print('host is {0}'.format(host))

	if authtype == 0:
		r=publickey_auth(user,host)
	elif authtype == 1:
		r=password_auth(user,host)
	elif authtype == 2:
		r=hostbased_auth(host)
	else:
		# should be caught earlier in parser.add_argument()
		print('Wrong authentication type.')			
		sys.exit(1)

	if(r):
		sys.exit(0)
	else:	
		sys.exit(1)
	
if __name__ == '__main__':
    main()
