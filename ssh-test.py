#!/usr/bin/env python
import subprocess
import signal
import os
import argparse


class Alarm(Exception):
	pass

def alarm_handler(signum, frame):
	raise Alarm


# global required
AUTHTYPES = ['public key','password','host-based','keyboard']
SSHDIR=os.getenv('HOME')+'/.ssh'
SSHD='/sshd'
SSH='/usr/bin/ssh'
USER=os.getlogin()


def password_auth(host):
	SSHPASS='/usr/bin/sshpass'
	SSHKEYGEN='/usr/bin/ssh-keygen'
	SSHKEYSCAN='/usr/bin/ssh-keyscan'
	PASSFILE=os.getcwd()+'/password'	# XXX: insecure
	KNOWNHOSTS=SSHDIR+'/known_hosts'
	AUTHNAME='password authentication'

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
	proc = subprocess.Popen([SSHKEYGEN,'-H','-F',host], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	signal.signal(signal.SIGALRM, alarm_handler)
	signal.alarm(5)	# in seconds
	
	output = proc.stdout.read()

	try:
		proc.communicate()
		signal.alarm(0)
	except Alarm:
		print('subprocess.Popen() takes too long. Return.')
		return False

	if host not in output:
		print('Host {0} is not in {1}.'.format(host,KNOWNHOSTS))
		print('Run: {0} -H -t rsa {1} >> {2}'.format(SSHKEYSCAN,host,KNOWNHOSTS))
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
	ARG=[SSHPASS,'-f',PASSFILE,SSH,'-q','-o','PreferredAuthentications=password','{0}@{1}'.format(USER,host),'/bin/sh','-c','exit']

	# print(ARG)
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
		print('{0} successful.'.format(AUTHNAME))
	else:
		print('{0} failed, code={1}.'.format(AUTHNAME,proc.returncode))
		print('\'man sshpass\' for return code.')
		return False

def main():
	# arguments parsing
	parser = argparse.ArgumentParser(description='SSH authentication test.')

	# format the help string for authtype
	h=''
	for a in range(len(AUTHTYPES)):
		h += '{0}: {1}, '.format(a,AUTHTYPES[a])

	h=h[:-2]+'.'

	parser.add_argument('-a', type=int, dest='authtype', required=True, choices=range(len(AUTHTYPES)), help='the authentication type, {0}'.format(h))
	parser.add_argument('host', type=str, metavar='HOST', default='localhost', nargs='?', help='the host to perform the SSH test, default: localhost')

	args = parser.parse_args()
	authtype, host = args.authtype, args.host


	password_auth(host)


if __name__ == '__main__':
    main()

