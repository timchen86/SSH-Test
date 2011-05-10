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
SSHDIR=os.getenv('HOME')+'/.ssh'
SSHD_INPS='/sshd'
SSH='/usr/bin/ssh'
USER=os.getlogin()

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
		print('subprocess.Popen() takes too long. Return.')
		return False
	
	return output, proc.returncode


def check_exe(files):
	for f in files:
		if(not os.path.isfile(f)) or (not os.access(f, os.X_OK)):
			print('{0} is not available.'.format(f))
			return False
	return True

def password_auth(host):
	SSHPASS='/usr/bin/sshpass'
	SSHKEYGEN='/usr/bin/ssh-keygen'
	SSHKEYSCAN='/usr/bin/ssh-keyscan'
	PASSFILE=os.getcwd()+'/password'
	AUTHNAME='password authentication'

	# check all necessary executables
	if( not check_exe([SSHPASS,SSHKEYGEN,SSHKEYSCAN]) ):
		return False
	
	# check all necessary files for read 
	for f in [PASSFILE]:
		if(not os.path.isfile(f)) or (not os.access(f, os.R_OK)):
			print('{0} is not available.'.format(f))
			return False

	# password authentication with sshpass
	# sshpass -f password ssh -q -o \
        # PreferredAuthentications=password ctf@localhost /bin/sh -c exit
	ARG=[SSHPASS,'-f',PASSFILE,SSH,'-q','-o','StrictHostKeyChecking=no',\
				       '-o','PreferredAuthentications=password',\
				       '{0}@{1}'.format(USER,host),'/bin/sh','-c','exit']
	# print(ARG)

	o,r = runproc(ARG,5)

	if r == 0:
		print('{0} successful.'.format(AUTHNAME))
	else:
		print('{0} failed, code={1}.'.format(AUTHNAME,r))
		print('\'man sshpass\' for return code.')
		return False


def publickey_auth(host):
	SCP='/usr/bin/scp'
	UUID=open('/proc/sys/kernel/random/uuid','r').read()
	TMP1='/tmp/sshchk.{0}'.format(UUID[:-1])	# remove '\n'
	TMP2=TMP1+'.copy'
	AUTHFILE=SSHDIR+'/authorized_keys'
	AUTHNAME='public key authentication'

	# check scp
	if( not check_exe([SCP]) ):
		return False
	
	# check all necessary files for read 
	for f in [AUTHFILE]:
		if(not os.path.isfile(f)) or (not os.access(f, os.R_OK)):
			print('{0} is not available.'.format(f))
			print('Test may be failed due to authorized_keys file, test continues.')
			print('you may add public key to authorized_keys, like below example')
			print('cat ~/.ssh/id_rsa.pub >> ~/.ssh/authorized_keys')

	# Create the tmp file
	try:
		open(TMP1, 'w').close()

		# scp -Bq user@localhost:file dst:file
		ARG = [SCP,'-o','PubkeyAuthentication=yes',\
                           '-o','PreferredAuthentications=publickey',\
	                   '-o','StrictHostKeyChecking=no',\
               		   '-Bq','{0}@{1}:{2}'.format(USER,host,TMP1),TMP2]
		#print ARG
	
		o,r = runproc(ARG,5)
	
		if r == 0:
			print('{0} successful.'.format(AUTHNAME))
		else:
			print('{0} failed, code={1}.'.format(AUTHNAME,r))
			return False
	finally:
		try: 
			os.remove(TMP1)
			os.remove(TMP2)
		except:
			pass

	return True



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

	parser.add_argument('host', type=str, metavar='HOST',\
                            default='localhost.localdomain', nargs='?', \
                            help='the host to perform the SSH test, for host-based authenticaion, \
                            the host name must be in FQDN. default: localhost.localdomain')

	args = parser.parse_args()
	authtype, host = args.authtype, args.host
	
	print('host is {0}'.format(host))

	# check ssh directories
	for d in [SSHDIR]:
		if(not os.path.isdir(d)) or (not os.access(d, os.R_OK)):
			print('{0} is not available.'.format(d))
			sys.exit(1)

	# check if key files available under .ssh
	f = os.listdir(SSHDIR)
	if len(f) < 2:	# at least we need public key and private key
		print('The public/private key files are not available.')
		sys.exit(1)

	# check if sshd is running
	o,r = runproc(['ps','ax'],5) 

	if SSHD_INPS not in o:
		print('sshd is not running.')
		sys.exit(1)

	if authtype == 0:
		r=publickey_auth(host)
	elif authtype == 1:
		r=password_auth(host)
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
