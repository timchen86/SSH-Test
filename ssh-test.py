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

def runproc(command,seconds):
	proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
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
	PASSFILE=os.getcwd()+'/password'	# XXX: insecure
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
	# sshpass -f password ssh -q -o PreferredAuthentications=password ctf@localhost /bin/sh -c exit
	ARG=[SSHPASS,'-f',PASSFILE,SSH,'-q','-o','StrictHostKeyChecking=no','-o','PreferredAuthentications=password','{0}@{1}'.format(USER,host),'/bin/sh','-c','exit']

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



def publickey_auth(host):
	SCP='/usr/bin/scp'
	TMP1='/tmp/sshchk.'+MAGIC
	TMP2=TMP1+'.copy'
	SSHD='sshd '
	AUTHNAME='public key'

	# Create the tmp file
	try:
		open(TMP1, 'w').close()

		# scp -Bq user@localhost:file dst:file
		ARG = [SCP,'-Bq',USER+'@localhost:'+TMP1,TMP2]
	
		try:
			proc.communicate()
			signal.alarm(0)
	        except Alarm:
			print('subprocess.Popen() takes too long. Return.')
			return False


		if proc.returncode == 0:
			print(AUTHNAME+' successful.')
		else:
			print(AUTHNAME+' failed.')
			return False
	finally:
		try: 
			os.remove(TMP1)
			os.remove(TMP2)
		except:
			pass

	return False


def host_auth(host):
	return False

def keyboard_auth(host):
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

	# check all directories
	for d in [SSHDIR]:
		if(not os.path.isdir(d)) or (not os.access(d, os.R_OK)):
			print('{0} is not available.'.format(d))
			return False

	# check if key files available under .ssh
	f = os.listdir(SSHDIR)
	if len(f) < 2:	# at least we need public key and private key
		print('The public/private key files are not available.')
		return False

# check if the host in known_hosts
#	o,r = runproc([SSHKEYGEN,'-H','-F',host],5) 

#	if host not in o:
#		print('Host {0} is not in {1}.'.format(host,KNOWNHOSTS))
#		print('Run: {0} -H -t rsa {1} >> {2}'.format(SSHKEYSCAN,host,KNOWNHOSTS))
#		return False

	# check if sshd is running
	o,r = runproc(['ps','ax'],5) 

	if SSHD not in o:
		print('sshd is not running.')
		return False

	if authtype == 0:
		publickey_auth(host)
	elif authtype == 1:
		password_auth(host)
	elif authtype == 2:
		host_auth(host)
	elif authtype == 3:
		keyboard_auth(host)
	else:
		print('Wrong authentication type.')	# should be detected earlier in parser.add_argument()
		return False
	
if __name__ == '__main__':
    main()

