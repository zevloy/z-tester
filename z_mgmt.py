
'''
Running the test in this script, called by Intelligent Tester Directly.

############################################## Calling Method ##################################################
# python D:\cc\Client\documents\projectcase\sxf656879\G_rule-matching_10_91\6/case91_p1_tx.py
# 2099 6_2018-09-03_18-22-07 :D\cc\Client\documents\projectcase\sxf656879\G_rule-matching_10_91\\log\2099\TSC\
# 10.240.20.228 "[0, 1]" Fiber 10000
# python z_mgmt.py 2099 6_2018-09-03_18-22-07 ./log/2099/TSC/ 127.0.0.1 "[0,1]" Fiber 10000
############################################## Calling Method ##################################################

Created on Oct 29, 2018
@author: zevloy
'''

import paramiko
from sys import argv
#from scapy.all import *  # MUST use the scapy lib provided by Trex.
from trex_stl_lib.api import *
from StcStream import StcStlStream

filename, jobid, casename, log_path, device, port_list, phy_mode, burst_loop_count = argv
print "file name is: %s" % filename

def start_ssh_server():
    # # create a instance of Transport
    trans = paramiko.Transport(("127.0.0.1", 22))
    # make connection
    trans.connect(username='vagrant', password='vagrant')

    # create a SSHClient instance
    ssh = paramiko.SSHClient()
    ssh._transport = trans
    # execute the command
    stdin, stdout, stderr = ssh.exec_command('df -hl')
    print(stdout.read().decode())

    # close the connection
    trans.close()


def fetch_log():
    # create a instance of Transport
    trans = paramiko.Transport(("211.94.162.158", 6556))
    # make connection
    trans.connect(username="root", password="111111")

    # create a instance SFTPClient and specify the channel
    sftp = paramiko.SFTPClient.from_transport(trans)
    # upload the file
    sftp.put(localpath='/tmp/11.txt', remotepath='/tmp/22.txt')

    # download the file
    # sftp.get(remotepath, localpath)
    trans.close()


def connect_ssh_server():
    # # create a instance of Transport
    trans = paramiko.Transport(("127.0.0.1", 22))
    # make connection
    trans.connect(username='vagrant', password='vagrant')

    # create a SSHClient instance
    ssh = paramiko.SSHClient()
    ssh._transport = trans
    # execute the command
    stdin, stdout, stderr = ssh.exec_command('ifconfig eth0')
    if 'UP' in stdout.read().decode():
        print "eth0 status is OK!"
    else:
        print "eth0 is down!"

    # close the connection
    trans.close()

# it is the IP of Spirent Test Center or the IP of packet generator.
dev = device
# the Tester's ports being used, "[0, 1]"
port_a, port_b = eval(port_list)

# the directory for the log
log_path = log_path + "/" + casename + "_"
temp_path = '../log/%s/TSC/%s_' % (jobid, casename)

