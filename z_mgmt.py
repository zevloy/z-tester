# -*- coding: UTF-8 -*-s
'''
Implementation of the z-tester management related job.

Created on Oct 16, 2018
@author: zevloy
'''

import paramiko
from sys import argv
from pkt_gen import send_stc_pkt, traffic_stats


filename, jobid, casename, log_path, device, port_list, phy_mode, burst_loop_count = argv 

def run_pkt_gen():
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


#it is the IP of Spirent Test Center or the IP of packet generator.
dev = device
#the Tester's ports being used
port_list = eval(port_list)

port_handle = []
#the directory for the log
log_path = log_path + "/" + casename + "_"
temp_path='../log/%s/TSC/%s_' % (jobid, casename)

#send stc pkt
pkt_gen.send_stc_pkt(f="StcConf\case91_traffic_config.xml")


#get traffic sending result
traffic_results_ret = pkt_generator.traffic_stats (
        port_handle                                      = [port_handle[0],port_handle[1]],
        mode                                             = 'all');

status = traffic_results_ret['status']
if (status == '0') :
    print("run sth.traffic_stats failed")
    print(traffic_results_ret)
else:
    print("***** run sth.traffic_stats successfully, and results is:")
    print(traffic_results_ret)

    t_filename=log_path+'traffic_all.txt'
    fp = open(t_filename,'w+')
    fp.write(str(traffic_results_ret))
    fp.close