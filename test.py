from trex_stl_lib.api import *

c = STLClient(server = '127.0.0.1')
c.connect()

try:

    c.acquire(ports=[0, 1])
    c.set_service_mode(ports = [0, 1])

    # start a capture
    id = c.start_capture(tx_ports = [0], rx_ports = [1],
                            limit = 100, bpf_filter = 'icmp and len >= 200')

    # generate some ping packets from port 0 to port 1 with 200 bytes
    c.ping_ip(src_port = port_0, dst_ip = '4.4.4.4', pkt_size = 200, count = 5)

    # print the capture status so far
    status = c.get_capture_status()
    #print("Packet Capture Status:\n{0}".format(status))

    # save the packets to PCAP
    c.stop_capture(capture_id = id['id'], output = '/tmp/pings.pcap')

except STLError as e:
    print(e)

finally:
    c.set_service_mode(ports = [0, 1], enabled = False)
    c.disconnect()
