#!/usr/bin/env python2
# -*- coding: utf-8 -*-
import argparse, grpc, os, sys
from time import sleep
from scapy.all import *

# set our lib path
sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
        '../../utils/'))

# And then we import
import p4runtime_lib.bmv2
from p4runtime_lib.switch import ShutdownAllSwitchConnections
import p4runtime_lib.helper

#SWITCH_TO_HOST_PORT = 1
#SWITCH_TO_SWITCH_PORT = 2

def writeACKReply(p4info_helper, sw, in_port, src_ip_addr, dst_ip_addr, dst_eth_addr, port):

    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.ipv4_lpm",
        match_fields={
            "hdr.ipv4.srcAddr": src_ip_addr,
            "hdr.ipv4.dstAddr": dst_ip_addr,
        },
        action_name="MyIngress.ipv4_forward",
        action_params={
            "dstMac": dst_eth_addr,
	    "port": port
        })
    sw.WriteTableEntry(table_entry)
    print "Installed forwarding ip_v4 rule on %s" % sw.name


def printGrpcError(e):
    print "gRPC Error: ", e.details(),
    status_code = e.code()
    print "(%s)" % status_code.name,
    # detail about sys.exc_info - https://docs.python.org/2/library/sys.html#sys.exc_info
    traceback = sys.exc_info()[2]
    print "[%s:%s]" % (traceback.tb_frame.f_code.co_filename, traceback.tb_lineno)

def main(p4info_file_path, bmv2_file_path):
    # Instantiate a P4Runtime helper from the p4info file
    # - then need to read from the file compile from P4 Program, which call .p4info
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file_path)
    port_map = {}
    IP_rules = {}
    flag = 0
  #  bcast = "ff:ff:ff:ff:ff:ff"

    try:
        """
         Create a switch connection object for s1 and s2;
          this is backed by a P4Runtime gRPC connection.
          Also, dump all P4Runtime messages sent to switch to given txt files.
         """
        s1 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s1',
            address='127.0.0.1:50051',
            device_id=0,
            proto_dump_file='logs/s1-p4runtime-requests.txt')

        # Send master arbitration update message to establish this controller as
        # master (required by P4Runtime before performing any other write operation)
        s1.MasterArbitrationUpdate()

        # Install the P4 program on the switch
        s1.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                        bmv2_json_file_path=bmv2_file_path)
        print "Installed P4 Program using SetForardingPipelineConfig on s1"
	
	 # Write the rules that forward traffic from h1 to h2
        writeACKReply(p4info_helper, sw=s1, in_port=1, src_ip_addr="10.0.1.1", dst_ip_addr="10.0.2.2", dst_eth_addr="08:00:00:00:02:22", port=2)
        print "rule h1_h2 is Installed "
       
	# Write the rules that tunnel traffic from h2 to h1
        writeACKReply(p4info_helper, sw=s1, in_port=2, src_ip_addr="10.0.2.2", dst_ip_addr="10.0.1.1", dst_eth_addr="08:00:00:00:01:11", port=1)
        print "rule h2_h1 is Installed "
        
# I have to define readtablerules function
#	def readTableRules(p4info_helper, sw):
	#readTableRules(p4info_helper, s1)

      	#allow controller to create and write new flow rule from validated ACK packet 
        while True:
            packetin = s1.PacketIn()
            if packetin.WhichOneof('update')=='packet':
                # print("Received Packet-in\n")
#TCP to include
                packet = packetin.packet.payload
               # pkt = Ether(_pkt=packet)
                pkt = Ipv4(_pkt=packet)
                metadata = packetin.packet.metadata 
                for meta in metadata:
                    metadata_id = meta.metadata_id 
                    value = meta.value 

                pkt_eth_src = pkt.getlayer(Ether).src 
                pkt_eth_dst = pkt.getlayer(Ether).dst 
                ether_type = pkt.getlayer(Ether).type
		pkt_ipv4_src = pkt.getlayer(Ipv4).dst
		pkt_ipv4_dst = pkt.getlayer(Ipv4).dst

                if ether_type == 2048 or ether_type == 2054:
                    #port_map.setdefault(pkt_eth_src, value)
                    port_map.setdefault(pkt_eth_src, value)
                    IP_rules.setdefault(value, [])

                   #if pkt_eth_dst not in IP_rules[value]:
                    if pkt_ipv4_dst not in IP_rules[value]:
#writeACKReply(p4info_helper, sw=s1, in_port=value, src_ip_addr=pkt_ipv4_src,  src_eth_addr=pkt_eth_src, dst_ip_addr=pkt_ipv4_dst, dst_eth_addr=pkt_eth_dst,  port=port_map[pkt_eth_dst])
			writeACKReply(p4info_helper, sw=s1, in_port=value, src_ip_addr=pkt_ipv4_src, dst_ip_addr=pkt_ipv4_dst, dst_eth_addr=pkt_eth_dst, port=port_map[pkt_eth_dst])
                            #IP_rules[value].append(pkt_eth_dst)
			IP_rules[value].append(pkt_ipv4_dst)

                        #if pkt_ipv4_src not in IP_rules[port_map[pkt_eth_dst]]:
                    if pkt_ipv4_src not in IP_rules[port_map[pkt_eth_dst]]:
                        writeACKReply(p4info_helper, sw=s1, in_port=port_map[pkt_eth_dst], src_ip_addr=pkt_ipv4_dst, dst_ip_addr=pkt_ipv4_src, dst_eth_addr=pkt_eth_src, port=port_map[pkt_eth_src])
				#IP_rules[port_map[pkt_eth_dst]].append(pkt_eth_dst)
                        IP_rules[port_map[pkt_eth_dst]].append(pkt_ipv4_src)


                        #build packetout and send it to SWITCH not to the target 
                       
                    print "========================="
                    print "port_map:%s" % port_map
                    print "IP_rules:%s" % IP_rules
                    print "=========================\n"


    except KeyboardInterrupt:
        # using ctrl + c to exit
        print "Shutting down."
    except grpc.RpcError as e:
        printGrpcError(e)

    # Then close all the connections
    ShutdownAllSwitchConnections()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='P4Runtime Controller')
    parser.add_argument('--p4info', help='p4info proto in text format from p4c',
                        type=str, action="store", required=False,
                        default='./build/SYN_cookie.p4.p4info.txt')
    parser.add_argument('--bmv2-json', help='BMv2 JSON file from p4c',
                        type=str, action="store", required=False,
                        default='./build/SYN_cookie.json')
    args = parser.parse_args()

    if not os.path.exists(args.p4info):
        parser.print_help()
        print "\np4info file not found: %s\nHave you run 'make'?" % args.p4info
        parser.exit(1)
    if not os.path.exists(args.bmv2_json):
        parser.print_help()
        print "\nBMv2 JSON file not found: %s\nHave you run 'make'?" % args.bmv2_json
        parser.exit(1)
    main(args.p4info, args.bmv2_json)
