/* -*- mode: P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<16> L2_LEARN_ETHER_TYPE = 0x1234;

const bit<32> key_1 = 32w0x27FBB1F0; //??
const bit<32> key_2 = 32w0x67281;
///If you choose that to be the same port number on every such switch, then use that number, perhaps assigned as the value of a const in your P4 code. 

const bit<9> CPU_PORT = 14;


/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;


header ethernet_t {
    macAddr_t dstMac;	
    macAddr_t srcMac;	
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<8>  flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
//    bit<16> options;
}

header Tcp_option_ss_h {
    bit<8>  kind;
    bit<32> maxSegmentSize;
}

header cpu_t {
    bit<48> srcMac; //correspond to macaddress
    bit<16> ingress_port;
}

// packet in 
//@controller_header("packet_in")
header packet_in_header_t {
    bit<16>  ingress_port;
}

// packet out 
//@controller_header("packet_out")
header packet_out_header_t {
    bit<16> egress_port;
    //bit<16> mcast_grp;
}



struct meta_t {
    bit<16> tcpLength;
    bit<32> hash_count;
    bit<32> hash_1;
    bit<32> hash_2;
    bit<32> mss;
    bit<32> cookie;
    bit<32> mss_cookie;
    bit<32> count_cookie;
    bit<32> ISN_d;
    bit<32> ISN_s;
    bit<9> ingress_port;

}

struct metadata {
  meta_t meta;
}

struct headers {
    packet_out_header_t     packet_out;
    packet_in_header_t      packet_in;
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    tcp_t	 tcp;
    Tcp_option_ss_h	Tcp_option_ss;
    cpu_t	cpu;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
               inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
	meta.meta.tcpLength = hdr.ipv4.totalLen - 16w20;
        transition select(hdr.ipv4.protocol) {
            6: parse_tcp;
	    default: accept;
	}	
    }
    
    state parse_tcp {
        packet.extract(hdr.tcp);
//	Tcp_option_parser.apply(packet, hdr.tcp.dataOffset,
//                                hdr.tcp_options_vec, hdr.tcp_options_padding);
        transition accept;
    }
}


/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  }
}

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {


    action drop() {
        mark_to_drop(standard_metadata);
    }
    
  /*************************************************************************
************   COOKIE GENERATION   *************
*************************************************************************/
    action swap_add_mac(inout bit<48> srcMac,inout bit<48> dstMac) {
	bit<48> tmp = srcMac;
	srcMac = dstMac;
	dstMac = tmp;
    }

    action swap_add_ip(inout bit<32> srcAddr, inout bit<32> dstAddr) {
	bit<32> tmp = srcAddr;
	srcAddr = dstAddr;
	dstAddr = tmp;
    }

    action swap_port_nb(inout bit<16> srcPort, inout bit<16> dstPort) {
	bit<16> tmp =srcPort;
	srcPort = dstPort;
	dstPort = tmp;
    }

    action return_synack()
    {
//
	meta.meta.hash_count = (bit<32>)standard_metadata.ingress_global_timestamp;	
	
//MSS - Max Segment Size extract from SYN packet 
	meta.meta.mss = (bit<32>)hdr.Tcp_option_ss.maxSegmentSize;

       	//extern void hash<O, T, D, M>(out O result, in HashAlgorithm algo, in T base, in D data, in M max);

//H1 = hash(IP_s, IP_d, Port_s, Port_d, K1)
	hash(meta.meta.hash_1, HashAlgorithm.crc16, (bit<16>)0, {hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.tcp.srcPort, hdr.tcp.dstPort, key_1 }, (bit<32>)65536);

//H1 = hash(IP_s, IP_d, Port_s, Port_d, K2, timestamp)
	hash(meta.meta.hash_2, HashAlgorithm.crc16, (bit<16>)0, {hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.tcp.srcPort, hdr.tcp.dstPort, key_2, meta.meta.hash_count }, (bit<32>)65536);

//ISN_d(cookie) = H1 + ISN_s + (timestamp × 2^24)+(H2 + MSS) mod 2^24

	meta.meta.cookie = meta.meta.hash_1+hdr.tcp.seqNo+(meta.meta.hash_count*0x01000000)+(meta.meta.hash_2+meta.meta.mss) & 0xffffff;

	swap_add_mac(hdr.ethernet.srcMac, hdr.ethernet.dstMac);
	swap_add_ip(hdr.ipv4.srcAddr, hdr.ipv4.dstAddr);
	swap_port_nb(hdr.tcp.srcPort, hdr.tcp.dstPort);
        hdr.tcp.flags = 8w0x12;	
	hdr.tcp.ackNo =(bit<32>)(hdr.tcp.seqNo + 32w0x00000001);

//afect the hash_cookie to SeqNo
        hdr.tcp.seqNo = (bit<32>)meta.meta.cookie;
	standard_metadata.egress_spec = standard_metadata.ingress_port;

    }


  action ipv4_forward(macAddr_t dstMac, egressSpec_t port)  {	
        standard_metadata.egress_spec = port;	
        hdr.ethernet.srcMac = hdr.ethernet.dstMac;
        hdr.ethernet.dstMac = dstMac;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.srcAddr: exact;
            hdr.ipv4.dstAddr: exact;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }
/**
      * Send the packet to the CPU port
      
      action Send_to_cpu() {
          outCtrl.outputPort = CPU_OUT_PORT;
      }*/

 action send_to_cpu(){
        standard_metadata.egress_spec = CPU_PORT;
        hdr.packet_in.setValid();
        hdr.packet_in.ingress_port = (bit<16>)standard_metadata.ingress_port;
    }


/*************************************************************************
************   Cookie 	V E R I F I C A T I O N   *************
*************************************************************************/
    
   action ACK_verify()		//Apply this action if it is an ACK packet
    {
	meta.meta.ISN_d = hdr.tcp.ackNo-1;
	meta.meta.ISN_s = hdr.tcp.seqNo-1;
//if count_cookie <=2 minutes and mss_cookie is within the 2 bit range (0,1,2,3) the ACK is valid 

//count(cookie) = (ISN_d − H1 − ISN_s)/2^24
	meta.meta.count_cookie = (meta.meta.ISN_d - meta.meta.hash_1 - meta.meta.ISN_s)/ 0x01000000;
//MSS(cookie) = (ISN_d − H1 − ISN_s) mod 2^24 − H2 mod 2^24
	meta.meta.mss_cookie = (meta.meta.ISN_d - meta.meta.hash_1 - meta.meta.ISN_s) & 0xffffff - meta.meta.hash_2 & 0xffffff;
    }


    apply {

	ipv4_lpm.apply();

	if (hdr.tcp.flags == 02) {
	   return_synack();
	}
	else if (hdr.tcp.flags == 10) {
	    ACK_verify();
	////if count_cookie <=2 minutes and mss_cookie is within the 2 bit range (0,1,2,3) the ACK is valid 
	
		if ((meta.meta.count_cookie <= 120) && (0 <= meta.meta.mss_cookie) && (meta.meta.mss_cookie <= 3)){
		send_to_cpu();}
		else{
		drop();	}	
	}

	  

    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {         

	if (standard_metadata.egress_port == CPU_PORT) {
            hdr.packet_in.setValid();
            hdr.packet_in.ingress_port = (bit<16>)standard_metadata.ingress_port;
        } }
}



/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/


control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	      hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);

	 update_checksum_with_payload(
				true,
				{ hdr.ipv4.srcAddr,
				  hdr.ipv4.dstAddr, 
				  8w0, 
				  hdr.ipv4.protocol, 
				  meta.meta.tcpLength, 
				  hdr.tcp.srcPort, 
				  hdr.tcp.dstPort,
				  hdr.tcp.seqNo, 
				  hdr.tcp.ackNo, 
				  hdr.tcp.dataOffset, 
				  hdr.tcp.res, 
				  hdr.tcp.flags, 
				  hdr.tcp.window,
				  hdr.tcp.urgentPtr },
				 hdr.tcp.checksum, 
				 HashAlgorithm.csum16);
				}
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
	packet.emit(hdr.tcp);
	packet.emit(hdr.packet_in);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
