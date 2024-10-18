/* -*- P4_16 -*- */

// CS5229 Programming Assignment 2
// Part B - Switch ML
//
// Name: Albert Einstein
// Student Number: A0123456B
// NetID: e0123456

#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<8>  IPV4_UDP_PRON = 0x11;
const bit<16> SWITCHML_UDP_PORT = 0x3824;
const bit<32> SWITCH_ML_CAPACITY = 8;
const bit<32> SWITCH_ML_HOST_NUM = 4;

const bit<32> SWITCH_IP = 0x0a0000FE;

enum bit<16> SWITCHML_OPT {
    DROPOFF = 0x0101, //257
    RECORDED = 0xFFFF, //65535
    FAILURE = 0x0000,
    RESULT = 0x1234 //4660
}

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
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

header icmp_t {
    /* TODO: your code here */
    /* Hint: define ICMP header */
    bit<16> typeCode;
    bit<16> hdrChecksum;
}

header udp_t {
    /* TODO: your code here */
    /* Hint: define UDP header */
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length;
    bit<16> checksum;
}

header switchml_t {
    /* TODO: your code here */
    /* Hint: define SwitchML header */
    bit<16> workerID;
    bit<16> opCode;
    bit<32> gradient_0;
    bit<32> gradient_1;
    bit<32> gradient_2;
    bit<32> gradient_3;
    bit<32> gradient_4;
    bit<32> gradient_5;
    bit<32> gradient_6;
    bit<32> gradient_7;
    
}

struct metadata {
    /* Do you need any meta data? */
    bit<1> update_port;
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    udp_t        udp;
    switchml_t   switch_ml;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        /* TODO: your code here */
        /* Hint: implement your parser */
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
        transition select(hdr.ipv4.protocol){
            IPV4_UDP_PRON: udp;
            default: accept;
        }
    }

    
    state udp {
        packet.extract(hdr.udp);
        transition select(hdr.udp.dstPort){
            SWITCHML_UDP_PORT : switchml;
            default: accept;
        }
    }
    state switchml {
       packet.extract(hdr.switch_ml);
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

    /* TODO: Define your registers */
    register<bit<32>>(SWITCH_ML_CAPACITY) gradients;

    register<bit<32>>(SWITCH_ML_HOST_NUM) received_bitmap; 

    bit<32> t0; 
    bit<32> t1;
    bit<32> t2;
    bit<32> t3;
    /* TODO: Define your action functions */

    action ipv4_forward_action(egressSpec_t port) {
        /* TODO: your code here */
        standard_metadata.egress_spec = port;
    }

    action record_gradient(){
        bit<32> existing_gradient;
        gradients.read(existing_gradient,0);
        gradients.write(0,existing_gradient+hdr.switch_ml.gradient_0);

        gradients.read(existing_gradient,1);
        gradients.write(1,existing_gradient+hdr.switch_ml.gradient_1);

        gradients.read(existing_gradient,2);
        gradients.write(2,existing_gradient+hdr.switch_ml.gradient_2);

        gradients.read(existing_gradient,3);
        gradients.write(3,existing_gradient+hdr.switch_ml.gradient_3);

        gradients.read(existing_gradient,4);
        gradients.write(4,existing_gradient+hdr.switch_ml.gradient_4);

        gradients.read(existing_gradient,5);
        gradients.write(5,existing_gradient+hdr.switch_ml.gradient_5);

        gradients.read(existing_gradient,6);
        gradients.write(6,existing_gradient+hdr.switch_ml.gradient_6);

        gradients.read(existing_gradient,7);
        gradients.write(7,existing_gradient+hdr.switch_ml.gradient_7);

        

    }

    action multicast() {
        standard_metadata.mcast_grp = 1;
    }

    action multicast_result(){
        bit<32> existing_gradient;
        bit<32> workindex = (bit<32>)hdr.switch_ml.workerID;
        gradients.read(existing_gradient,0);
        hdr.switch_ml.gradient_0 = existing_gradient;
        received_bitmap.write(0,0);
        gradients.write(0,0);

        gradients.read(existing_gradient,1);
        hdr.switch_ml.gradient_1 = existing_gradient;
        received_bitmap.write(1,0);
        gradients.write(1,0);

        gradients.read(existing_gradient,2);
        hdr.switch_ml.gradient_2 = existing_gradient;
        received_bitmap.write(2,0);
        gradients.write(2,0);

        gradients.read(existing_gradient,3);
        hdr.switch_ml.gradient_3 = existing_gradient;
        received_bitmap.write(3,0);
        gradients.write(3,0);

        gradients.read(existing_gradient,4);
        hdr.switch_ml.gradient_4 = existing_gradient;
        gradients.write(4,0);

        gradients.read(existing_gradient,5);
        hdr.switch_ml.gradient_5 = existing_gradient;
        gradients.write(5,0);

        gradients.read(existing_gradient,6);
        hdr.switch_ml.gradient_6 = existing_gradient;
        gradients.write(6,0);

        gradients.read(existing_gradient,7);
        hdr.switch_ml.gradient_7 = existing_gradient;
        gradients.write(7,0);

        
    }
    action drop() {
        mark_to_drop(standard_metadata);
    }

    table ipv4_forward {
        key = {
            hdr.ipv4.dstAddr: exact;
        }
        actions = {
            ipv4_forward_action;
            multicast;
            drop;
        }
        default_action = multicast();
    }

    apply {
        if (hdr.ethernet.isValid() && hdr.ipv4.isValid()) {
            /* TODO: your code here */
            /* Hint 1: verify if the secret message is destined to the switch */
            /* Hint 2: there are two cases to handle -- DROPOFF, PICKUP */
            /* Hint 3: what happens when you PICKUP from an empty mailbox? */
            /* Hint 4: remember to "sanitize" your mailbox with 0xdeadbeef after every PICKUP */
            /* Hint 5: msg_checksums are important! */
            /* Hint 6: once everything is done, swap addresses, set port and reply to sender */
            if (hdr.ipv4.dstAddr == SWITCH_IP && hdr.udp.dstPort == SWITCHML_UDP_PORT){
                meta.update_port = 1;
                if (hdr.switch_ml.opCode==SWITCHML_OPT.DROPOFF){
                    bit<32> check;
                    bit<32> workindex = (bit<32>)hdr.switch_ml.workerID;
                    received_bitmap.read(check,workindex);
                    if (check != 1){
                        record_gradient();
                        received_bitmap.write(workindex,1);
                    }
                    
                    hdr.switch_ml.opCode = SWITCHML_OPT.RECORDED;

                    received_bitmap.read(t0,0);
                    received_bitmap.read(t1,1);
                    received_bitmap.read(t2,2);
                    received_bitmap.read(t3,3);

                    if (t0==1 && t1==1 && t2==1 && t3==1){
                        multicast_result();
                        hdr.switch_ml.opCode = SWITCHML_OPT.RESULT;
                        multicast();
                    }
                    
                }
                else{
                    hdr.switch_ml.opCode = SWITCHML_OPT.FAILURE;
                }

                macAddr_t temp = hdr.ethernet.dstAddr;
                hdr.ethernet.dstAddr = hdr.ethernet.srcAddr;
                hdr.ethernet.srcAddr = temp;
                            
                ip4Addr_t tmp = hdr.ipv4.dstAddr;
                hdr.ipv4.dstAddr = hdr.ipv4.srcAddr;
                hdr.ipv4.srcAddr = tmp;

                bit<16> t = hdr.udp.dstPort;
                hdr.udp.dstPort = hdr.udp.srcPort;
                hdr.udp.srcPort = t;

                standard_metadata.egress_spec = standard_metadata.ingress_port;
                ipv4_forward.apply();
            }
            else if(hdr.ipv4.dstAddr == SWITCH_IP && hdr.udp.dstPort != SWITCHML_UDP_PORT){
                drop();
            }
            else{
                ipv4_forward.apply();
            }
        } else {
            // Not IPv4 packet
            drop();
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action set_host(macAddr_t eth_addr, ip4Addr_t ip_addr, bit<16> host_id) {
        /* TODO: your code here */
        hdr.ethernet.dstAddr = eth_addr;
        hdr.ipv4.dstAddr = ip_addr;
        hdr.switch_ml.workerID = host_id;
    }

    table port_to_host {
        key = {
            standard_metadata.egress_port : exact;
        }
        actions = {
            set_host;
            drop;
        }
        size = 1024;
        default_action = drop;
    }

    apply {
        /* TODO: your codes here */
        /* HINT: update destination information */
        /* HINT: check the runtime table, there will something you need*/
        if (meta.update_port == 1){
            port_to_host.apply();
        }
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { 
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.diffserv,
                hdr.ipv4.totalLen,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.fragOffset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr 
            },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16
        );
    }
}


/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        /* TODO: your code here */
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.udp);
        packet.emit(hdr.switch_ml);
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
