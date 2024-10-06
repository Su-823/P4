/* -*- P4_16 -*- */

// CS5229 Programming Assignment 2
// Part A - 2 Secret Message
//
// Name: Albert Einstein
// Student Number: A0123456B
// NetID: e0123456

#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_SECRET = 0xFFFF;
const bit<32> SWITCH_IP = 0x0a0000FE;

enum bit<16> SECRET_OPT {
    DROPOFF = 0x0001,
    PICKUP  = 0x0002,
    SUCCESS = 0xFFFF,
    FAILURE = 0x0000,
    WRONGPW = 0x2333
}

const bit<8>  IPV4_UDP_PRON = 0x11;
const bit<32> OV_VAL = 0xdeadbeef;
const bit<32> MAX_HASHED_VAL = 0xFFFFFFFF;

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

header secret_t {
    bit<32> hostID;
    bit<32> salt;
    bit<32> pw_hash;
    bit<16> opCode;
    bit<32> mailboxNum;
    bit<32> message;
}

struct metadata {
    /* empty */
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    udp_t        udp;
    secret_t     secret;
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
            TYPE_SECRET: secret;
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

    state secret {
       packet.extract(hdr.secret);
       transition accept;
    }

    state udp {
        packet.extract(hdr.udp);
        //packet.extract(hdr.secret);
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
    
    register<bit<32>>(65536) secret_mailboxes;
    register<bit<32>>(65536) msg_checksums;
    bit<32> hased_pwd;
    bit<32> checksum;
    action drop() {
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward_action(egressSpec_t port) {
        standard_metadata.egress_spec = port;
    }

    action compute_hashes( bit<32> passward){
       hash(hased_pwd, HashAlgorithm.crc32, (bit<32>)0, {passward},MAX_HASHED_VAL);
    }
    action compute_checksum( bit<32> message){
       hash(checksum, HashAlgorithm.crc32, (bit<32>)0, {message}, MAX_HASHED_VAL);
    }
    action check_password(bit<32> stored_password) {
        /* TODO: your code here */
        compute_hashes(stored_password + hdr.secret.salt);
        if (hased_pwd == hdr.secret.pw_hash){
            hdr.secret.opCode = SECRET_OPT.SUCCESS;
        }
        else{
            hdr.secret.opCode = SECRET_OPT.WRONGPW;
        }
    }

    table ipv4_forward {
        key = {
            hdr.ipv4.dstAddr: exact;
        }
        actions = {
            ipv4_forward_action;
            drop;
        }
        default_action = drop();
    }

    table password_check {
        key = {
            hdr.secret.hostID: exact;
        }
        actions = {
            check_password;
            drop;
        }
        default_action = drop();
    }

    apply {
        if(hdr.secret.isValid()) {
            /* TODO: your code here */
            /* Hint 1: verify if the secret message is destined to the switch */

            /* Hint 2: check password before processing the packet */

            /* Hint 3: if the password is correct, continue; if the password is incorrect, what should you reply? */

            /* Hint 4: there are two cases to handle -- DROPOFF, PICKUP */

            /* Hint 5: what happens when you PICKUP from an empty mailbox? */

            /* Hint 6: remember to "sanitize" your mailbox with 0xdeadbeef after every PICKUP */

            /* Hint 7: msg_checksums are important! */

            /* Hint 8: once everything is done, swap addresses, set port and reply to sender */
            if (hdr.ipv4.dstAddr == SWITCH_IP){
                password_check.apply();
                if (hdr.secret.opCode == SECRET_OPT.DROPOFF){
                    compute_checksum(hdr.secret.message);
                    secret_mailboxes.write(hdr.secret.mailboxNum, hdr.secret.message);
                    msg_checksums.write(hdr.secret.mailboxNum, checksum);
                    hdr.secret.opCode = SECRET_OPT.SUCCESS;
                }
                else if (hdr.secret.opCode == SECRET_OPT.PICKUP){
                    bit<32> stored_msg;
                    bit<32> stored_chechsums;
                    secret_mailboxes.read(stored_msg,hdr.secret.mailboxNum);
                    msg_checksums.read(stored_chechsums,hdr.secret.mailboxNum);
                    compute_checksum(stored_msg);
                    if (stored_msg==OV_VAL){
                        hdr.secret.opCode = SECRET_OPT.FAILURE;
                    }
                    else if (stored_chechsums==checksum){
                        hdr.secret.message = stored_msg;
                        hdr.secret.opCode = SECRET_OPT.SUCCESS;
                        secret_mailboxes.write(hdr.secret.mailboxNum, OV_VAL);
                    }
                    else{
                        hdr.secret.opCode = SECRET_OPT.FAILURE;
                    }

                }
                macAddr_t temp = hdr.ethernet.dstAddr;
                hdr.ethernet.dstAddr = hdr.ethernet.srcAddr;
                hdr.ethernet.srcAddr = temp;
                ip4Addr_t tmp = hdr.ipv4.dstAddr;
                hdr.ipv4.dstAddr = hdr.ipv4.srcAddr;
                hdr.ipv4.srcAddr = tmp;
                standard_metadata.egress_spec = standard_metadata.ingress_port;
            }
        }
        ipv4_forward.apply();
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
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
        packet.emit(hdr.udp);
        packet.emit(hdr.secret);
        packet.emit(hdr.ipv4);
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
