from socket import getaddrinfo, inet_aton
from datetime import datetime
from threading import Thread
from time import sleep
import pydivert

hosts = ["www.youtube.com"]
ip = "YOUR_LOCAL_ADDR"
DELAY = 15

def log(out):
    now = datetime.now().strftime("%H:%M:%S")
    print(f"[{now}] {out}")

def getfilter(hosts):
    flt = []
    for host in hosts:
        res = getaddrinfo(host, 443)
        for r in res:
            ip = r[4][0]
            flt.append(f"(ip.SrcAddr == {ip} or ip.DstAddr == {ip})")
    return "tcp and (" + " or ".join(flt) + ")"

def istls(pkt):
    return len(pkt.payload) > 0 and pkt.payload[0] == 0x16 and pkt.payload[5] == 0x02

def intaddr(addr):
	return int.from_bytes(inet_aton(addr), "big")

def keysession(pkt):
	return intaddr(pkt.src_addr) + pkt.tcp.src_port + intaddr(pkt.dst_addr) + pkt.tcp.dst_port

def ack(pkt):
    return pkt.tcp.ack and not pkt.tcp.syn and pkt.src_addr == ip

def synack(pkt):
    return pkt.tcp.syn and pkt.tcp.ack and pkt.src_addr != ip

def issyn(pkt):
	return pkt.tcp.syn and not pkt.tcp.ack and pkt.src_addr == ip

def printpkt(pkt):
	print(f"{pkt.src_addr}:{pkt.tcp.src_port} -> {pkt.dst_addr}:{pkt.tcp.dst_port}, PKT_LEN={pkt.ipv4.packet_len}, IP_FLAGS={pkt.ip.flags}, TCP_FLAGS: SYN={pkt.tcp.syn} ACK={pkt.tcp.ack} RST={pkt.tcp.rst} FIN={pkt.tcp.fin} PSH={pkt.tcp.psh}, SEQ={pkt.tcp.seq_num}, ACK={pkt.tcp.ack_num}")


def sendack(session, w, key):

	sleep(DELAY)
	w.send(session["ackpkt"])
	session["bypass"] = True
	
	log(f"[{key}.thread] delayed ACK sent, if no 'TLS Server Hello' follows,  bypass probably failed")

def sniff(filter):

    sessions = {}
    w = pydivert.WinDivert(filter)
    w.open()

    while True:
        pkt = w.recv()

        #printpkt(pkt)

        if pkt.tcp.rst:
        	continue

        if ack(pkt):

        	key = keysession(pkt)

        	if not sessions[key]["ackpkt"]:

        		sessions[key]["ackpkt"] = pkt
        		th = Thread(target=sendack, args = (sessions[key], w, key)).start()
        		log(f"[{key}.thread] ACK delay thread was created")
        		
        		continue

        	if sessions[key]["ackpkt"] and not sessions[key]["bypass"]:
        		
        		sessions[key]["ackpkt"] = pkt
        		continue

        	#log(f"[{key}] ACK bypassed")

        if synack(pkt):
        	
        	key = keysession(pkt)

        	if key not in sessions:
        		log(f"[{key}] {pkt.src_addr}:{pkt.tcp.src_port} -> {pkt.dst_addr}:{pkt.tcp.dst_port}")
        		sessions[key] = {"bypass": False, "ackpkt": None}

        	elif key in sessions:
        		#log(f"[{key}] 'SA' from {pkt.src_addr}:{pkt.tcp.src_port} dropped")
        		continue

        if istls(pkt):
        	key = keysession(pkt)
        	log(f"[{key}] TLS Server Hello detected, TLS handshake bypassed")

        w.send(pkt)

    w.close()

filter = getfilter(hosts)

try:
	#print(filter)
	sniff(filter)

except KeyboardInterrupt:
    log("byby :*")

except Exception as error:
	log(repr(error))