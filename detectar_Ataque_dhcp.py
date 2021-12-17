from scapy.all import *
from Tkinter import *
import sys


count = 0

def sniffer(interface):
	sniff(iface = interface, store = False, prn = process_sniffed_packed)
	#prn -> funcion que se aplica en cada paquete
	
	
def warning_ads(): 
	raiz = Tk()
	mi_Frame = Frame()
	mi_Frame.pack()
	mi_Label = Label(mi_Frame, text="Estas siendo atacado por INUNDACION DE DHCP") #Creacion del Label
	mi_Label.pack()
	mi_Label.config(bg="white") #Cambiar color de fondo
	mi_Label.config(font=('Arial',30 )) #Cambiar tipo y tamano de fuente
	mi_Label.config(fg="red") #Cambiar color del texto
	mi_Label.config(padx=20, pady=20) #Agregar margen de relleno
	raiz.mainloop()
	
def get_mac(ip):
	try:
		arp_request = ARP(pdst=ip)# solicitud de MAC, dada la IP, request (op=1)
		broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
		arp_request_broadcast = broadcast/arp_request
		reply_list = srp(arp_request_broadcast, timeout=1, verbose = False)[0]#retorna la MAC e IP
		#srp: Send and receive packets at layer 2
		#print(reply_list[0][1].hwsrc)
		return reply_list[0][1].hwsrc #obtenemos la MAC de la IP
	except:
		return False
	
def process_sniffed_packed(packet):
	global count
	if packet.haslayer(DHCP) and packet[DHCP].options[2][0] == 'requested_addr': #and packet[DHCP].options == 'BOOTREQUEST'
		#print("paquete DHCP 1 *************************************")
		#packet.show2()		
		#print("paquete DHCP 2 **************************************")
		#packet.show()
		#print("paquete DHCP 3 ************************************")
		#packet.summary()
		b =packet[DHCP].options[2]
		#print('esto es B', b)
		#print(type(b))
		if b[0] == 'requested_addr':
			#print('soy un requested')
			IP_spoof = b[1] 
			#print(IP_spoof)
			#print(type(IP_spoof))
			mac_spoof = get_mac(IP_spoof)
			#print('Mac SPOOF', mac_spoof)
			if mac_spoof == False:				
				count  = count + 1
				if count == 5:
					print('[+] ESTAS SIENDO ATACADO POR INUNDACION DE DHCP')
					warning_ads()
					sys.exit()
			
		print(packet[DHCP].options[2])
		
print("[+] MONITOREANDO INUNDACION POR DHCP ******")	
sniffer('eth0')
