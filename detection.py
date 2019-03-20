#!/usr/bin/env python
#-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-====-==-==-==-==
#  author: Youndzo Francine && Yimnaing Crescence
#  Objectif: Détecter si un client quelconque se trouve à proximité
#  et Obtenir une liste des SSIDs annoncés par les clients Wifi présents
#  description: Pour aborder le probléme nous avons importé scapy  qui va nous permetre 
#  de sniffer chaque paquet.A chaque fois qu'un parquet sera sniffer nous appellons
#  la fonction qui permet d'etudier le paquet enfin de determiner si le client est à proximité ou pas.
#  le but etant ici d'enregistrer toutes les adresses mac  dans une liste pour pouvoir determiner ainsi le client est à proximité ou pas.
#  A chaque  fois  qu'on sniffe un paquet, on teste si c'est un paquet wifi
#  et si c'est le cas on tester si ce un paquest probe request si oui on extrait l'adresse mac source  on verifie si celle-ci se trouve deja dans la liste des adresses mac deja enregistré puis et on detecte si le client est à proximité en  parcourant la  liste des clients deja enregistré 
#
#-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-====-==-==-==-==
import sys
from scapy.all import *

#interface à sniffer
interface="wlan0"

listClients=[] #liste des clients sniffés
listClientSsid=[] # liste des differents ssid des clients


trameManager = (0,2,4)

def sniffing(packet)
	if len(sys.argv) != 2 #si le user à passer l'argument
		print" missing argument "
		sys.exit(1)
	if packet.haslayer(Dot11): # verifie si c'est un paquet wifi
		if packet.type == 0 and subtype in trameManager:
			if packet.addr2 not in listClients:
				print packet.addr2
				listClients.append(packet.addr2) # ajout du client dans la liste s'il n'est pas present
			if sys.argv[1] in listClients:
				print "client found"
				sys.exit(1)
sniff(iface=interface, prn=sniffing) #sniff du paquet

