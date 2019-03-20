#!/usr/bin/env python
#-*- coding: utf-8 -*-

#-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
#  author: youndzo francine && yimnaing Kamdem
#  Objectif: Détecter si un certains client se trouve à proximité
#            Obtenir une liste des SSIDs annoncés par les clients Wifi présents ainsi que le nom 
# du constructeur de la carte wifi#  description: Pour aborder le problème nous avons importé scapy
#  qui va nous permetre de sniffer chaque paquet et l'api
# http://api.macvendors.com/ pour determiner le nom du constructeur de la carte
# Nous avons aussi utilisé un dictionnaire de python pour le stockage de chaque client avec sa 
#liste des ssid. (adresse mac : ssid).Fonctionnement: A chaque fois que l'on reçoit le paquet on  
#le met dans  le dictionaire comme clé. Si l'adresse mac ne se trouvais  pas deja dans le dictionnaire. 
#à partir de l'adress mac on stock ces SSID et  on pourra recupérer la liste de ces derniers à partir de
# son adresse mac. On affiche cependant les resultats pédiodiquement. 
#-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==





from scapy.all import *
import requests
import threading


interface = "wlan0mon"

dictionary= dict()
vendor=""

trameManager = (0, 2, 4)

#-=======-===========-=================-============-==========-=============
# cette fonction permet pour chaque paquet sniffer  determiner les adresse source 
# mac et les ssid des  clients  et enfin le nom du constructeur
# Elle prends en paramètre le packet sniffer.
#-=======-===========-=================-============-==========-=============



def sniffing(packetToSniff):
      if packetToSniff.haslayer(Dot11):
        ssidtab = []
        if packetToSniff.type == 0 and packetToSniff.subtype in trameManager:
# on enregistre  l'adresse mac source si elle n'est pas encore present dans la liste
# Pour chaque cle inséré dans le dictionnaire alloue une liste devant contenir la liste des ssid           
           if packetToSniff.addr2 not in dictionary.keys():
              dictionary[packetToSniff.addr2] = ssidtab
           if packetToSniff.info not in dictionary[packetToSniff.addr2]:
# Ce test permet de filtre les ssid vide  et de stocker uniquement que ceux qui ne sont pas vide 
              if packetToSniff.info:
                dictionary[packetToSniff.addr2].append(packetToSniff.info)



#-=======-===========-=================-============-==========-=============
# cette fonction permet d'afficher pour chaque client son adresse mac et ces 
# ssid et le nom de constructeur de sa carte  wifi
#-=======-===========-=================-============-==========-=============




def display():

     for key, value in dictionary.items():

         ssd= ""

# pour chaque adresse mac on trouve son constructeur en utilisant api macvendors
         vendor = requests.get('http://api.macvendors.com/' + key).text
         for i in value:
          ssd += " ," + " "  + str(i.strip("[] ' "))  
         print("{} ({}) - {}.".format(key,vendor.strip('\n \t '), ssd.lstrip("  , ")))
     print('=====================================================')


# execute la fonction affichage périodiquement sniffing 
     threading.Timer(5, display).start() 




#-=======-===========-=================-============-==========-=============
# appelle de la fonction affichage et sniff qui à chaque fois qui a capture le
# le paquet doit appelle la fonction p
#-=======-===========-=================-============-==========-=============
display()
sniff(iface=interface, prn=sniffing)
