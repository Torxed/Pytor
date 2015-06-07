import urllib.parse, traceback, pymongo
import ipaddress, struct
from socket import *
from base64 import b64decode as bdec
from base64 import b64encode as benc
#from ssl import *
from select import epoll, EPOLLIN, EPOLLOUT, EPOLLHUP
from random import randint, shuffle

## Following the standard from: http://www.bittorrent.org/beps/bep_0015.html

coreSock = socket(AF_INET, SOCK_DGRAM)
coreSock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
coreSock.bind(('0.0.0.0', 8080))
coreSock.setblocking(0)

dbConnection = pymongo.MongoClient()
#dbConnection.drop_database('Pytor') ## < DEBUG !
database = dbConnection.Pytor
table = database.torrents

poll = epoll()
poll.register(coreSock.fileno(), EPOLLIN)
clients = {}
connections = {}

def bit64(b):
	return struct.unpack('>Q', b)[0]
def bit32(b):
	return struct.unpack('>I', b)[0]
def bit16(b):
	return struct.unpack('>H', b)[0]
def pbit64(i):
	return struct.pack('>Q', i)
def pbit32(i):
	return struct.pack('>I', i)
def pbit16(i):
	return struct.pack('>H', i)

while True:
	events = poll.poll(1)
	for fileno, event in events:

		if event & EPOLLIN:
			data, address = coreSock.recvfrom(1024)

			print(address)
			#print('Raw:',data)

			connection_id = bit64(data[0:8])
			action = bit32(data[8:12])
			transaction_id = bit32(data[12:16])

			if not address[0]+':'+str(address[1]) in connections:
				new_connection_id = randint(0, 18446744073709551615)
				connections[address[0]+':'+str(address[1])] = new_connection_id

				response = pbit32(0) + pbit32(transaction_id) + pbit64(new_connection_id)
				coreSock.sendto(response, (address[0], address[1]))
				
				continue
			elif connections[address[0]+':'+str(address[1])] != connection_id:
				print(connections)
				print(connection_id)
				print(transaction_id)

				response = pbit32(3) + pbit32(transaction_id) + struct.pack('>p', "Can not bypass connection request.")
				coreSock.sendto(response, (address[0], address[1]))
				raise KeyError('Client tried to bypass connection sync')

			elif action == 1:
				print('Got a announce request:')

				info_hash = benc(data[16:36])
				peer_id = benc(data[36:56])
				downloaded = bit64(data[56:56+8])
				left = bit64(data[64:64+8])
				uploaded = bit64(data[72:72+8])
				event = bit32(data[80:80+4]) # 0: none; 1: completed; 2: started; 3: stopped
				announceip = bit32(data[84:84+4]) # 0 == default
				key = bit32(data[88:88+4])
				num_want = bit32(data[92:92+4])
				port = num_want = bit16(data[96:96+2]) # -1 == default

				print('  Downloaded:',downloaded)
				print('  left:',left)
				print('  key:',key)

				if 0 < num_want < 500:
					num_want = 500

				print('  Hash:',info_hash)
				torrent = table.find_one({"id": info_hash})
				interval = 60

				if torrent:
					seeders = torrent['users']['seeders']
					leechers = torrent['users']['leechers']
					if left <= 0:
						table.update({"id": info_hash}, {"$set": {"users.seeders.U" + str(int(ipaddress.ip_address(address[0]))) : port}})
						table.update({"id": info_hash}, {"$unset": {"users.leechers.U" + str(int(ipaddress.ip_address(address[0]))) : 1}})

					else:
						table.update({"id": info_hash}, {"$set": {"users.leechers.U" + str(int(ipaddress.ip_address(address[0]))) : port}})
						table.update({"id": info_hash}, {"$unset": {"users.seeders.U" + str(int(ipaddress.ip_address(address[0]))) : 1}})

					print(' !!Found:')
					print('  Seeders:',len(seeders))
					print('  Leechers:',len(leechers))

					response = pbit32(1) + pbit32(transaction_id) + pbit32(interval) + pbit32(len(seeders)) + pbit32(len(leechers))
					for leecher in leechers:
						response += pbit32(int(leecher[1:])) + pbit16(leechers[leecher])
					for seeder in seeders:
						response += pbit32(int(seeder[1:])) + pbit16(seeders[seeder])
				else:
					table.insert_one({"id": info_hash, "users" : {'seeders' : {}, 'completed' : {}, 'leechers' : {}}})
					response = pbit32(1) + pbit32(transaction_id) + pbit32(interval) + pbit32(0) + pbit32(0)

				print('<<', response)
				coreSock.sendto(response, (address[0], address[1]))

			elif action == 2:
				print('Got a scrape request')
				for n in range(16,len(data[16:]), 16+20):
					info_hash = benc(data[n:n+20])
					print([info_hash])

					torrent = table.find_one({"id": info_hash})
					if not torrent:
						table.insert_one({"id": info_hash, "users" : {'seeders' : {}, 'completed' : {}, 'leechers' : {}}}) #"U"+str(int(client)) : headers['RequestURI']['port']}})
						seeders, completed, leechers = 0,0,0
					else:
						seeders = len(torrent['users']['seeders'])
						completed = len(torrent['users']['seeders'])
						leechers = len(torrent['users']['seeders'])

					response = pbit32(2) + pbit32(transaction_id) + pbit32(seeders) + pbit32(completed) + pbit32(leechers)
					coreSock.sendto(response, (address[0], address[1]))
			else:
				response = pbit32(3) + pbit32(transaction_id) + struct.pack('>p', "Can not bypass connection request.")
				coreSock.sendto(response, (address[0], address[1]))
				print('Unknown action:',action,'with a packet length of:',len(data))

poll.unregister(coreSock.fileno())
poll.close()
coreSock.close()