# I referenced the following web pages while working on my code:
#
# https://docs.python.org/3.6/howto/sockets.html
# https://pythonspot.com/python-network-sockets-programming-tutorial/
# https://pymotw.com/2/select/
# https://pypi.python.org/pypi/pycrypto
# https://www.laurentluce.com/posts/python-and-cryptography-with-pycrypto/
# http://pythonhosted.org/pycrypto/
# stackoverflow.com/questions/14179784/python-encrypting-with-pycrypto-aes

import sys
import socket
import queue
import threading
import select
from Crypto.Hash import SHA
from Crypto.Hash import SHA256
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Hash import HMAC

# This will be launched a separate thread
class getNextMessageToSendThread(threading.Thread):
    def __init__(self, queue):
        threading.Thread.__init__(self)
        self.running = True
        self.queue = queue
    def run(self):
        while self.running:
            self.queue.put(sys.stdin.readline()[:-1])
    def stop(self):
        self.running = False

# This is basically the main thread after
# establishing the connection
def startTalking(sock, confkey, mackey):
  try:
    input = [sock]
    output = [sock]
    messageQueue = queue.Queue()
    thread1 = getNextMessageToSendThread(messageQueue)
    thread1.start()
    while True:
        (readable, writable, exceptional) = select.select(input, output, input)
        for s in readable:
            data = s.recv(100)
            if data:
                while len(data) < 100:
                    data += s.recv(100 - len(data))
                # separately recover each piece of the packet
                initialVector = data[:16]
                ciphertext = data[16:80]
                givenMac = data[80:100]
                # check the MAC and exit if there is a mismatch
                computedMac = HMAC.HMAC(mackey,
                                        initialVector + ciphertext,
                                        SHA).digest()
                if givenMac != computedMac:
                    print('given MAC is ' + str(givenMac))
                    print('cmptd MAC is ' + str(computedMac))
                    print('message not authentic')
                    raise SystemExit
                # decrypt
                obj = AES.new(confkey, AES.MODE_CBC, initialVector)
                plaintext = obj.decrypt(ciphertext)
                # remove padding and decode
                print(plaintext[:-plaintext[-1]].decode())
            else:
                print('the other end closed the connection')
                raise SystemExit
        for s in writable:
            try:
                nextMessage = messageQueue.get(False)
            except queue.Empty:
                continue
            else:
                while len(nextMessage) > 0:
                    if len(nextMessage) > 63:
                        # encode
                        nextBlock = nextMessage[:63].encode('utf-8')
                        nextMessage = nextMessage[63:]
                    else:
                        # encode
                        nextBlock = nextMessage.encode('utf-8')
                        nextMessage = []
                    # pad
                    length = 64 - (len(nextBlock) % 64)
                    nextBlock += bytes([length])*length
                    # encrypt
                    initialVector = Random.new().read(AES.block_size)
                    obj = AES.new(confkey, AES.MODE_CBC, initialVector)
                    nextCiphertext = obj.encrypt(nextBlock)
                    # MAC
                    mac = HMAC.HMAC(mackey,
                                    initialVector + nextCiphertext,
                                    SHA).digest()
                    s.send(initialVector + nextCiphertext + mac)
  except (KeyboardInterrupt, SystemExit):
    print('closing the connection on this end')
    sock.close()
    print('stopping the input thread')
    thread1.stop()
    print('press enter to exit')
    sys.exit(0)

# parse command line options to start-up in server or client mode
if len(sys.argv) == 6 and sys.argv[1] == '-s':
    confkey = SHA256.new(sys.argv[3].encode('utf-8')).digest()
    mackey = SHA256.new(sys.argv[5].encode('utf-8')).digest()
    print('entering server mode')
    serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serversocket.bind(('', 9999))
    serversocket.listen(1)
    print('up and listening on port 9999')
    (clientsocket, address) = serversocket.accept()
    print('accepted client address: ' + str(address))
    clientsocket.setblocking(0)
    startTalking(clientsocket, confkey, mackey)
elif len(sys.argv) == 7 and sys.argv[1] == '-c':
    print('entering client mode')
    print('attempting connection to ' + sys.argv[2])
    serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serversocket.connect((sys.argv[2], 9999))
    print('connected!')
    confkey = SHA256.new(sys.argv[4].encode('utf-8')).digest()
    mackey = SHA256.new(sys.argv[6].encode('utf-8')).digest()
    serversocket.setblocking(0)
    startTalking(serversocket, confkey, mackey)
else:
    print('options are "-s -confkey k1 -authkey k2" for server mode or' +
            ' "-c address -confkey k1 -authkey k2" for client mode')
