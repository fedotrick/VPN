import socket
import struct
import threading
from cryptography.fernet import Fernet
from pyroute2 import IPRoute

class VPNServer:
    def __init__(self, local_addr, local_port, encryption_key):
        # Создаем TUN интерфейс
        self.ip = IPRoute()
        self.tun_name = 'vpn0'
        
        try:
            idx = self.ip.link_create(ifname=self.tun_name, kind='tun')
            self.ip.addr('add', index=idx, address='10.0.0.1', mask=24)
            self.ip.link('set', index=idx, state='up')
        except Exception as e:
            print(f"Failed to create TUN interface: {e}")
            return
        
        # Создаем UDP сокет
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.bind((local_addr, local_port))
        except Exception as e:
            print(f"Failed to create socket: {e}")
            return
        
        # Инициализируем шифрование
        self.cipher = Fernet(encryption_key)
        
        self.clients = {}
        self.lock = threading.Lock()
        
    def handle_tunnel(self):
        while True:
            # Чтение данных из TUN интерфейса
            packet = self.ip.recv(self.tun_name)
            if packet:
                encrypted_packet = self.cipher.encrypt(packet['data'])
                with self.lock:
                    for client_addr in self.clients:
                        self.sock.sendto(encrypted_packet, client_addr)
    
    def handle_socket(self):
        while True:
            data, addr = self.sock.recvfrom(65535)
            with self.lock:
                if addr not in self.clients:
                    self.clients[addr] = True
                    print(f"New client connected: {addr}")
            
            try:
                decrypted_data = self.cipher.decrypt(data)
                self.ip.send(self.tun_name, decrypted_data)
            except Exception as e:
                print(f"Error processing packet from {addr}: {e}")
    
    def run(self):
        tunnel_thread = threading.Thread(target=self.handle_tunnel)
        socket_thread = threading.Thread(target=self.handle_socket)
        
        tunnel_thread.start()
        socket_thread.start()
        
        tunnel_thread.join()
        socket_thread.join()

# Генерация ключа шифрования
key = Fernet.generate_key()
print(f"Encryption key: {key.decode()}")  # Декодируем для удобного отображения

# Запуск сервера
server = VPNServer("0.0.0.0", 5000, key)
server.run()
