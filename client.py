import socket
import threading
from cryptography.fernet import Fernet
from pyroute2 import IPRoute

class VPNClient:
    def __init__(self, server_addr, server_port, encryption_key):
        # Создаем TUN интерфейс
        self.ip = IPRoute()
        self.tun_name = 'vpn_client'
        
        try:
            idx = self.ip.link_create(ifname=self.tun_name, kind='tun')
            self.ip.addr('add', index=idx, address='10.0.0.2', mask=24)
            self.ip.link('set', index=idx, state='up')
        except Exception as e:
            print(f"Failed to create TUN interface: {e}")
            return
        
        # Создаем UDP сокет
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.server_addr = (server_addr, server_port)
        
        # Инициализируем шифрование
        self.cipher = Fernet(encryption_key)
        
    def handle_tunnel(self):
        while True:
            # Читаем данные из TUN интерфейса
            packet = self.ip.recv(self.tun_name)
            if packet:
                # Шифруем пакет
                encrypted_packet = self.cipher.encrypt(packet['data'])
                # Отправляем на сервер
                self.sock.sendto(encrypted_packet, self.server_addr)
    
    def handle_socket(self):
        while True:
            data, addr = self.sock.recvfrom(65535)
            try:
                # Расшифровываем полученные данные
                decrypted_data = self.cipher.decrypt(data)
                # Записываем в TUN интерфейс
                self.ip.send(self.tun_name, decrypted_data)
            except Exception as e:
                print(f"Error processing packet: {e}")
    
    def run(self):
        tunnel_thread = threading.Thread(target=self.handle_tunnel)
        socket_thread = threading.Thread(target=self.handle_socket)
        
        tunnel_thread.start()
        socket_thread.start()
        
        tunnel_thread.join()
        socket_thread.join()

# Используйте тот же ключ, что был сгенерирован на сервере
encryption_key = b'your_encryption_key_here'  # Вставьте ключ, полученный от сервера

# Запуск клиента
client = VPNClient("server_ip_address", 5000, encryption_key)
client.run()
