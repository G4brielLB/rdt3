import socket
import hashlib
import threading
import time

menu = """
1. Iniciar conversa
0. Sair
"""

class Host:
    def __init__(self, router_ip, router_port):
        self.ip = self.get_local_ip()
        self.port = self.get_free_port()
        self.address = (self.ip, self.port)
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(self.address)
        self.router_address = (router_ip, router_port)
        self.sequence_number = 0
        self.last_ack_recv = -1
        self.last_seq_recv = -1
        self.last_message = None
        self.timer = None
        self.timer_lock = threading.Lock()
        self.timeout = 20  # Tempo limite em segundos
        self.max_retries = 4  # Número máximo de reenvios
        self.retry_count = 0  # Contador de reenvios

    def get_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception as e:
            print(f"[ERROR] Não foi possível obter o IP local: {e}")
            return "127.0.0.1"

    def get_free_port(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.bind(("", 0))
            port = s.getsockname()[1]
            s.close()
            return port
        except Exception as e:
            print(f"[ERROR] Não foi possível obter uma porta livre: {e}")
            return 5000

    def calculate_checksum(self, data):
        return hashlib.sha256(data.encode()).hexdigest()

    def start_timer(self):
        """Inicia o temporizador para monitorar o timeout."""
        self.timer_lock.acquire()
        if self.timer and self.timer.is_alive():
            self.timer.cancel()
        self.timer = threading.Timer(self.timeout, self.handle_timeout)
        self.timer.start()
        self.timer_lock.release()

    def stop_timer(self):
        """Para o temporizador."""
        self.timer_lock.acquire()
        if self.timer and self.timer.is_alive():
            self.timer.cancel()
        self.timer_lock.release()

    def handle_timeout(self):
        """Lida com o timeout e reenvia a mensagem."""
        if self.retry_count < self.max_retries:
            print("[TIMEOUT] Tempo limite excedido. Reenviando a última mensagem...")
            self.socket.sendto(self.last_message, self.router_address)
            self.retry_count += 1
            self.start_timer()  # Reinicia o temporizador após o reenvio
        else:
            print("[TIMEOUT] Número máximo de reenvios atingido. Parando o temporizador.")
            self.stop_timer()

    def send_message(self, message, dest_address):
        """Envia uma mensagem ao destinatário."""
        dest_ip, dest_port = dest_address
        checksum = self.calculate_checksum(message)
        is_ack = False
        packet = f"{self.ip}:|:{self.port}:|:{dest_ip}:|:{dest_port}:|:{self.sequence_number}:|:{checksum}:|:{message}:|:{is_ack}".encode()
        self.last_message = packet
        self.retry_count = 0  # Reinicia o contador de reenvios
        try:
            print(f"[ENVIO] Enviando para o roteador {self.router_address} a mensagem: {message} com Seq: {self.sequence_number}")
            self.socket.sendto(packet, self.router_address)
            self.start_timer()  # Inicia o temporizador após o envio
        except Exception as e:
            print(f"[ERROR] Falha ao enviar a mensagem: {e}")

    def listen_message(self):
        """Escuta mensagens recebidas."""
        while True:
            try:
                packet, addr = self.socket.recvfrom(1024)
                #print(f"[RECEPÇÃO] Mensagem recebida de {addr}: {packet.decode()}")
                sender_address = (packet.decode().split(":|:")[0], int(packet.decode().split(":|:")[1]))
                print(f"[RECEPÇÃO] Mensagem recebida de {sender_address}")
                self.process_message(packet.decode(), addr)
            except Exception as e:
                print(f"[ERROR] Falha ao receber a mensagem: {e}")

    def process_message(self, packet, addr):
        """Processa mensagens recebidas."""
        try:
            fields = packet.split(":|:")
            is_ack = fields[7]
            # Host recebendo mensagem
            if is_ack == "False":
                sender_ip, sender_port, dest_ip, dest_port, seq, checksum, message, is_ack = fields
                if (dest_ip, int(dest_port)) != self.address:
                    print("[RECEPÇÃO] Pacote não destinado a este host. Ignorando...")
                    return
                if self.calculate_checksum(message) != checksum:
                    print("[RECEPÇÃO] Checksum inválido. Pacote descartado. Enviando ACK contrário...")
                    #print("[RECEPÇÃO] Esperando o timer estourar para o reenvio do pacote...")
                    checksum_ack = self.calculate_checksum("ACK")
                    ack_packet = f"{self.ip}:|:{self.port}:|:{sender_ip}:|:{sender_port}:|:{1 - int(seq)}:|:{checksum_ack}:|:ACK:|:{True}".encode()
                    self.socket.sendto(ack_packet, addr)
                    return
                if int(seq) == self.last_seq_recv:
                    print("[RECEPÇÃO] Pacote duplicado. Pacote descartado. Reenviando ACK...")
                    checksum_ack = self.calculate_checksum("ACK")
                    ack_packet = f"{self.ip}:|:{self.port}:|:{sender_ip}:|:{sender_port}:|:{seq}:|:{checksum_ack}:|:ACK:|:{True}".encode()
                    self.socket.sendto(ack_packet, addr)
                    return

                print(f"[RECEPÇÃO] Mensagem recebida: {message} (Seq: {seq})")
                self.last_seq_recv = int(seq)
                checksum_ack = self.calculate_checksum("ACK")
                ack_packet = f"{self.ip}:|:{self.port}:|:{sender_ip}:|:{sender_port}:|:{seq}:|:{checksum_ack}:|:ACK:|:{True}".encode()
                try:
                    print(f"[ENVIO] Enviando ACK para {addr}")
                    self.socket.sendto(ack_packet, addr)
                except Exception as e:
                    print(f"[ERROR] Falha ao enviar o ACK: {e}")
            # Host recebendo ACK
            else:
                sender_ip, sender_port, dest_ip, dest_port, seq, checksum_ack, ack, is_ack = fields
                if (dest_ip, int(dest_port)) != self.address:
                    print("[RECEPÇÃO] Pacote não destinado a este host. Ignorando...")
                    return
                if checksum_ack != self.calculate_checksum(ack):
                    print("[RECEPÇÃO] ACK inválido (Corrompido). Ignorando...")
                    return
                if int(seq) != self.sequence_number:
                    print("[RECEPÇÃO] ACK com número de sequência inesperado. Ignorando...")
                    return
                if int(seq) == self.last_ack_recv: 
                    print("[RECEPÇÃO] ACK duplicado. Ignorando...")
                    return

                print(f"[RECEPÇÃO] ACK recebido para o pacote com Seq: {seq}")
                self.last_ack_recv = int(seq)
                self.sequence_number = 1 - self.sequence_number
                self.stop_timer()  # Para o temporizador já que o pacote foi recebido com sucesso

        except Exception as e:
            print(f"[ERROR] Falha ao processar a mensagem: {e}")
    

def main():
    router_ip = input("Digite o IP do roteador: ")
    router_port = int(input("Digite a porta do roteador: "))
    host = Host(router_ip, router_port)
    threading.Thread(target=host.listen_message, daemon=True).start()
    print("Host está pronto!")
    print(f"IP: {host.ip} | Porta: {host.port}")
    print(menu)
    while True:
        option = input("Escolha uma opção: ")
        if option == "1":
            dest_ip = input("Digite o IP do destinatário: ")
            dest_port = int(input("Digite a porta do destinatário: "))
            dest_address = (dest_ip, dest_port)
            while True:
                message = input("Digite a mensagem (ou 'sair' para encerrar): ").strip()
                if message.lower() == "sair":
                    break
                host.send_message(message, dest_address)
        elif option == "0":
            break
        else:
            print("Opção inválida!")


if __name__ == "__main__":
    main()
