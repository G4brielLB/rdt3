import socket
import threading
import queue

class Router:
    def __init__(self):
        self.ip = self.get_local_ip()
        self.port = 5000
        self.address = (self.ip, self.port)
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(self.address)

        self.message_queue = queue.Queue()  # Fila para pacotes
        self.user_interacting = threading.Event()  # Controla interação do usuário

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

    def listen(self):
        """Recebe pacotes e os coloca na fila."""
        print(f"[ROTEADOR] Escutando em {self.address}")
        while True:
            packet, addr = self.socket.recvfrom(1024)
            self.message_queue.put((packet, addr))

    def process_messages(self):
        """Processa pacotes na fila e aguarda decisão do usuário."""
        while True:
            if not self.user_interacting.is_set() and not self.message_queue.empty():
                # Pegar o próximo pacote da fila
                packet, addr = self.message_queue.get()
                #print(f"[ROTEADOR] Pacote recebido de {addr}: {packet.decode()}")
                
                # Solicitar ação do usuário
                self.user_interacting.set()  # Bloquear outros pacotes
                action = self.get_user_choice(packet)
                self.user_interacting.clear()  # Liberar para próximo pacote
                
                # Realizar a ação escolhida
                self.apply_action(action, packet, addr)

    def get_user_choice(self, packet):
        """Exibe opções ao usuário e retorna a escolha."""
        while True:
            print("[ROTEADOR] Escolha uma opção:")
            print("1. Repassar")
            print("2. Descartar")
            print("3. Corromper")
            print(f"[ROTEADOR] Pacote: {packet.decode()}")
            choice = input("[ROTEADOR] Sua escolha: ").strip()
            if choice in {"1", "2", "3"}:
                return choice
            print("[ROTEADOR] Opção inválida. Tente novamente.")

    def apply_action(self, action, packet, addr):
        """Aplica a ação escolhida pelo usuário."""
        fields = packet.decode().split(":|:")
        is_ack = fields[7]
        if is_ack == "False": 
            if action == "1":  # Repassar
                dest_ip, dest_port = fields[2], int(fields[3])
                dest_address = (dest_ip, dest_port)
                self.socket.sendto(packet, dest_address)
                print(f"[ROTEADOR] Pacote repassado para {dest_address}")
            elif action == "2":  # Descartar
                print("[ROTEADOR] Pacote descartado!")
            elif action == "3":  # Corromper
                corrupted_message = fields[6][::-1]
                corrupted_packet = f"{fields[0]}:|:{fields[1]}:|:{fields[2]}:|:{fields[3]}:|:{fields[4]}:|:{fields[5]}:|:{corrupted_message}:|:{fields[7]}".encode()
                dest_ip, dest_port = fields[2], int(fields[3])
                dest_address = (dest_ip, dest_port)
                self.socket.sendto(corrupted_packet, dest_address)
                print(f"[ROTEADOR] Pacote corrompido e enviado para {dest_address}")
        else: # ACK
            if action == "1":
                dest_ip, dest_port = fields[2], int(fields[3])
                dest_address = (dest_ip, dest_port)
                self.socket.sendto(packet, dest_address)
                print(f"[ROTEADOR] ACK repassado para {dest_address}")
            elif action == "2":
                print("[ROTEADOR] ACK descartado!")
            elif action == "3":
                corrupted_message = fields[6][::-1]
                corrupted_packet = f"{fields[0]}:|:{fields[1]}:|:{fields[2]}:|:{fields[3]}:|:{fields[4]}:|:{fields[5]}:|:{corrupted_message}:|:{fields[7]}".encode()
                dest_ip, dest_port = fields[2], int(fields[3])
                dest_address = (dest_ip, dest_port)
                self.socket.sendto(corrupted_packet, dest_address)
                print(f"[ROTEADOR] ACK corrompido e enviado para {dest_address}")

    def start(self):
        """Inicia threads para escutar e processar mensagens."""
        threading.Thread(target=self.listen, daemon=True).start()
        threading.Thread(target=self.process_messages, daemon=True).start()
        print("[ROTEADOR] Inicializado e rodando...")

def main():
    router = Router()
    router.start()
    print("[ROTEADOR] Pressione Ctrl+C para sair.")
    try:
        while True:
            pass  # Mantém o programa rodando
    except KeyboardInterrupt:
        print("\n[ROTEADOR] Encerrando...")
    except Exception as e:
            print(f"\n[ROTEADOR] Encerrando devido a um erro: {e}")
    finally:
            print("[ROTEADOR] Recursos liberados. Saindo do programa.")


if __name__ == "__main__":
    main()
