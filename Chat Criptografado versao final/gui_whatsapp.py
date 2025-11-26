import tkinter as tk
from tkinter import font, simpledialog, messagebox
import socket
import threading
import json
import binascii
import sys
import time
from datetime import datetime

# Importa as classes de criptografia fornecidas
from crypto_hibrido3 import RSA_Twofish

# --- Configurações ---
HOST = '127.0.0.1'
PORT = 9999

# --- Cores do Tema (Estilo WhatsApp Web) ---
COLOR_BG_MAIN = "#ECE5DD"      # Bege claro (fundo do chat)
COLOR_SIDEBAR = "#ffffff"      # Branco (fundo da lista de contatos)
COLOR_HEADER = "#075E54"       # Verde escuro (cabeçalho)
COLOR_ME_BUBBLE = "#DCF8C6"    # Verde claro (minhas mensagens)
COLOR_THEM_BUBBLE = "#FFFFFF"  # Branco (mensagens dos outros)
COLOR_BTN_SEND = "#00887A"     # Botão enviar
COLOR_LOG_BG = "#1e1e1e"       # Fundo do log (estilo terminal)
COLOR_LOG_TXT = "#00ff00"      # Texto do log

class ConsoleRedirector:
    """Redireciona os prints para o widget de log inferior."""
    def __init__(self, text_widget):
        self.text_widget = text_widget

    def write(self, str_text):
        try:
            self.text_widget.configure(state='normal')
            self.text_widget.insert(tk.END, str_text)
            self.text_widget.see(tk.END)
            self.text_widget.configure(state='disabled')
        except:
            pass

    def flush(self):
        pass

class WhatsAppClientGUI:
    def __init__(self, master):
        self.master = master
        self.master.title("Chat Seguro - RSA & Twofish")
        self.master.geometry("1100x750")
        self.master.configure(bg="#dcdcdc")

        # Estado da aplicação
        self.nome_usuario = ""
        self.client_socket = None
        self.rsa_twofish = None
        self.chaves_publicas_pares = {}
        self.running = True
        self.selected_recipient = tk.StringVar(value="todos")

        # Configurar fontes
        self.font_msg = font.Font(family="Helvetica", size=10)
        self.font_name = font.Font(family="Helvetica", size=9, weight="bold")
        self.font_time = font.Font(family="Helvetica", size=8)

        # Inicia Interface e Lógica
        self._setup_ui()
        self._startup_sequence()

    def _setup_ui(self):
        # === CONTAINER PRINCIPAL ===
        main_container = tk.Frame(self.master, bg="#dcdcdc")
        main_container.pack(fill=tk.BOTH, expand=True)

        # === BARRA LATERAL (CONTATOS) ===
        sidebar = tk.Frame(main_container, bg=COLOR_SIDEBAR, width=250)
        sidebar.pack(side=tk.LEFT, fill=tk.Y)
        sidebar.pack_propagate(False) # Força largura fixa

        # Cabeçalho da Sidebar
        sidebar_header = tk.Frame(sidebar, bg=COLOR_HEADER, height=50)
        sidebar_header.pack(fill=tk.X)
        tk.Label(sidebar_header, text="Contatos", bg=COLOR_HEADER, fg="white", font=("Arial", 12, "bold")).pack(pady=10)

        # Lista de Contatos
        self.contact_list = tk.Listbox(sidebar, bg=COLOR_SIDEBAR, bd=0, highlightthickness=0, font=("Arial", 11), selectbackground="#e6e6e6", selectforeground="black")
        self.contact_list.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.contact_list.bind('<<ListboxSelect>>', self._on_user_select)

        # Botão Limpar Logs (na sidebar, parte inferior)
        tk.Button(sidebar, text="Limpar Logs", command=self._clear_logs, bg="#f0f0f0", relief="flat").pack(fill=tk.X, pady=5)

        # === ÁREA DIREITA (CHAT + INPUT + LOGS) ===
        right_area = tk.Frame(main_container, bg=COLOR_BG_MAIN)
        right_area.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        # Cabeçalho do Chat
        self.chat_header = tk.Label(right_area, text="Conversa com: todos", bg="#ededed", fg="#000", font=("Arial", 11), anchor="w", padx=15, height=2)
        self.chat_header.pack(fill=tk.X)

        # --- ÁREA DE SCROLL DE MENSAGENS (O "Canvas" mágico) ---
        self.chat_canvas = tk.Canvas(right_area, bg=COLOR_BG_MAIN, highlightthickness=0)
        self.chat_scrollbar = tk.Scrollbar(right_area, orient="vertical", command=self.chat_canvas.yview)
        
        # Frame interno que vai crescer conforme as mensagens chegam
        self.msg_frame_container = tk.Frame(self.chat_canvas, bg=COLOR_BG_MAIN)

        # Configurações do Scroll
        self.msg_frame_window = self.chat_canvas.create_window((0, 0), window=self.msg_frame_container, anchor="nw")
        
        self.msg_frame_container.bind("<Configure>", lambda e: self.chat_canvas.configure(scrollregion=self.chat_canvas.bbox("all")))
        self.chat_canvas.configure(yscrollcommand=self.chat_scrollbar.set)
        
        # Hack para o frame interno ter a largura do canvas
        self.chat_canvas.bind('<Configure>', self._on_canvas_configure)

        self.chat_canvas.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=0, pady=0)
        self.chat_scrollbar.pack(side=tk.RIGHT, fill=tk.Y, in_=self.chat_canvas)

        # === ÁREA DE INPUT ===
        input_frame = tk.Frame(right_area, bg="#f0f0f0", height=50)
        input_frame.pack(fill=tk.X, side=tk.TOP)

        self.msg_entry = tk.Entry(input_frame, font=("Arial", 12), bd=0, bg="white")
        self.msg_entry.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.msg_entry.bind("<Return>", self.enviar_mensagem)

        btn_send = tk.Button(input_frame, text="➤", font=("Arial", 14), bg=COLOR_BTN_SEND, fg="white", bd=0, command=self.enviar_mensagem, width=4)
        btn_send.pack(side=tk.RIGHT, padx=5, pady=5)

        # === PAINEL DE LOGS (Terminal Hacker) ===
        log_frame = tk.LabelFrame(right_area, text="Log Criptográfico (RSA/Twofish)", bg="#2b2b2b", fg="white", height=150)
        log_frame.pack(side=tk.BOTTOM, fill=tk.X)
        log_frame.pack_propagate(False) # Força altura fixa

        self.log_display = tk.Text(log_frame, bg=COLOR_LOG_BG, fg=COLOR_LOG_TXT, font=("Consolas", 8), state='disabled', padx=5, pady=5)
        self.log_display.pack(fill=tk.BOTH, expand=True)

        # Redirecionar prints
        sys.stdout = ConsoleRedirector(self.log_display)

    def _on_canvas_configure(self, event):
        """Garante que as mensagens ocupem a largura correta."""
        self.chat_canvas.itemconfig(self.msg_frame_window, width=event.width)

    def _add_message_bubble(self, sender, text, is_me, status=""):
        """Cria o visual da bolha de mensagem."""
        
        # Frame wrapper para a linha (para alinhar à esquerda ou direita)
        wrapper_frame = tk.Frame(self.msg_frame_container, bg=COLOR_BG_MAIN)
        wrapper_frame.pack(fill=tk.X, pady=5, padx=10)

        # Cor e alinhamento
        bg_color = COLOR_ME_BUBBLE if is_me else COLOR_THEM_BUBBLE
        align = tk.RIGHT if is_me else tk.LEFT
        anchor_txt = "e" if is_me else "w"

        # Bolha (Frame com borda arredondada 'fake' via padding)
        bubble = tk.Frame(wrapper_frame, bg=bg_color, bd=1, relief="solid")
        bubble.configure(highlightbackground="#ccc", highlightthickness=0)
        bubble.pack(side=align, anchor=anchor_txt, ipadx=5, ipady=2)

        # Nome do remetente (se não for eu)
        if not is_me:
            tk.Label(bubble, text=sender, font=self.font_name, bg=bg_color, fg="#e542a3").pack(anchor="w", padx=5, pady=(2,0))

        # Texto da mensagem
        msg_label = tk.Label(bubble, text=text, font=self.font_msg, bg=bg_color, wraplength=400, justify="left")
        msg_label.pack(padx=8, pady=(2, 2))

        # Rodapé da bolha (Hora + Status)
        time_str = datetime.now().strftime("%H:%M")
        footer_txt = f"{time_str}  {status}"
        tk.Label(bubble, text=footer_txt, font=self.font_time, bg=bg_color, fg="gray").pack(anchor="e", padx=5, pady=(0,2))

        # Auto-scroll para o final
        self.master.update_idletasks()
        self.chat_canvas.yview_moveto(1.0)

    # --- LÓGICA DO SISTEMA (IGUAL AO ANTERIOR, ADAPTADA PARA NOVA GUI) ---
    def _startup_sequence(self):
        self.nome_usuario = simpledialog.askstring("Login", "Seu Nome de Usuário:")
        if not self.nome_usuario:
            self.master.destroy()
            return
        
        threading.Thread(target=self._init_crypto_and_connect, daemon=True).start()

    def _init_crypto_and_connect(self):
        try:
            print("--- GERANDO CHAVES RSA (Pode demorar um pouco) ---")
            self.rsa_twofish = RSA_Twofish(verbose=True)
            self._connect_to_server()
        except Exception as e:
            messagebox.showerror("Erro", str(e))

    def _connect_to_server(self):
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((HOST, PORT))
            
            dados = {'nome': self.nome_usuario, 'chave_publica': self.rsa_twofish.export_public_key()}
            self.client_socket.sendall((json.dumps(dados) + "\n").encode('utf-8'))
            
            threading.Thread(target=self._receive_loop, daemon=True).start()
        except Exception as e:
            print(f"[ERRO] Falha na conexão: {e}")

    def _receive_loop(self):
        buffer = ""
        while self.running:
            try:
                parte = self.client_socket.recv(4096)
                if not parte: break
                buffer += parte.decode('utf-8')
                while "\n" in buffer:
                    linha, buffer = buffer.split("\n", 1)
                    if linha.strip():
                        try:
                            self._process_packet(json.loads(linha))
                        except: pass
            except: break

    def _process_packet(self, pacote):
        tipo = pacote.get('tipo')
        if tipo == 'lista_chaves':
            self.chaves_publicas_pares = pacote['chaves']
            self.master.after(0, self._update_contact_list)
        
        elif tipo == 'mensagem':
            self._handle_incoming_message(pacote)

    def _handle_incoming_message(self, pacote):
        remetente = pacote['remetente']
        print(f"\n[ENVELOPE DIGITAL] Recebido de {remetente}")

        try:
            # 1. Decifrar chave Sessão
            chave_twofish = self.rsa_twofish.decrypt_key_with_rsa(pacote['chave_sessao'])
            # 2. Decifrar Mensagem
            twofish = self.rsa_twofish.get_twofish(chave_twofish)
            msg_bytes = binascii.unhexlify(pacote['conteudo'])
            texto = twofish.decrypt(msg_bytes).decode('utf-8')
            
            # 3. Validar Assinatura
            assinatura = pacote['assinatura']
            valido = False
            if remetente in self.chaves_publicas_pares:
                pub = self.rsa_twofish.import_public_key(self.chaves_publicas_pares[remetente])
                valido = self.rsa_twofish.verify_signature(texto.encode('utf-8'), assinatura, pub)
            
            status = "✔ Assinado" if valido else "⚠ Alerta"
            
            # Atualizar GUI
            self.master.after(0, lambda: self._add_message_bubble(remetente, texto, False, status))
            
        except Exception as e:
            print(f"[ERRO DECRIPTO] {e}")

    def enviar_mensagem(self, event=None):
        texto = self.msg_entry.get().strip()
        dest = self.selected_recipient.get()
        if not texto: return

        self.msg_entry.delete(0, tk.END)
        self._add_message_bubble("Eu", texto, True, "⏳ Enviando...")
        
        threading.Thread(target=self._send_logic, args=(texto, dest)).start()

    def _send_logic(self, texto, destinatario):
        print(f"\n--- ENVIANDO PARA {destinatario} ---")
        assinatura = self.rsa_twofish.sign_message(texto.encode('utf-8'))
        
        targets = [t for t in self.chaves_publicas_pares if t != self.nome_usuario] if destinatario == 'todos' else [destinatario]
        
        for nome_dest in targets:
            try:
                pub_key_dest = self.rsa_twofish.import_public_key(self.chaves_publicas_pares[nome_dest])
                chave_twofish = self.rsa_twofish.generate_twofish_key()
                chave_sessao_cifrada = self.rsa_twofish.encrypt_key_with_rsa(chave_twofish, pub_key_dest)
                
                twofish = self.rsa_twofish.get_twofish(chave_twofish)
                msg_cifrada = binascii.hexlify(twofish.encrypt(texto.encode('utf-8'))).decode('utf-8')

                pacote = {
                    'tipo': 'mensagem', 'remetente': self.nome_usuario, 'destinatario': nome_dest,
                    'conteudo': msg_cifrada, 'chave_sessao': chave_sessao_cifrada, 'assinatura': assinatura
                }
                self.client_socket.sendall((json.dumps(pacote) + "\n").encode('utf-8'))
                print(f"[OK] Enviado para {nome_dest}")
            except Exception as e:
                print(f"[ERRO] {e}")

    def _update_contact_list(self):
        self.contact_list.delete(0, tk.END)
        self.contact_list.insert(tk.END, "todos")
        for u in self.chaves_publicas_pares:
            if u != self.nome_usuario:
                self.contact_list.insert(tk.END, u)

    def _on_user_select(self, event):
        sel = self.contact_list.curselection()
        if sel:
            user = self.contact_list.get(sel[0])
            self.selected_recipient.set(user)
            self.chat_header.config(text=f"Conversa com: {user}")

    def _clear_logs(self):
        self.log_display.configure(state='normal')
        self.log_display.delete('1.0', tk.END)
        self.log_display.configure(state='disabled')

if __name__ == "__main__":
    root = tk.Tk()
    app = WhatsAppClientGUI(root)
    root.mainloop()