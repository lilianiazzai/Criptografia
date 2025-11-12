import socket
import threading
import json
import tkinter as tk
from tkinter import messagebox, Canvas, Scrollbar, Frame
from crypto_hibrido import RSA_Twofish

# ============================
# VARIÁVEIS GLOBAIS
# ============================
chaves_publicas_dos_pares = {}
minhas_chaves = RSA_Twofish()
meu_nome = None
cliente_socket = None
destinatario_atual = None


# ============================
# FUNÇÕES DE REDE
# ============================
def receber_mensagens():
    global chaves_publicas_dos_pares
    buffer = ""
    try:
        while True:
            parte = cliente_socket.recv(4096)
            if not parte:
                print("Desconectado do servidor.")
                break
            buffer += parte.decode('utf-8')
            while "\n" in buffer:
                linha, buffer = buffer.split("\n", 1)
                if not linha.strip():
                    continue
                try:
                    mensagem = json.loads(linha)
                except Exception as e:
                    print(f"Erro ao decodificar JSON recebido: {e}")
                    continue

                tipo_mensagem = mensagem.get('tipo')
                if tipo_mensagem == 'lista_chaves':
                    chaves_publicas_dos_pares = mensagem['chaves']
                    atualizar_lista_contatos()
                else:
                    remetente = mensagem.get('remetente')
                    encrypted_key = bytes.fromhex(mensagem['chave_criptografada_hex'])
                    encrypted_msg = bytes.fromhex(mensagem['mensagem_criptografada_hex'])
                    chave_twofish_descriptografada = minhas_chaves.decrypt_key_with_rsa(encrypted_key)
                    twofish_obj = minhas_chaves.get_twofish(chave_twofish_descriptografada)
                    mensagem_descriptografada = twofish_obj.decrypt(encrypted_msg).decode('utf-8')

                    adicionar_mensagem(remetente, mensagem_descriptografada, tipo="recebida")
    except Exception as e:
        print(f"Erro no recebimento: {e}")
    finally:
        cliente_socket.close()


def enviar_mensagem_gui():
    global destinatario_atual
    texto = campo_mensagem.get("1.0", tk.END).strip()
    if not texto:
        return

    # Envio para TODOS
    if destinatario_atual == "todos":
        try:
            for nome_dest, chave_pub_str in chaves_publicas_dos_pares.items():
                if nome_dest == meu_nome:
                    continue
                chave_pub_dest = minhas_chaves.import_public_key(chave_pub_str.encode('utf-8'))
                chave_twofish = minhas_chaves.generate_twofish_key()
                chave_criptografada = minhas_chaves.encrypt_key_with_rsa(chave_twofish, chave_pub_dest)
                twofish_obj = minhas_chaves.get_twofish(chave_twofish)
                msg_criptografada = twofish_obj.encrypt(texto.encode('utf-8'))

                pacote = {
                    'tipo': 'mensagem',
                    'remetente': meu_nome,
                    'destinatario': nome_dest,
                    'chave_criptografada_hex': chave_criptografada.hex(),
                    'mensagem_criptografada_hex': msg_criptografada.hex()
                }
                cliente_socket.sendall((json.dumps(pacote) + "\n").encode('utf-8'))

            adicionar_mensagem("Você (para todos)", texto, tipo="enviada")
            campo_mensagem.delete("1.0", tk.END)
        except Exception as e:
            messagebox.showerror("Erro", f"Erro ao enviar mensagem em grupo: {e}")
        return

    # Envio individual
    if not destinatario_atual:
        messagebox.showwarning("Aviso", "Selecione um contato primeiro.")
        return

    try:
        chave_pub_str = chaves_publicas_dos_pares[destinatario_atual]
        chave_pub_dest = minhas_chaves.import_public_key(chave_pub_str.encode('utf-8'))

        chave_twofish = minhas_chaves.generate_twofish_key()
        chave_criptografada = minhas_chaves.encrypt_key_with_rsa(chave_twofish, chave_pub_dest)
        twofish_obj = minhas_chaves.get_twofish(chave_twofish)
        msg_criptografada = twofish_obj.encrypt(texto.encode('utf-8'))

        pacote = {
            'tipo': 'mensagem',
            'remetente': meu_nome,
            'destinatario': destinatario_atual,
            'chave_criptografada_hex': chave_criptografada.hex(),
            'mensagem_criptografada_hex': msg_criptografada.hex()
        }
        cliente_socket.sendall((json.dumps(pacote) + "\n").encode('utf-8'))
        adicionar_mensagem("Você", texto, tipo="enviada")
        campo_mensagem.delete("1.0", tk.END)
    except Exception as e:
        messagebox.showerror("Erro", f"Erro ao enviar mensagem: {e}")


# ============================
# FUNÇÕES DE INTERFACE
# ============================
def atualizar_lista_contatos():
    lista_contatos.delete(0, tk.END)
    for nome in chaves_publicas_dos_pares.keys():
        if nome != meu_nome:
            lista_contatos.insert(tk.END, nome)


def ao_selecionar_contato(event):
    global destinatario_atual
    sel = lista_contatos.curselection()
    if not sel:
        return
    destinatario_atual = lista_contatos.get(sel[0])
    label_contato["text"] = f"Conversando com: {destinatario_atual}"


def selecionar_todos():
    global destinatario_atual
    destinatario_atual = "todos"
    label_contato["text"] = "Conversando com: TODOS"


def adicionar_mensagem(remetente, texto, tipo="recebida"):
    frame_msg = Frame(chat_container, bg="#ececec")
    cor = "#dcf8c6" if tipo == "enviada" else "#ffffff"
    lado = "e" if tipo == "recebida" else "w"
    msg = tk.Label(frame_msg, text=f"{remetente}: {texto}", bg=cor,
                   wraplength=350, justify="left", anchor="w", padx=8, pady=5,
                   font=("Arial", 10), relief="solid", bd=1)
    msg.pack(anchor=lado, padx=10, pady=3)
    frame_msg.pack(fill="x", anchor=lado)
    chat_canvas.yview_moveto(1.0)
    chat_container.update_idletasks()
    chat_canvas.configure(scrollregion=chat_canvas.bbox("all"))


def conectar_servidor():
    global cliente_socket, meu_nome, minhas_chaves
    meu_nome = campo_nome.get().strip()
    if not meu_nome:
        messagebox.showwarning("Aviso", "Digite seu nome antes de conectar.")
        return

    try:
        cliente_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        cliente_socket.connect(('127.0.0.1', 9999))
    except Exception as e:
        messagebox.showerror("Erro", f"Não foi possível conectar: {e}")
        return

    dados_iniciais = {
        'nome': meu_nome,
        'chave_publica': minhas_chaves.export_public_key().decode('utf-8')
    }
    cliente_socket.sendall((json.dumps(dados_iniciais) + "\n").encode('utf-8'))

    threading.Thread(target=receber_mensagens, daemon=True).start()
    frame_login.pack_forget()
    frame_chat.pack(fill="both", expand=True)


# ============================
# INTERFACE TKINTER
# ============================
janela = tk.Tk()
janela.title("CryptoChat 💬")
janela.geometry("750x550")
janela.configure(bg="#ececec")

# --- Frame de login ---
frame_login = tk.Frame(janela, bg="#ececec")
tk.Label(frame_login, text="Seu nome:", bg="#ececec", font=("Arial", 12)).pack(pady=10)
campo_nome = tk.Entry(frame_login, font=("Arial", 12))
campo_nome.pack(pady=5)
tk.Button(frame_login, text="Conectar", command=conectar_servidor, font=("Arial", 12),
          bg="#075E54", fg="white", width=15).pack(pady=20)
frame_login.pack(fill="both", expand=True)

# --- Frame principal do chat ---
frame_chat = tk.Frame(janela, bg="#ececec")

# Esquerda: lista de contatos
frame_esquerda = tk.Frame(frame_chat, width=200, bg="#ffffff")
tk.Label(frame_esquerda, text="Contatos", bg="#25D366", fg="white", font=("Arial", 12, "bold")).pack(fill="x")
tk.Button(frame_esquerda, text="Enviar para Todos", bg="#25D366", fg="white",
          command=selecionar_todos).pack(fill="x", pady=3)
lista_contatos = tk.Listbox(frame_esquerda, font=("Arial", 11))
lista_contatos.pack(fill="both", expand=True)
lista_contatos.bind("<<ListboxSelect>>", ao_selecionar_contato)
frame_esquerda.pack(side="left", fill="y")

# Direita: área de chat
frame_direita = tk.Frame(frame_chat, bg="#ececec")
label_contato = tk.Label(frame_direita, text="Selecione um contato", bg="#ececec", font=("Arial", 12, "bold"))
label_contato.pack(pady=5)

# Área de chat com Canvas
chat_canvas = Canvas(frame_direita, bg="#ececec", highlightthickness=0)
scrollbar = Scrollbar(frame_direita, command=chat_canvas.yview)
chat_canvas.configure(yscrollcommand=scrollbar.set)
scrollbar.pack(side="right", fill="y")
chat_canvas.pack(side="left", fill="both", expand=True)
chat_container = Frame(chat_canvas, bg="#ececec")
chat_canvas.create_window((0, 0), window=chat_container, anchor="nw")

# Campo de envio
frame_envio = tk.Frame(frame_direita, bg="#ececec")
campo_mensagem = tk.Text(frame_envio, height=3, font=("Arial", 11))
campo_mensagem.pack(side="left", fill="x", expand=True, padx=5, pady=5)
tk.Button(frame_envio, text="Enviar", bg="#25D366", fg="white", font=("Arial", 11, "bold"),
          command=enviar_mensagem_gui).pack(side="right", padx=5, pady=5)
frame_envio.pack(fill="x")
frame_direita.pack(side="right", fill="both", expand=True)

janela.mainloop()