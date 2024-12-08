# Робимо імпорт бібліотек
import socket
import os
import json
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography import x509
from cryptography.x509.oid import NameOID

# Зробимо Центр Сертифікації CA
def create_ca_certificate():
    ca_key = ec.generate_private_key(ec.SECP256R1()) # Генеруємо приватний ключ і створюємо загальний сертифікат
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "UA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "My CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, "My Root CA"),
    ]) # далі створюємо сертифікат, який підписує сам себе
    cert = x509.CertificateBuilder().subject_name(subject)\
        .issuer_name(issuer)\
        .public_key(ca_key.public_key())\
        .serial_number(x509.random_serial_number())\
        .not_valid_before(datetime.utcnow())\
        .not_valid_after(datetime.utcnow() + timedelta(days=365))\
        .sign(ca_key, hashes.SHA256())
    return ca_key, cert

def sign_certificate(ca_key, ca_cert, public_key, common_name): # даною функцією створюється сертифікат для клієнта/сервера, які підписуються СА
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "UA"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    cert = x509.CertificateBuilder().subject_name(subject)\
        .issuer_name(ca_cert.subject)\
        .public_key(public_key)\
        .serial_number(x509.random_serial_number())\
        .not_valid_before(datetime.utcnow())\
        .not_valid_after(datetime.utcnow() + timedelta(days=365))\
        .sign(ca_key, hashes.SHA256())
    return cert

#  Робимо можливість збереження та завантаження сертифіката/ключа
def save_key_to_file(key, filename):
    with open(filename, "wb") as f: # таким чином зберігається приватний ключ у файл
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

def save_cert_to_file(cert, filename): # дана функція відповідає за збереження сертифікату у файл
    with open(filename, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

def load_key_from_file(filename): # завантаженя ключу із файла
    with open(filename, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def load_cert_from_file(filename): # завантаження сертифікату із файла
    with open(filename, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())

# Обмін ключами
def ecdhe_key_exchange(private_key, peer_public_key):            # виконується обмін ключами за протоколом ECDHE
    shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"handshake data"
    ).derive(shared_key)
    return derived_key

# Шифрування та дешифрування. Шифрування відбувається за допомогою AES у режимі GCM
def encrypt_message(aes_key, plaintext):
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)
    return nonce, ciphertext

def decrypt_message(aes_key, nonce, ciphertext): # дешифрування повідомлення за допомогою AES у режимі GCM
    aesgcm = AESGCM(aes_key)
    return aesgcm.decrypt(nonce, ciphertext, None).decode()

# Реалізуємо сервер, який виконує автентифікацію, робить захищений канал зв'язку та проводить обмін ключами
def server():
    ca_key, ca_cert = create_ca_certificate()
    save_key_to_file(ca_key, "ca_key.pem")
    save_cert_to_file(ca_cert, "ca_cert.pem")
    
    server_key = ec.generate_private_key(ec.SECP256R1())
    server_cert = sign_certificate(ca_key, ca_cert, server_key.public_key(), "Server")
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("localhost", 65432))
        s.listen()
        print("Сервер підключено, очікуємо підключення клієнта...")
        conn, addr = s.accept()
        with conn:
            print("Встановлено з'єднання з", addr)
            
            # відправлення сертифіката
            conn.sendall(server_cert.public_bytes(serialization.Encoding.PEM))
            
            # отримання сертифіката клієнта
            client_cert_data = conn.recv(4096)
            client_cert = x509.load_pem_x509_certificate(client_cert_data)
            client_public_key = client_cert.public_key()
            
            # ECDHE обмін
            shared_key = ecdhe_key_exchange(server_key, client_public_key)
            print("Встановлено спільний ключ")
            
            # захищений канал
            while True:
                nonce, ciphertext = conn.recv(4096).split(b"||")
                plaintext = decrypt_message(shared_key, nonce, ciphertext)
                print("Отримано:", plaintext)
                if plaintext == "exit":
                    break
                response = f"Echo: {plaintext}"
                nonce, encrypted_response = encrypt_message(shared_key, response)
                conn.sendall(nonce + b"||" + encrypted_response)

# Далі робимо клієнта, який може підключатись до нашого сервера і проводить автентифікацію
def client():
    ca_cert = load_cert_from_file("ca_cert.pem")
    
    client_key = ec.generate_private_key(ec.SECP256R1())
    client_cert = sign_certificate(load_key_from_file("ca_key.pem"), ca_cert, client_key.public_key(), "Client")
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(("localhost", 65432))
        print("Підключено до сервера")
        
        # отримання сертифіката сервера
        server_cert_data = s.recv(4096)
        server_cert = x509.load_pem_x509_certificate(server_cert_data)
        server_public_key = server_cert.public_key()
        
        # відправлення сертифіката клієнта
        s.sendall(client_cert.public_bytes(serialization.Encoding.PEM))
        
        # ECDHE обмін
        shared_key = ecdhe_key_exchange(client_key, server_public_key)
        print("Встановлено спільний ключ")
        
        # захищений канал
        while True:
            message = input("Введіть повідомлення (введіть 'exit' для виходу): ")
            nonce, encrypted_message = encrypt_message(shared_key, message)
            s.sendall(nonce + b"||" + encrypted_message)
            if message == "exit":
                break
            nonce, ciphertext = s.recv(4096).split(b"||")
            response = decrypt_message(shared_key, nonce, ciphertext)
            print("Відповідь сервера:", response)

# запуск самої програми. Потрібно обрати, або війти в режимі сервера або в режимі клієнта
if __name__ == "__main__":
    role = input("Запускаємо що? (server/client): ").strip().lower()
    if role == "server":
        server()
    elif role == "client":
        if not os.path.exists("ca_cert.pem"):
            print("Відсутній сертифікат CA, Спочатку запустіть сервер.")
            exit(1)
        client()
