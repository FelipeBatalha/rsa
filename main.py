import base64
import json
from oaep import *
from rsa import *
import sys

def generate_key_files():

    public_key, private_key = generate_keys()

    public_key = base64.b64encode(json.dumps(public_key).encode('utf-8')).decode('utf-8')
    private_key= base64.b64encode(json.dumps(private_key).encode('utf-8')).decode('utf-8')
    
    with open('public_key.pub', 'w') as public_file:
        public_file.write(public_key)

    with open('private_key', 'w') as private_file:
        private_file.write(private_key)


def get_key(key_file):

    with open(key_file, 'r') as public_file:
        encoded_public_key = public_file.read()

    decoded_key = json.loads(base64.b64decode(key_file.encode('utf-8')).decode('utf-8'))

    return tuple(decoded_key)

if __name__ == "__main__":

    if len(sys.argv) != 3:
        print("Uso: \nPara cifrar: python3 main.py cifrar arquivo_de_entrada nome_arquivo_cifrado \
            Para decifrar: python3 main.py decifrar arquivo_cifrado arquivo_de_saida")
        sys.exit(1)
    choice = sys.argv[1]
    input_file = sys.argv[2]
    output_file = sys.argv[2]

    while True:

        msg = 'apenas uma mensagem de teste'

        if choice == "cifrar":
            print("Gerando novas chaves..")
            generate_key_files()
            public_key = get_key('public_key.pub')
            with open(input_file, 'rb') as file_in, open(output_file, 'wb') as file_out:
                data = file_in.read()
                encrypted_file = oaep_encrypt(data, public_key)
                file_out.write(oaep_encrypt)

            print("Concluído")
        elif choice == "decifrar":
            private_key = get_key('private_key')
            with open(input_file, 'rb') as file_in, open(output_file, 'wb') as file_out:
                data = file_in.read()
                decrypted_file = oaep_decrypt(data, private_key)
                file_out.write(decrypted_file)
        else:
            print("Escolha inválida. Digite cifrar ou decifrar, mais o nome dos arquivos de entrada e saida")
            break
        print("Operação concluída.")
        break