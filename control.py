import os, sys, shutil, random

from generator import RSAKeyPairGenerator
from rsacrypt import RSACrypt
from lab3 import BlockCipherUtil, StandartEncryptionModes, VigenerCipher

class RSASimulation:
    def __init__(self, pass_filepath, message_filepath):
        if not os.path.exists(os.path.join(os.getcwd(), 'Sender')):
            os.mkdir(os.path.join(os.getcwd(), 'Sender'))
        self.sender_path = os.path.join(os.getcwd(), 'Sender')
        if not os.path.exists(os.path.join(os.getcwd(), 'Recipient')):
            os.mkdir(os.path.join(os.getcwd(), 'Recipient'))
        self.recipient_path = os.path.join(os.getcwd(), 'Recipient')
        shutil.copy(pass_filepath, os.path.join(os.getcwd(), 'Sender'))
        shutil.copy(message_filepath, os.path.join(os.getcwd(), 'Sender'))

        self.block_len = 2

    def step_1(self):
        kpg = RSAKeyPairGenerator()
        open_key, close_key = kpg.generate_keys()
        with open(os.path.join(self.sender_path, 'open_key.txt'), 'w') as f:
            f.write(str(open_key[0])+'\n')
            f.write(str(open_key[1]))
            f.close()
        with open(os.path.join(self.recipient_path, 'close_key.txt'), 'w') as f:
            f.write(str(close_key[0])+'\n')
            f.write(str(close_key[1]))
            f.close()

    def step_2(self, pass_filename):
        passwrd = None
        rsac = RSACrypt()
        with open(os.path.join(self.sender_path, pass_filename), 'r') as f:
            passwrd = map(ord, f.read())
            f.close()
        rsac.read_keys(open_key_filename=os.path.join(self.sender_path, 'open_key.txt'), private_key_filename=None)
        if passwrd and rsac.open_key:
            with open(os.path.join(self.recipient_path, (pass_filename + '.cod')), 'w') as f:
                wr_stream = rsac.encrypt(passwrd)
                for value in wr_stream:
                    f.write(str(value)+'\n')
                f.close()

    def step_3(self, pass_filename):
        passwrd_code = None
        with open(os.path.join(self.recipient_path, (pass_filename + '.cod')), 'r') as f:
            passwrd_code = (int(v) for v in f.readlines())
            f.close()
        rsac = RSACrypt()
        rsac.read_keys(None, os.path.join(self.recipient_path, 'close_key.txt'))
        if passwrd_code and rsac.private_key:
            with open(os.path.join(self.recipient_path, pass_filename), 'w') as f:
                wr_stream = rsac.decrypt(passwrd_code) # probably eval error from int to int
                for value in wr_stream:
                    f.write(chr(value))
                f.close()


    def step_4(self, pass_filename, msg_filename):
        passwrd = None
        with open(os.path.join(self.sender_path, pass_filename), 'r') as f:
            passwrd = f.read()
        vc = VigenerCipher()
        stm = StandartEncryptionModes(key=passwrd, block_len=self.block_len)
        bcu = BlockCipherUtil(input_file=os.path.join(self.sender_path, msg_filename),
                              output_file=os.path.join(self.recipient_path, (msg_filename+'.cod')))
        r_init = random.Random()
        r_init.seed(stm.key)
        init_block = (r_init.randint(1, 256) for _ in range(stm.block_len))
        text = bcu.read_from_file()
        enc_text = stm.cfb_encrypt(text, init_block, vc.encrypt)
        bcu.write_to_file(iter(map(chr, enc_text)), 'w')

    def step_5(self, pass_filename, msg_filename):
        passwrd = None
        with open(os.path.join(self.recipient_path, pass_filename), 'r') as f:
            passwrd = f.read()
        vc = VigenerCipher()
        stm = StandartEncryptionModes(key=passwrd, block_len=self.block_len)
        bcu = BlockCipherUtil(input_file=os.path.join(self.recipient_path, (msg_filename + '.cod')),
                              output_file=os.path.join(self.recipient_path, msg_filename))
        r_init = random.Random()
        r_init.seed(stm.key)
        init_block = (r_init.randint(1, 256) for _ in range(stm.block_len))
        text = bcu.read_from_file()
        text = stm.cfb_decrypt(text, init_block, vc.encrypt)
        bcu.write_to_file(iter(map(chr, text)), 'w')


    def run(self):
        pass_filename = 'password'
        msg_filename = 'LICENSE.md'
        self.step_1()
        self.step_2(pass_filename)
        self.step_3(pass_filename)
        self.step_4(pass_filename, msg_filename)
        self.step_5(pass_filename, msg_filename)


if __name__ == '__main__':
    sim = RSASimulation(os.path.join(os.getcwd(), 'password'), os.path.join(os.getcwd(), 'LICENSE.md'))
    sim.run()
    pass