import Network_2_1
import argparse
from time import sleep
import hashlib


class Packet:
    # the number of bytes used to store packet length
    seq_num_S_length = 10
    length_S_length = 10
    # length of md5 checksum in hex
    checksum_length = 32

    def __init__(self, seq_num, msg_S):
        self.seq_num = seq_num
        self.msg_S = msg_S

    @classmethod
    def from_byte_S(self, byte_S):
        if Packet.corrupt(byte_S):
            raise RuntimeError('Cannot initialize Packet: byte_S is corrupt')

        # extract the fields
        seq_num = int(
            byte_S[Packet.length_S_length: Packet.length_S_length + Packet.seq_num_S_length])
        msg_S = byte_S[Packet.length_S_length +
                       Packet.seq_num_S_length + Packet.checksum_length:]
        return self(seq_num, msg_S)

    def get_byte_S(self):
        # convert sequence number of a byte field of seq_num_S_length bytes
        seq_num_S = str(self.seq_num).zfill(self.seq_num_S_length)
        # convert length to a byte field of length_S_length bytes
        length_S = str(self.length_S_length + len(seq_num_S) + self.checksum_length + len(self.msg_S)).zfill(
            self.length_S_length)
        # compute the checks0um
        checksum = hashlib.md5(
            (length_S + seq_num_S + self.msg_S).encode('utf-8'))
        checksum_S = checksum.hexdigest()
        # compile into a string
        return length_S + seq_num_S + checksum_S + self.msg_S

    @staticmethod
    def corrupt(byte_S):

        length_S = byte_S[0:Packet.length_S_length]
        seq_num_S = byte_S[Packet.length_S_length:
                           Packet.seq_num_S_length + Packet.seq_num_S_length]
        checksum_S = byte_S[
            Packet.seq_num_S_length + Packet.seq_num_S_length: Packet.seq_num_S_length + Packet.length_S_length + Packet.checksum_length]
        msg_S = byte_S[Packet.seq_num_S_length +
                       Packet.seq_num_S_length + Packet.checksum_length:]

        checksum = hashlib.md5(
            str(length_S + seq_num_S + msg_S).encode('utf-8'))
        computed_checksum_S = checksum.hexdigest()
        return checksum_S != computed_checksum_S

    def send_packet(self, rdt_instance):
        rdt_instance.network.udt_send(self.get_byte_S())

    def is_ack_pack(self):
        if self.msg_S == '1' or self.msg_S == '0':
            return True
        return False


class RDT_2_1:
    seq_num = 0
    byte_buffer = ''
    timeout = 3

    def __init__(self, role_S, server_S, port):
        self.network = Network_2_1.NetworkLayer(role_S, server_S, port)

    def disconnect(self):
        self.network.disconnect()

    def get_response(self):
        response = ''
        while response == '':
            response = self.network.udt_receive()
        return response

    def rdt_1_0_send(self, msg_S):
        p = Packet(self.seq_num, msg_S)
        self.seq_num += 1
        self.network.udt_send(p.get_byte_S())

    def rdt_1_0_receive(self):
        ret_S = None
        byte_S = self.network.udt_receive()
        self.byte_buffer += byte_S
        while True:
            if len(self.byte_buffer) < Packet.length_S_length:
                break 
            length = int(self.byte_buffer[:Packet.length_S_length])
            if len(self.byte_buffer) < length:
                break  
            p = Packet.from_byte_S(self.byte_buffer[0:length])
            ret_S = p.msg_S 
            self.byte_buffer = self.byte_buffer[length:]
            
        return ret_S

    # This one sends using rdt_2_1
    def rdt_2_1_send(self, msg_S):
        p = Packet(self.seq_num, msg_S)
        while True:
            p.send_packet(self)
            response = self.get_response()
            length = int(response[:Packet.length_S_length])
            self.byte_buffer = response[length:]
            if Packet.corrupt(response[:length]) == False:
                response_p = Packet.from_byte_S(response[:length])
                if response_p.seq_num < self.seq_num:
                    print("SENDER: Receiver behind sender")
                    ack = Packet(response_p.seq_num, "1")
                    ack.send_packet(self)
                elif response_p.msg_S is "1":
                    print("SENDER: Received ACK, move on to next.")
                    self.seq_num += 1
                    return
                elif response_p.msg_S is "0":
                    print("SENDER: NAK received")
            else:
                print("SENDER: Corrupted ACK")

    # This one receives using rdt_2_1
    def rdt_2_1_receive(self):
        ret_S = None
        byte_S = self.network.udt_receive()
        self.byte_buffer += byte_S

        while True:
            
            if len(self.byte_buffer) < Packet.length_S_length:
                break 
            length = int(self.byte_buffer[:Packet.length_S_length])
            if len(self.byte_buffer) < length:
                break 

            if Packet.corrupt(self.byte_buffer):
                packet = Packet(self.seq_num, "0")
                print("RECEIVER: Corrupt packet, sending NAK.")
                packet.send_packet(self)
                self.byte_buffer = self.byte_buffer[length:]
            else:
                packet = Packet.from_byte_S(self.byte_buffer[0:length])
                print('RECEIVER: Received new.  Send ACK and increment seq.')
                ack = Packet(self.seq_num, "1")
                ack.send_packet(self)
                self.seq_num += 1
                ret_S = packet.msg_S if (ret_S is None) else ret_S + p.msg_S
                return ret_S


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='RDT implementation.')
    parser.add_argument('role', help='Role is either client or server.', choices=[
                        'client', 'server'])
    parser.add_argument('server', help='Server.')
    parser.add_argument('port', help='Port.', type=int)
    args = parser.parse_args()

    rdt = RDT_2_1(args.role, args.server, args.port)
    if args.role == 'client':
        rdt.rdt_1_0_send('MSG_FROM_CLIENT')
        sleep(2)
        print(rdt.rdt_1_0_receive())
        rdt.disconnect()

    else:
        sleep(1)
        print(rdt.rdt_1_0_receive())
        rdt.rdt_1_0_send('MSG_FROM_SERVER')
        rdt.disconnect()
