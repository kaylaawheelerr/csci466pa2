import Network_2_1
import argparse
from time import sleep
import hashlib

ACK = "1"
NAK = "0"
WAITING_FOR_RESPONSE = ''

class Packet:
    # the number of bytes used to store packet length
    seq_num_S_length = 10
    length_S_length = 10
    # length of md5 checksum in hex
    checksum_length = 32

    def __init__(self, seq_num, message_string):
        self.seq_num = seq_num
        self.message_string = message_string

    @classmethod
    def from_byte_string(self, byte_S):
        if Packet.corrupt(byte_S):
            raise RuntimeError('Cannot initialize Packet: byte_S is corrupt')

        # extract the fields
        seq_num = int(
            byte_S[Packet.length_S_length: Packet.length_S_length + Packet.seq_num_S_length])
        message_string = byte_S[Packet.length_S_length +
                       Packet.seq_num_S_length + Packet.checksum_length:]
        return self(seq_num, message_string)

    def get_byte_string(self):
        # convert sequence number of a byte field of seq_num_S_length bytes
        seq_num_S = str(self.seq_num).zfill(self.seq_num_S_length)
        # convert length to a byte field of length_S_length bytes
        length_S = str(self.length_S_length + len(seq_num_S) + self.checksum_length + len(self.message_string)).zfill(
            self.length_S_length)
        # compute the checks0um
        checksum = hashlib.md5(
            (length_S + seq_num_S + self.message_string).encode('utf-8'))
        checksum_S = checksum.hexdigest()
        # compile into a string
        return length_S + seq_num_S + checksum_S + self.message_string

    @staticmethod
    def corrupt(byte_S):
        # extract the fields
        length_S = byte_S[0:Packet.length_S_length]
        seq_num_S = byte_S[Packet.length_S_length:
                           Packet.seq_num_S_length + Packet.seq_num_S_length]
        checksum_S = byte_S[
            Packet.seq_num_S_length + Packet.seq_num_S_length: Packet.seq_num_S_length + Packet.length_S_length + Packet.checksum_length]
        message_string = byte_S[Packet.seq_num_S_length +
                       Packet.seq_num_S_length + Packet.checksum_length:]

        # compute the checksum locally
        checksum = hashlib.md5(
            str(length_S + seq_num_S + message_string).encode('utf-8'))
        computed_checksum_S = checksum.hexdigest()
        # and check if the same
        return checksum_S != computed_checksum_S


class RDT_2_1:
    ## latest sequence number used in a packet
    seq_num = 1
    ## buffer of bytes read from network
    byte_buffer = WAITING_FOR_RESPONSE

    def __init__(self, role_S, server_S, port):
        self.network = Network_2_1.NetworkLayer(role_S, server_S, port)

    def same_sequence(self, current_sequence):
        if self.seq_num == current_sequence:
            return True
        return False

    def no_response(self, response):
        if response == WAITING_FOR_RESPONSE:
            return True
        return False

    def disconnect(self):
        self.network.disconnect()

    def rdt_2_1_send(self, message_string):
        packet = Packet(self.seq_num, message_string)
        current_seq = self.seq_num

        while self.same_sequence(current_seq):
            self.network.udt_send(packet.get_byte_string())
            response = WAITING_FOR_RESPONSE

            while self.no_response(response):
                response = self.network.udt_receive()
            message_length = int(response[:Packet.length_S_length])
            self.byte_buffer = response[message_length:]
            self.precheck_packet = response[:message_length]
            if not Packet.corrupt(self.precheck_packet):
                response_packet = Packet.from_byte_string(self.precheck_packet)
                if response_packet.seq_num < self.seq_num:
                    print("SENDER: Receiver behind sender")
                    self.network.udt_send(Packet(response_packet.seq_num, ACK).get_byte_string())
                elif response_packet.message_string is ACK:
                    print("SENDER: Received ACK, move on to next.")
                    self.seq_num += 1
                elif response_packet.message_string is NAK:
                    print("SENDER: NAK received")
                    self.byte_buffer = WAITING_FOR_RESPONSE
            else:
                print("SENDER: Corrupted ACK")
                self.byte_buffer = WAITING_FOR_RESPONSE

    def rdt_2_1_receive(self):
        return_string = None
        byte_S = self.network.udt_receive()
        self.byte_buffer += byte_S
        current_seq = self.seq_num
        # Don't move on until seq_num has been toggled
        # keep extracting packets - if reordered, could get more than one
        while self.same_sequence(current_seq):
            byte_buffer_size = len(self.byte_buffer)
            # check if we have received enough bytes
            if byte_buffer_size < Packet.length_S_length:
                break  # not enough bytes to read packet length
            # extract length of packet
            length = int(self.byte_buffer[:Packet.length_S_length])
            if byte_buffer_size < length:
                break  # not enough bytes to read the whole packet

            # Check if packet is corrupt
            if Packet.corrupt(self.byte_buffer):
                # Send a NAK
                print("RECEIVER: Corrupt packet, sending NAK.")
                self.network.udt_send(Packet(self.seq_num, NAK).get_byte_string())
            else:
                # create packet from buffer content
                packet = Packet.from_byte_string(self.byte_buffer[0:length])
                if packet.message_string == ACK or packet.message_string == NAK:
                    self.byte_buffer = self.byte_buffer[length:]
                    continue
                if packet.seq_num < self.seq_num:
                    print('RECEIVER: Already received packet.  ACK again.')
                    # Send another ACK
                    self.network.udt_send(Packet(packet.seq_num, ACK).get_byte_string())
                elif packet.seq_num == self.seq_num:
                    print('RECEIVER: Received new.  Send ACK and increment seq.')
                    # SEND ACK
                    self.network.udt_send(Packet(self.seq_num, ACK).get_byte_string())
                    self.seq_num += 1

                return_string = packet.message_string if (return_string is None) else return_string + p.message_string
            # remove the packet bytes from the buffer
            self.byte_buffer = self.byte_buffer[length:]
            # if this was the last packet, will return on the next iteration
        return return_string

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='RDT implementation.')
    parser.add_argument('role', help='Role is either client or server.', choices=[
                        'client', 'server'])
    parser.add_argument('server', help='Server.')
    parser.add_argument('port', help='Port.', type=int)
    args = parser.parse_args()

    rdt = RDT_2_1(args.role, args.server, args.port)
    if args.role == 'client':
        rdt.rdt_2_1_send('MSG_FROM_CLIENT')
        sleep(2)
        print(rdt.rdt_2_1_receive())
        rdt.disconnect()

    else:
        sleep(1)
        print(rdt.rdt_2_1_receive())
        rdt.rdt_2_1_send('MSG_FROM_SERVER')
        rdt.disconnect()
