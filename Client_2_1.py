import argparse
import RDT_2_1
import time

if __name__ == '__main__':
    parser =  argparse.ArgumentParser(description='Quotation client talking to a Pig Latin server.')
    parser.add_argument('server', help='Server.')
    parser.add_argument('port', help='Port.', type=int)
    args = parser.parse_args()
    
    msg_L = ['The use of COBOL cripples the mind; its teaching should, therefore, be regarded as a criminal offense. -- Edsgar Dijkstra',
            'C makes it easy to shoot yourself in the foot; C++ makes it harder, but when you do, it blows away your whole leg. -- Bjarne Stroustrup',
            'A mathematician is a device for turning coffee into theorems. -- Paul Erdos',
            'Grove giveth and Gates taketh away. -- Bob Metcalfe (inventor of Ethernet) on the trend of hardware speedups not being able to keep up with software demands',
            'Wise men make proverbs, but fools repeat them. -- Samuel Palmer (1805-80)']
    
     
    timeout = 2 #send the next message if no response
    time_of_last_data = time.time()
     
    rdt = RDT_2_1.RDT_2_1('client', args.server, args.port)
    for message_string in msg_L:
        print('Converting: '+message_string)
        rdt.rdt_2_1_send(message_string)
       
        # try to receive message before timeout 
        message_string = None
        while message_string == None:
            message_string = rdt.rdt_2_1_receive()
            if message_string is None:
                if time_of_last_data + timeout < time.time():
                    break
                else:
                    continue
        time_of_last_data = time.time()
        
        #print the result
        if message_string:
            print('to: '+message_string+'\n')
        
    rdt.disconnect()