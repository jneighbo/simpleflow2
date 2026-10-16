"""Send synthetic NetFlow v5 packets to a running local collector for testing."""
import argparse
import ipaddress
import random
import socket
import struct
import time


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--host', default='127.0.0.1')
    p.add_argument('--port', type=int, default=2055)
    p.add_argument('--packets', type=int, default=20)
    args = p.parse_args()
    rand = random.Random(42)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for i in range(args.packets):
        now = time.time()
        records = []
        for j in range(10):
            protocol, port = rand.choice([(6, 443), (17, 53), (6, 22), (6, 80)])
            ingress = rand.random() > .4
            local = int(ipaddress.IPv4Address(f'10.10.0.{rand.randint(2, 20)}'))
            remote = int(ipaddress.IPv4Address(f'203.0.113.{rand.randint(1, 50)}'))
            size = rand.randint(10000, 900000)
            records.append(struct.pack('!IIIHHIIIIHHBBBBHHBBH', remote if ingress else local, local if ingress else remote,
                int(ipaddress.IPv4Address('10.10.0.1')), 1 if ingress else 2, 2 if ingress else 1,
                size // 1000, size, 10000, 15000, port if ingress else 52000+j, 52000+j if ingress else port,
                0, 16 if protocol == 6 else 0, protocol, 0, 64500 if ingress else 64512, 64512 if ingress else 64500, 24, 24, 0))
        header = struct.pack('!HHIIIIBBH', 5, 10, 30000+i*200, int(now), int(now%1*1e9), i*10, 0, 1, 0)
        sock.sendto(header+b''.join(records), (args.host, args.port))
        time.sleep(.2)
    sock.close()
    print(f'Sent {args.packets * 10} synthetic flow records to {args.host}:{args.port}')


if __name__ == '__main__':
    main()
