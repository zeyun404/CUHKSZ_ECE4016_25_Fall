import socket
import json
import studentcode_124090567 as studentcode
import sys

ss = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ss.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
ss.bind(('localhost', 6000))
ss.listen(1)
print('Waiting for simulator')

try:
    clientsocket, address = ss.accept()
    print("Simulator connected from", address)
except Exception as e:
    print("Accept failed:", e)
    ss.close()
    sys.exit(1)

def recv_commands():
    buffer = ""
    try:
        while True:
            data = clientsocket.recv(4096)
            if not data:
                print("Simulator closed the connection.")
                break
            buffer += data.decode()

            # process all complete lines (messages terminated by '\n')
            while '\n' in buffer:
                line, _, buffer = buffer.partition('\n')
                if not line:
                    continue

                try:
                    jsonargs = json.loads(line)
                except Exception as e:
                    print("Failed to decode JSON line:", e, file=sys.stderr)
                    print("Line content:", repr(line), file=sys.stderr)
                    continue

                if jsonargs.get("exit", 0) != 0:
                    print("Received exit signal from simulator.", file=sys.stderr)
                    return

                mb = jsonargs.get("Measured Bandwidth")
                pt = jsonargs.get("Previous Throughput")
                buf_occ = jsonargs.get("Buffer Occupancy")
                av_brs = jsonargs.get("Available Bitrates")
                vtime = jsonargs.get("Video Time")
                chunk_arg = jsonargs.get("Chunk")
                rebuff = jsonargs.get("Rebuffering Time")
                pref = jsonargs.get("Preferred Bitrate")
                next_chunk_sizes = jsonargs.get("Next Chunk Sizes", None)

                try:
                    bitrate = studentcode.student_entrypoint(mb, pt, buf_occ, av_brs, vtime, chunk_arg, rebuff, pref, next_chunk_sizes)
                except TypeError as e:
                    print("TypeError when calling student_entrypoint:", e, file=sys.stderr)
                    try:
                        bitrate = studentcode.student_entrypoint(mb, pt, buf_occ, av_brs, vtime, chunk_arg, rebuff, pref)
                    except Exception as ee:
                        print("Calling student_entrypoint failed:", ee, file=sys.stderr)
                        bitrate = 0
                except Exception as e:
                    print("Exception when calling student_entrypoint:", e, file=sys.stderr)
                    bitrate = 0

                response = json.dumps({"bitrate": int(bitrate)}) + '\n'
                clientsocket.sendall(response.encode())
    except KeyboardInterrupt:
        print("Interrupted by user.")
    finally:
        try:
            clientsocket.close()
        except:
            pass

if __name__ == "__main__":
    recv_commands()
    ss.close()