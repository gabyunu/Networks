# calculator_client.py

import socket                                      # TCP socket communication
import json                                        # JSON serialization

HOST = "ec2-18-221-174-49.us-east-2.compute.amazonaws.com" # Server IP address.
PORT = 80                                          # Server port

while True:
    a = input("Enter first number (or exit to quit): ") # Read first value as text

    if a.strip().lower() == "exit":
        break

    b = input("Enter second number: ")             # Read second value as text
    operation = input("Enter operation (add, sub, mul, div): ") # Read operation as text

    try:
        a = float(a)
    except ValueError:
        pass

    try:
        b = float(b)
    except ValueError:
        pass

    payload = {                                    # Create request dictionary
        "a": a,                                    # Store first value
        "b": b,                                    # Store second value
        "operation": operation                     # Store requested operation
    }

    s = socket.socket()                            # Create TCP socket
    s.settimeout(10)

    try:
        s.connect((HOST, PORT))                    # Connect to server
        s.send(json.dumps(payload).encode())       # Serialize and send request. json.dumps(payload) converts the payload dictionary into a JSON string, and .encode() converts that string into bytes, which is the format required for sending data over a socket.

        response = s.recv(1024).decode()            # Receive server response
        print("Server response:", response)        # Display response

    except OSError as error:
        print("Connection error:", error)

    finally:
        s.close()                                  # Close connection
