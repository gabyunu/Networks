# calculator_server.py

import socket
import json

HOST = "0.0.0.0"
PORT = 80


def handle_request(data):
    try:
        payload = json.loads(data)

        # Comprobar que el JSON sea un objeto.
        if not isinstance(payload, dict):
            return {"code": 400, "error": "Request sent"}

        a = payload.get("a")
        b = payload.get("b")
        operation = payload.get("operation")

        # TODO 1: Comprobar si falta algun parametro.
        if "a" not in payload or "b" not in payload or "operation" not in payload:
            return {"code": 400, "error": "Missing parameters"}

        # TODO 2: Validar que a y b sean numeros.
        if type(a) not in (int, float) or type(b) not in (int, float):
            return {"code": 422, "error": "a and b may be numbers"}

        if not isinstance(operation, str):
            return {"code": 422, "error": "The operation must be text"}

        # TODO 3: Implementar las operaciones.
        if operation == "add":
            result = a + b

        elif operation == "sub":
            result = a - b

        elif operation == "mul":
            result = a * b

        elif operation == "div":
            # TODO 4: Controlar la division para cero.
            if b == 0:
                return {"code": 422, "error": "Division by zero"}

            result = a / b

        else:
            # TODO 5: Controlar operaciones no admitidas.
            return {"code": 422, "error": "Unsupported operation"}

        return {"code": 200, "result": result}

    except json.JSONDecodeError:
        # TODO 6: Responder cuando el JSON es invalido.
        return {"code": 400, "error": "JSON invalido"}


# Crear el socket TCP.
server_socket = socket.socket()
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server_socket.bind((HOST, PORT))
server_socket.listen(5)
print(f"Calculator server running on {HOST}:{PORT}") # Display server status

while True:                                        # Keep server running
    conn, addr = server_socket.accept()            # Accept incoming connection
    print(f"Connection from {addr}")               # Display client address
    data = conn.recv(1024).decode()                # Receive client data
    response = handle_request(data)                # Process request on server

    try:
        payload = json.loads(data)
        if not isinstance(payload, dict):
            payload = {}
    except json.JSONDecodeError:
        payload = {}

    print("\n---------- OPERATION LOG ----------")
    print("Client IP:", addr[0])
    print("Server IP (local):", conn.getsockname()[0])
    print("Operation:", payload.get("operation", "Missing"))
    print("a:", payload.get("a", "Missing"))
    print("b:", payload.get("b", "Missing"))
    print("Result:", response.get("result"))
    print("Error:", response.get("error"))
    print("Code:", response.get("code"))
    print("-----------------------------------", flush=True)

    response = {
        "result": response.get("result"),
        "error": response.get("error"),
        "code": response["code"]
    }           # Convert response to JSON
    response_json = json.dumps(response)           # Convert response to JSON
    conn.send(response_json.encode())              # Send response to client
    conn.close()                                   # Close client connection             # Send response to client
    conn.close()                                   # Close client connection
