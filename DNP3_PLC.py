#!/usr/bin/env python3
"""
DNP3 PLC Simulator
"""

import socket
import threading
import time
import struct
import random
from datetime import datetime

class DNP3Frame:
    def __init__(self):
        self.start = 0x0564
        self.length = 0
        self.control = 0x44
        self.destination = 1
        self.source = 10
        self.data = b''
    
    def pack(self):
        header = struct.pack('<HHBHH', self.start, self.length, self.control, self.destination, self.source)
        crc = self.calculate_crc(header[2:])
        return header + struct.pack('<H', crc) + self.data
    
    def calculate_crc(self, data):
        # Simplified CRC-16 for DNP3
        crc = 0x0000
        for byte in data:
            crc ^= byte
            for _ in range(8):
                if crc & 1:
                    crc = (crc >> 1) ^ 0xA001
                else:
                    crc >>= 1
        return crc

class DNP3Outstation:
    def __init__(self, host='0.0.0.0', port=20000):
        self.host = host
        self.port = port
        self.socket = None
        self.running = False
        
        # Simulated data points
        self.binary_inputs = [False] * 16
        self.analog_inputs = [0.0] * 8
        self.binary_outputs = [False] * 8
        self.analog_outputs = [0.0] * 4
        
        # Security flags for testing
        self.auth_enabled = False
        self.vulnerable_mode = True
        self.log_traffic = True
        
    def start(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((self.host, self.port))
        self.socket.listen(5)
        self.running = True
        
        print(f"[+] DNP3 Outstation started on {self.host}:{self.port}")
        print(f"[+] Vulnerable mode: {self.vulnerable_mode}")
        
        # Start data simulation thread
        threading.Thread(target=self.simulate_data, daemon=True).start()
        
        while self.running:
            try:
                client_socket, addr = self.socket.accept()
                print(f"[+] Connection from {addr}")
                threading.Thread(target=self.handle_client, args=(client_socket, addr), daemon=True).start()
            except Exception as e:
                if self.running:
                    print(f"[-] Error accepting connection: {e}")
    
    def handle_client(self, client_socket, addr):
        try:
            while self.running:
                data = client_socket.recv(1024)
                if not data:
                    break
                
                if self.log_traffic:
                    self.log_message(f"RX from {addr}: {data.hex()}")
                
                response = self.process_dnp3_message(data, addr)
                if response:
                    client_socket.send(response)
                    if self.log_traffic:
                        self.log_message(f"TX to {addr}: {response.hex()}")
                        
        except Exception as e:
            print(f"[-] Error handling client {addr}: {e}")
        finally:
            client_socket.close()
            print(f"[-] Disconnected from {addr}")
    
    def process_dnp3_message(self, data, client_addr):
        try:
            if len(data) < 10:
                return None
            
            # Parse DNP3 header (little endian)
            start = struct.unpack('<H', data[0:2])[0]
            length = data[2]
            control = data[3] 
            dest = struct.unpack('<H', data[4:6])[0]
            src = struct.unpack('<H', data[6:8])[0]
            crc = struct.unpack('<H', data[8:10])[0]
            
            print(f"[DEBUG] Parsed header: start=0x{start:04x}, len={length}, ctrl=0x{control:02x}, dst={dest}, src={src}, crc=0x{crc:04x}")
            
            if start != 0x0564:
                print(f"[ERROR] Invalid start bytes: 0x{start:04x}, expected 0x0564")
                return None
            
            # Extract application layer (after 10-byte data link header)
            if len(data) < 12:
                return self.create_error_response()
            
            app_data = data[10:]
            
            if len(app_data) < 2:
                return self.create_error_response()
            
            app_control = app_data[0]
            # Function code is in position 2 (after transport layer byte)
            if len(app_data) >= 3:
                function_code = app_data[2]
            else:
                function_code = app_data[1]  # fallback
            
            # Log the function code and source
            client_ip = client_addr[0]
            print(f"[*] DNP3 Function Code: {function_code} from {client_ip} (DNP3_src={src})")
            
            # Process based on function code
            if function_code == 1:  # Read
                print(f"[*] READ REQUEST from {client_ip}")
                return self.handle_read_request(app_data, src, dest, client_ip)
            elif function_code == 2:  # Write
                print(f"[*] WRITE REQUEST from {client_ip}")
                return self.handle_write_request(app_data, src, dest, client_ip)
            elif function_code == 3:  # Select
                print(f"[*] SELECT REQUEST from {client_ip}")
                return self.handle_select_request(app_data, src, dest, client_ip)
            elif function_code == 4:  # Operate
                print(f"[*] OPERATE REQUEST from {client_ip}")
                return self.handle_operate_request(app_data, src, dest, client_ip)
            elif function_code == 13:  # Cold Restart
                print(f"[*] RESTART REQUEST from {client_ip}")
                return self.handle_restart_request(src, dest, client_ip)
            else:
                print(f"[*] UNKNOWN FUNCTION CODE: {function_code} from {client_ip}")
                return self.create_unsupported_response(src, dest)
                
        except Exception as e:
            print(f"[-] Error processing DNP3 message: {e}")
            return None
    
    def handle_read_request(self, app_data, src, dest, client_ip):
        # Create response with current data
        response_data = b'\x81\x00\x00'  # App control + function + IIN
        
        # Add binary inputs (Group 1)
        bi_data = b'\x01\x02\x00\x00\x08\x00'  # Group 1, Var 2, range 0-7
        bi_flags = 0
        for i in range(8):
            if self.binary_inputs[i]:
                bi_flags |= (0x81 << (i * 8))  # Online + Value
            else:
                bi_flags |= (0x01 << (i * 8))  # Online only
        bi_data += struct.pack('<Q', bi_flags)
        
        # Add analog inputs (Group 30)
        ai_data = b'\x1E\x01\x00\x00\x04\x00'  # Group 30, Var 1, range 0-3
        for i in range(4):
            ai_value = int(self.analog_inputs[i] * 1000)  # Convert to integer
            ai_data += struct.pack('<HB', ai_value, 0x01)  # Value + Online flag
        
        response_data += bi_data + ai_data
        return self.create_response_frame(response_data, src, dest)
    
    def handle_write_request(self, app_data, src, dest, client_ip):
        if self.vulnerable_mode:
            # Accept all writes without authentication
            print(f"[!] ATTACK_DETECTED: UNAUTHORIZED_WRITE from_ip={client_ip} dnp3_src={src} to_port={self.port} severity=HIGH")
            print(f"[!] VULNERABILITY: Accepting unauthenticated write from {client_ip}")
            return self.create_response_frame(b'\x81\x00\x00', src, dest)
        else:
            # Reject unauthorized writes
            return self.create_response_frame(b'\x81\x00\x02', src, dest)  # Device restart required
    
    def handle_select_request(self, app_data, src, dest, client_ip):
        print(f"[!] ATTACK_DETECTED: UNAUTHORIZED_SELECT from_ip={client_ip} dnp3_src={src} to_port={self.port} severity=MEDIUM")
        # Always accept select (for testing)
        return self.create_response_frame(b'\x81\x00\x00', src, dest)
    
    def handle_operate_request(self, app_data, src, dest, client_ip):
        if self.vulnerable_mode:
            # Execute operation without verification
            print(f"[!] ATTACK_DETECTED: UNAUTHORIZED_OPERATE from_ip={client_ip} dnp3_src={src} to_port={self.port} severity=HIGH")
            print(f"[!] VULNERABILITY: Executing operation from {client_ip}")
            return self.create_response_frame(b'\x81\x00\x00', src, dest)
        else:
            return self.create_response_frame(b'\x81\x00\x02', src, dest)
    
    def handle_restart_request(self, src, dest, client_ip):
        print(f"[!] CRITICAL: Restart request from {client_ip} (DNP3_src={src})")
        if self.vulnerable_mode:
            print(f"[!] VULNERABILITY: Executing restart without authentication from {client_ip}")
            return self.create_response_frame(b'\x81\x00\x00', src, dest)
        else:
            return self.create_response_frame(b'\x81\x00\x04', src, dest)  # Function not supported
    
    def create_response_frame(self, app_data, dest, src):
        frame = DNP3Frame()
        frame.destination = dest
        frame.source = src
        frame.data = app_data
        frame.length = len(app_data) + 5  # App data + header fields after length
        return frame.pack()
    
    def create_error_response(self):
        frame = DNP3Frame()
        frame.data = b'\x81\x00\x01'  # App control + function + Device restart
        frame.length = 8
        return frame.pack()
    
    def create_unsupported_response(self, dest, src):
        frame = DNP3Frame()
        frame.destination = dest
        frame.source = src
        frame.data = b'\x81\x00\x04'  # Function not supported
        frame.length = 8
        return frame.pack()
    
    def simulate_data(self):
        """Simulate changing PLC data"""
        while self.running:
            # Simulate binary inputs (sensors)
            for i in range(len(self.binary_inputs)):
                if random.random() < 0.1:  # 10% chance of state change
                    self.binary_inputs[i] = not self.binary_inputs[i]
            
            # Simulate analog inputs (temperature, pressure, etc.)
            for i in range(len(self.analog_inputs)):
                self.analog_inputs[i] += random.uniform(-0.5, 0.5)
                self.analog_inputs[i] = max(0, min(100, self.analog_inputs[i]))
            
            time.sleep(1)
    
    def log_message(self, message):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] {message}")
    
    def stop(self):
        self.running = False
        if self.socket:
            self.socket.close()

def main():
    print("DNP3 PLC Simulator for Security Testing")
    print("=======================================")
    
    outstation = DNP3Outstation(host='0.0.0.0', port=20000)
    
    try:
        outstation.start()
    except KeyboardInterrupt:
        print("\n[+] Shutting down...")
        outstation.stop()

if __name__ == "__main__":
    main()