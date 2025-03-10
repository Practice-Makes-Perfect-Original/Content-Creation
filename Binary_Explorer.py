## This is a simple program that allows exploration of binary files
"""
Binary File Explorer

Author: Keaton
License: MIT License (see LICENSE file for details)
Website: https://github.com/yourgithub

Description:
A script to explore binary files, displaying content in hex or ASCII format.

Usage:
    python script.py <file_path> [-c chunk_size] [-f hex/ascii]

Disclaimer:
This software is provided "as is", without warranty of any kind. The author is not responsible for any misuse or damage caused by this tool.

"""



import os
import argparse

def read_binary(file_path, chunk_size=200, output_format='hex'):
    if not os.path.exists(file_path):
        print("Error: File not found.")
        return
    
    with open(file_path, "rb") as f:
        offset = 0
        while True:
            data = f.read(chunk_size)
            if not data:
                break
            
            if output_format == 'hex':
                print(f"{offset:08X}: {data.hex()}")
            elif output_format == 'ascii':
                printable = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in data)
                print(f"{offset:08X}: {printable}")
            
            offset += chunk_size
            if input("Press Enter to continue or type 'exit' to quit: ").strip().lower() == 'exit':
                break

def main():
    parser = argparse.ArgumentParser(description="Binary File Explorer")
    parser.add_argument("file", help="Path to the binary file")
    parser.add_argument("-c", "--chunk", type=int, default=200, help="Number of bytes to read per chunk")
    parser.add_argument("-f", "--format", choices=['hex', 'ascii'], default='hex', help="Output format: hex or ascii")
    args = parser.parse_args()
    
    read_binary(args.file, args.chunk, args.format)

if __name__ == "__main__":
    main()
