import os

filename = input("Please provide a file name to search and display:\n")

command = "cat " + filename
os.system(command)

""" Solution:

import subprocess

filename = input("Please provide a file name to search and display:\n")

# Using subprocess.Popen to execute the command safely
try:
    result = subprocess.Popen(["cat", filename], stdout=subprocess.PIPE)
    output, _ = result.communicate()
    print(output.decode())
except FileNotFoundError:
    print("File not found.")
    
"""
