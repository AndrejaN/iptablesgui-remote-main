[![Python application](https://github.com/FaheemAlvii/iptablesgui-remote/actions/workflows/python-app.yml/badge.svg)](https://github.com/FaheemAlvii/iptablesgui-remote/actions/workflows/python-app.yml)

# Modified version of the software from - https://github.com/FaheemAlvii/iptablesgui-remote
 Thanks to FaheemAlvii for the original work.
 
 Added the ability for using ppk keys for authentication instead of passwords.

# iptablesgui-remote
Remotely Manage your IPTables using GUI based on ssh connection.

1. Make Sure Python3 is installed
2. pip3 install -r requirements.txt
3. Open multi-server.py and add Servers in this format:
      SERVERS = [
          {'name': 'ServerName', 'host': 'ipadress', 'port': 22, 'username': 'root', 'key_filename': 'filename.ppk'},
      ]

4. python multi-server.py | python3 multi-server.py


Screenshots:

![image](https://github.com/user-attachments/assets/c7ba3871-72ad-4fc7-8f71-c57a477b6619)
![image](https://github.com/user-attachments/assets/5cc1b693-0009-420a-ab5a-d1758cdd5e0e)
