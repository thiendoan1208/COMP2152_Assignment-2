"""
Author: DUC THIEN DOAN
Assignment: #2
Description: Port Scanner - A tool that scans a target machine for open network ports
"""

import socket
import threading
import sqlite3
import os
import platform
import datetime

print(f"Python Version: {platform.python_version()}")
print(f"Operating System: {os.name}")

# This dictionary stores common port numbers and their associated service names.
common_ports = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-Alt",
}


class NetworkTool:
    def __init__(self, target):
        self.__target = target

    # Q3: What is the benefit of using @property and @target.setter?
    # @property and @target.setter let the class control access to the private target value.
    # This makes validation easier because the setter can reject invalid input like an empty string.
    # It also keeps the code clean by letting us use scanner.target like a normal attribute.
    @property
    def target(self):
        return self.__target

    @target.setter
    def target(self, value):
        if value == "":
            print("Error: Target cannot be empty")
            return
        self.__target = value

    def __del__(self):
        print("NetworkTool instance destroyed")


# Q1: How does PortScanner reuse code from NetworkTool?
# PortScanner reuses code from NetworkTool through inheritance.
# It gets the target attribute, property methods, and validation logic without rewriting them.
class PortScanner(NetworkTool):
    def __init__(self, target):
        super().__init__(target)
        self.scan_results = []
        self.lock = threading.Lock()

    def __del__(self):
        print("PortScanner instance destroyed")
        super().__del__()

    def scan_port(self, port):
        sock = None

        # Q4: What would happen without try-except here?
        # Without try-except, a socket or network error could stop the current scan.
        # If the target machine is unreachable, the program may fail before finishing the scan.
        # Exception handling keeps the scanner stable and lets it continue running.
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((self.target, port))
            status = "Open" if result == 0 else "Closed"
            service_name = common_ports.get(port, "Unknown")

            with self.lock:
                self.scan_results.append((port, status, service_name))
        except socket.error as error:
            print(f"Error scanning port {port}: {error}")
        finally:
            if sock is not None:
                sock.close()

    def get_open_ports(self):
        return [result for result in self.scan_results if result[1] == "Open"]

    # Q2: Why do we use threading instead of scanning one port at a time?
    # Threading lets the scanner check many ports at the same time, so it finishes faster.
    # Scanning one port at a time would be much slower, especially when ports wait for a timeout.
    # This matters even more when scanning a large range like 1 to 1024.
    def scan_range(self, start_port, end_port):
        threads = []

        for port in range(start_port, end_port + 1):
            thread = threading.Thread(target=self.scan_port, args=(port,))
            threads.append(thread)

        for thread in threads:
            thread.start()

        for thread in threads:
            thread.join()


def save_results(target, results):
    conn = None
    try:
        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT,
                port INTEGER,
                status TEXT,
                service TEXT,
                scan_date TEXT
            )
            """
        )

        for port, status, service in results:
            cursor.execute(
                """
                INSERT INTO scans (target, port, status, service, scan_date)
                VALUES (?, ?, ?, ?, ?)
                """,
                (target, port, status, service, str(datetime.datetime.now())),
            )

        conn.commit()
    except sqlite3.Error as error:
        print(f"Database error: {error}")
    finally:
        if conn is not None:
            conn.close()


def load_past_scans():
    if not os.path.exists("scan_history.db"):
        print("No past scans found.")
        return

    conn = None
    try:
        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()
        cursor.execute("SELECT target, port, status, service, scan_date FROM scans")
        rows = cursor.fetchall()

        if not rows:
            print("No past scans found.")
            return

        for target, port, status, service, scan_date in rows:
            print(f"[{scan_date}] {target} : Port {port} ({service}) - {status}")
    except sqlite3.Error:
        print("No past scans found.")
    finally:
        if conn is not None:
            conn.close()


if __name__ == "__main__":
    target = input("Enter target IP address (default 127.0.0.1): ").strip() or "127.0.0.1"

    try:
        start_port = int(input("Enter starting port (1-1024): "))
        end_port = int(input("Enter ending port (1-1024): "))
    except ValueError:
        print("Invalid input. Please enter a valid integer.")
    else:
        if not (1 <= start_port <= 1024 and 1 <= end_port <= 1024):
            print("Port must be between 1 and 1024.")
        elif end_port < start_port:
            print("End port must be greater than or equal to start port.")
        else:
            scanner = PortScanner(target)
            print(f"Scanning {target} from port {start_port} to {end_port}...")
            scanner.scan_range(start_port, end_port)

            open_ports = sorted(scanner.get_open_ports(), key=lambda item: item[0])
            print(f"--- Scan Results for {target} ---")
            for port, status, service in open_ports:
                print(f"Port {port}: {status} ({service})")
            print("-------")
            print(f"Total open ports found: {len(open_ports)}")

            save_results(target, scanner.scan_results)

            show_history = input("Would you like to see past scan history? (yes/no): ").strip().lower()
            if show_history == "yes":
                load_past_scans()


# Q5: New Feature Proposal
# One feature I would add is a filtered report that only shows important ports like 22, 80, and 443.
# I would use a list comprehension to create a new list with only those selected port results.
# This would help the user focus on the most useful information first.
