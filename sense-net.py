#!/usr/bin/env python3
#Sense-NET is a tool to interact with bioimplants (specially those manufactured by Dangerous Things)
#Refer to the documentation for a list of compatible implants and devices
#Mauro Eldritch @ DC5411 - 2024

import os, sys, platform, argparse, signal
import ndef
from smartcard.CardMonitoring import CardMonitor, CardObserver
from smartcard.util import toHexString
from smartcard.CardConnection import CardConnection
from termcolor import colored

#Known manufacturers (RFID mode)
KNOWN_MANUFACTURERS = {
	"02": "STMicroelectronics",
	"04": "NXP Semiconductors",
	"07": "Texas Instruments",
	"08": "INSIDE Secure (INSIDE)",
	"0A": "Innovision Research",
	"1B": "Sony Corporation",
	"1C": "Infineon Technologies",
	"2E": "Broadcom",
	"3F": "Motorola",
	"44": "Atmel",
	"88": "Samsung Electronics"
}

#Known chips (NFC mode)
KNOWN_CHIPS = {
	"00 01": "MIFARE Classic 1K",
	"00 38": "MIFARE Plus® SL2 2K",
	"00 02": "MIFARE Classic 4K",
	"00 39": "MIFARE Plus® SL2 4K",
	"00 03": "MIFARE Ultralight®",
	"00 26": "MIFARE Mini®",
	"00 3A": "MIFARE Ultralight® C",
	"00 36": "MIFARE Plus® SL1 2K",
	"00 37": "MIFARE Plus® SL1 4K",
}

#Known standards (NFC mode)
KNOWN_STANDARDS = {
	"03": "ISO 14443A, Part 3",
	"11": "FeliCa"
}

#Catch user's interruptions via SIGINT 
def signal_handler(sig, frame):
	printc("\n[!] Detected Ctrl+C. Exiting...", "yellow")
	sys.exit(0)
signal.signal(signal.SIGINT, signal_handler)

#I miss Ruby's colorize gem
def printc(string, color, extras=None):
	if extras:
		print(colored(string, color, attrs=[extras]))
	else:
		print(colored(string, color))

#Detect compatible readers and their available modes
def detect_reader_mode():
	os_type = platform.system()
	if os_type == "Darwin":
		output = os.popen("system_profiler SPUSBDataType 2>/dev/null").read()
		if "Vendor ID: 0x08ff" in output and "Product ID: 0x0009" in output:
			return "Dangerous Things RFID reader (Sycreader RFID Technology / AuthenTec).", "RFID"
		elif "Vendor ID: 0x072f" in output and "Product ID: 0x223b" in output:
			return "ACR1252 Dual Reader (ACS).", "NFC"
		else:
			return None, None
	elif os_type in ["Linux", "FreeBSD", "OpenBSD", "NetBSD"]:
		output = os.popen("lsusb").read()
		if "08ff:0009" in output:
			return "Dangerous Things RFID reader (Sycreader RFID Technology / AuthenTec).", "RFID"
		elif "072f:223b" in output:
			return "ACR1252 Dual Reader (ACS).", "NFC"
		else:
			return None, None
	else:
		printc("[!] Unsupported operating system.", "red")
		return None, None

#RFID Mode
def rfid_menu():
	option = ""
	while option != "0":
		printc("RFID Menu", "blue", "underline")
		printc("[1] Get implant information", "blue")
		printc("[0] Exit\n", "blue")
		option = input("[>] ").strip()
		if option == "1":
			get_rfid_info()
		elif option == "0":
			printc("[*] Exiting.", "yellow")
		else:
			printc("[!] Invalid option. Press any key to continue.", "red")
			input()
		os.system("clear")
		
def get_rfid_info():
	printc("\n[?] Please scan your implant using the RFID reader... ", "blue")
	bioimplant = input("[>] ").strip()
	if bioimplant and len(bioimplant) == 14:
		manufacturer_byte = bioimplant[:2]
		identifier = bioimplant[2:12]
		checksum = bioimplant[12:]
		manufacturer = KNOWN_MANUFACTURERS.get(manufacturer_byte, "Unknown")
		printc(f"\n[*] Bioimplant UID:   {bioimplant}", "blue", "bold")
		printc(f"[*] Manufacturer:     {manufacturer}", "blue", "bold")
		printc(f"[*] Identifier:	      {identifier}", "blue", "bold")
		printc(f"[*] Checksum:	      {checksum}", "blue", "bold")
		printc("\n[?] Press any key to continue...", "blue")
		input()
	else:
		printc("[!] Invalid data. Ensure the UID is 14 characters long.", "red")
		input()

#NFC mode
def nfc_menu():
	option = ""
	while option != "0":
		printc("[*] NFC Menu", "blue", "underline")
		printc("[1] Get implant information", "blue")
		printc("[2] Read implant contents (NDEF)", "blue")
		printc("[3] Read implant contents (RAW)", "blue")
		printc("[4] Write implant content", "blue")
		printc("[0] Exit\n", "blue")
		option = input("[>] ").strip()
		if option == "1":
			start_nfc_listener("info")
		elif option == "2":
			start_nfc_listener("read")
		elif option == "3":
			start_nfc_listener("raw")
		elif option == "4":
			printc("\n[?] Enter the NDEF message to be recorded on the implant: ", "blue")
			new_ndef_message = input("[>] ").strip()
			start_nfc_listener("write", new_ndef_message)
		elif option == "0":
			printc("[*] Exiting.", "yellow")
		else:
			printc("[!] Invalid option. Press any key to continue.", "red")
			input()
		os.system("clear")

#Read RAW blocks
def read_raw_blocks(connection):
	read_command = [0xFF, 0xB0, 0x00, 0x00, 0x10]
	block_number = 0
	max_blocks = 48
	try:
		while block_number < max_blocks:
			response, sw1, sw2 = connection.transmit(read_command)
			if sw1 == 0x90 and sw2 == 0x00:
				block_data = bytes(response)
				formatted_data = ' '.join([block_data.hex()[i:i+2] for i in range(0, len(block_data.hex()), 2)])
				printc(f"[*] Block {block_number:02}:       {formatted_data}", "blue", "bold")
				block_number += 1
				read_command[3] += 1
			else:
				printc("\n[*] End of data or no more readable blocks.", "blue")
				break
		if block_number == max_blocks:
			printc(f"\n[*] Reached maximum block limit of {max_blocks}.", "blue")
	except Exception as e:
		printc(f"[!] Error while reading blocks: {e}", "red")

#Observer for NFC Raw Read
class RawNTAG215Observer(CardObserver):
	def update(self, observable, actions):
		(addedcards, _) = actions
		for card in addedcards:
			printc(f"[*] Bioimplant ATR: {toHexString(card.atr)}", "blue", "bold")
			try:
				connection = card.createConnection()
				connection.connect()
				read_raw_blocks(connection)
			except Exception as e:
				printc(f"[!] Unable to connect to implant: {e}", "red")

#Create NDEF Text Record
def create_ndef_text_record(text: str) -> bytes:
	text_record = ndef.TextRecord(text)
	encoded_message = b''.join(ndef.message_encoder([text_record]))
	message_length = len(encoded_message)
	initial_message = b'\x03' + message_length.to_bytes(1, 'big') + encoded_message + b'\xFE'
	padding_length = -len(initial_message) % 4
	complete_message = initial_message + (b'\x00' * padding_length)
	return complete_message

#Write NDEF Message
def write_ndef_message(connection, ndef_message):
	page = 4
	while ndef_message:
		block_data = ndef_message[:4]
		ndef_message = ndef_message[4:]
		write_command = [0xFF, 0xD6, 0x00, page, 0x04] + list(block_data)
		response, sw1, sw2 = connection.transmit(write_command)
		if sw1 != 0x90 or sw2 != 0x00:
			printc(f"[!] Failed to write to page {page}: SW1={sw1:02X}, SW2={sw2:02X}", "red")
			return False
		printc(f"[*] Successfully wrote to page {page}", "blue")
		page += 1
	return True
		
#Observer for NFC Write
class WriteNTAG215Observer(CardObserver):
	def __init__(self, new_ndef_message):
		self.new_ndef_message = new_ndef_message
	def update(self, observable, actions):
		(addedcards, _) = actions
		for card in addedcards:
			printc(f"[*] Bioimplant ATR: {toHexString(card.atr)}", "blue", "bold")
			printc(f"[*] NDEF message:   {self.new_ndef_message}\n", "blue", "bold")
			try:
				connection = card.createConnection()
				connection.connect()
				ndef_message = create_ndef_text_record(str(self.new_ndef_message))
				if write_ndef_message(connection, ndef_message):
					printc("\n[*] NDEF message successfully written.", "blue")
			except Exception as e:
				printc(f"[!] Unable to connect to implant: {e}", "red")
		
#Parse NDEF as UTF8
def parse_ndef_raw_data(raw_data: bytes):
	try:
		if raw_data[0] == 0x03:
			length = raw_data[1]
			payload = raw_data[2:2 + length]
			printc(f"[*] NDEF Payload: {payload.decode('utf-8', errors='ignore')}\n", "blue", "bold")
		else:
			printc("[!] Invalid NDEF start marker.", "red")
	except Exception as e:
		printc("[!] Error decoding NDEF message: {e}.","red")

#Read NDEF messages
def read_ndef_message(connection: CardConnection):
	read_command = [0xFF, 0xB0, 0x00, 4, 0x04]
	raw_data = b''
	try:
		while True:
			response, sw1, sw2 = connection.transmit(read_command)
			if sw1 == 0x90 and sw2 == 0x00:
				raw_data += bytes(response[:4])
				if 0xFE in response:
					break
				read_command[3] += 1
			else:
				printc(f"[!] Failed to read at page {read_command[3]}: SW1={sw1:02X}, SW2={sw2:02X}", "red")
				return
		printc(f"[*] Raw NDEF data:  {raw_data.hex()}", "blue", "bold")
		parse_ndef_raw_data(raw_data)
	except Exception as e:
		printc(f"[!] Error rading implant: {e}", "red")

#Observer for NFC Read
class ReadNTAG215Observer(CardObserver):
	def update(self, observable, actions):
		(addedcards, _) = actions
		for card in addedcards:
			printc(f"[*] Bioimplant ATR: {toHexString(card.atr)}", "blue", "bold")
			try:
				connection = card.createConnection()
				connection.connect()
				read_ndef_message(connection)
			except Exception as e:
				printc(f"[!] Unable to connect to implant: {e}", "red")

#Decode ATR
def decode_atr(atr: str):
	atr_parts = atr.split(" ")
	rid = " ".join(atr_parts[7:12])
	standard = KNOWN_STANDARDS.get(atr_parts[12], "Unknown")
	card_name = KNOWN_CHIPS.get(" ".join(atr_parts[13:15]), "Unknown")
	printc(f"[*] RID:            {rid}", "blue", "bold")
	printc(f"[*] Standard:       {standard}", "blue", "bold")
	printc(f"[*] Chip Type:      {card_name}", "blue", "bold")

#Attempt to get UID and manufacturer
def get_nfc_info(connection):
	get_uid_command = [0xFF, 0xCA, 0x00, 0x00, 0x00]
	try:
		response, sw1, sw2 = connection.transmit(get_uid_command)
		if sw1 == 0x90 and sw2 == 0x00:
			uid = bytes(response)
			manufacturer_byte = uid[0:1].hex().upper()
			manufacturer = KNOWN_MANUFACTURERS.get(manufacturer_byte, "Unknown")
			checksum = uid[-1]
			payload = uid.hex()
			formatted_payload = ' '.join([payload[i:i+2] for i in range(0, len(payload), 2)])
			printc(f"[*] UID:            {toHexString(response)}", "blue", "bold")
			printc(f"[*] Manufacturer:   {manufacturer}", "blue", "bold")
			printc(f"[*] Checksum:       {checksum:02X}", "blue", "bold")
			printc(f"[*] Payload:        {formatted_payload}", "blue", "bold")
			return uid
		else:
			printc(f"[!] Failed to retrieve UID: SW1={sw1:02X}, SW2={sw2:02X}", "red")
			return None
	except Exception as e:
		printc(f"[!] Error retrieving NFC implant information: {e}", "red")
		return None
					
#Observer for NFC Info
class InfoNTAG215Observer(CardObserver):
	def update(self, observable, actions):
		(addedcards, _) = actions
		for card in addedcards:
			printc(f"[*] Bioimplant ATR: {toHexString(card.atr)}", "blue", "bold")
			try:
				connection = card.createConnection()
				connection.connect()
				get_nfc_info(connection)
				decode_atr(toHexString(card.atr))
			except Exception as e:
				printc(f"[!] Unable to connect to implant: {e}", "red")
		
#Start NFC listener
def start_nfc_listener(observer, new_ndef_message=None):
	cardmonitor = CardMonitor()
	cardobserver = None
	if observer == "info":
		cardobserver = InfoNTAG215Observer()
	elif observer == "read":
		cardobserver = ReadNTAG215Observer()
	elif observer == "write":
		cardobserver = WriteNTAG215Observer(new_ndef_message)
	elif observer == "raw":
		cardobserver = RawNTAG215Observer()
	cardmonitor.addObserver(cardobserver)
	try:
		printc("\n[*] NFC listener started.", "blue")
		printc("[*] Place your implant near the reader. Press Enter to stop the listener.\n", "blue")
		input()
	finally:
		cardmonitor.deleteObserver(cardobserver)
		printc("[*] NFC listener stopped.\n", "yellow")

#Arguments
def process_arguments():
	parser = argparse.ArgumentParser(description="Sense-NET: A tool for interacting with bioimplants.")
	parser.add_argument("--get-rfid-info", action="store_true", help="Get RFID implant information.")
	parser.add_argument("--get-nfc-info", action="store_true", help="Get NFC implant information.")
	parser.add_argument("--read-ndef", action="store_true", help="Read NDEF contents from an NFC implant.")
	parser.add_argument("--read-raw", action="store_true", help="Read raw blocks from an NFC implant.")
	parser.add_argument("--write-ndef", type=str, help="Write NDEF content to an NFC implant.")
	parser.add_argument("--version", action="store_true", help="Get Sense/Net version.")
	return parser.parse_args()

#Read arguments
def execute_action(args):
	if args.get_rfid_info:
		get_rfid_info()
	elif args.get_nfc_info:
		start_nfc_listener("info")
	elif args.read_ndef:
		start_nfc_listener("read")
	elif args.read_raw:
		start_nfc_listener("raw")
	elif args.write_ndef:
		start_nfc_listener("write", args.write_ndef)
	elif args.version:
		version()

#Version
def version():
	printc("Sense/Net v1.00", "green", "bold")
	printc("https://github.com/MauroEldritch/sense-net", "green", "bold")

#Main
def main():
	printc("\nWelcome to Sense/Net\n", "cyan", "bold")
	reader, mode = detect_reader_mode()
	if reader:
		printc(f"> Detected reader: {reader}", "cyan")
		printc(f"> Compatible mode: {mode}\n", "cyan")
		if mode == "RFID":
			rfid_menu()
		else:
			nfc_menu()
	else:
		printc("\n[!] No compatible devices found.", "red")

args = process_arguments()
#Non-interactive
if any(vars(args).values()):
	execute_action(args)
#Interactive
else:
	main();