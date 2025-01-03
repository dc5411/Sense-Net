#!/usr/bin/env python3
#Sense-NET is a tool to interact with bioimplants (specially those manufactured by Dangerous Things)
#Refer to the documentation for a list of compatible implants and devices
#Mauro Eldritch @ BCA LTD - 2024

import os, sys, platform, argparse
import ndef
from smartcard.CardMonitoring import CardMonitor, CardObserver
from smartcard.util import toHexString
from smartcard.CardConnection import CardConnection

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
		print("[!] Unsupported operating system.")
		return None, None

#RFID Mode
def rfid_menu():
	option = ""
	while option != "0":
		print("[*] RFID Menu")
		print("[1] Get implant information")
		print("[0] Exit\n")
		option = input("[>] ").strip()
		if option == "1":
			get_rfid_info()
		elif option == "0":
			print("[*] Exiting.")
		else:
			print("[!] Invalid option. Press any key to continue.")
			input()
		os.system("clear")
		
#Known manufacturers
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

#Known Chips
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

#Known Standards
KNOWN_STANDARDS = {
	"03": "ISO 14443A, Part 3",
	"11": "FeliCa"
}

def get_rfid_info():
	sys.stdout.write("[?] Please scan your implant using the RFID reader... ")
	sys.stdout.flush()
	bioimplant = input().strip()
	if bioimplant and len(bioimplant) == 14:
		manufacturer_byte = bioimplant[:2]
		identifier = bioimplant[2:12]
		checksum = bioimplant[12:]
		manufacturer = KNOWN_MANUFACTURERS.get(manufacturer_byte, "Unknown")
		print(f"\n[*] Bioimplant UID: {bioimplant}")
		print(f"[*] Manufacturer:   {manufacturer}")
		print(f"[*] Identifier:	 {identifier}")
		print(f"[*] Checksum:	   {checksum}")
		input("\n[?] Press any key to continue...")
	else:
		print("[!] Invalid data. Ensure the UID is 14 characters long.")
		input()

#NFC mode
def nfc_menu():
	option = ""
	while option != "0":
		print("[*] NFC Menu")
		print("[1] Get implant information")
		print("[2] Read implant contents (NDEF)")
		print("[3] Read implant contents (RAW)")
		print("[4] Write implant content")
		print("[0] Exit\n")
		option = input("[>] ").strip()
		if option == "1":
			start_nfc_listener("info")
		elif option == "2":
			start_nfc_listener("read")
		elif option == "3":
			start_nfc_listener("raw")
		elif option == "4":
			new_ndef_message = input("\n[>] Enter the NDEF message to be recorded on the implant: ").strip()
			start_nfc_listener("write", new_ndef_message)
		elif option == "0":
			print("[*] Exiting NFC menu...")
		else:
			print("[!] Invalid option. Please select 0, 1, or 2.")
		os.system("clear")

#Read RAW blocks
def read_raw_blocks(connection):
	print("[*] Reading all blocks:")
	read_command = [0xFF, 0xB0, 0x00, 0x00, 0x10]
	block_number = 0
	max_blocks = 48
	try:
		while block_number < max_blocks:
			response, sw1, sw2 = connection.transmit(read_command)
			if sw1 == 0x90 and sw2 == 0x00:
				block_data = bytes(response)
				formatted_data = ' '.join([block_data.hex()[i:i+2] for i in range(0, len(block_data.hex()), 2)])
				print(f"[*] Block {block_number:02}: {formatted_data}")
				block_number += 1
				read_command[3] += 1
			else:
				print("[*] End of data or no more readable blocks.")
				break
		if block_number == max_blocks:
			print(f"[*] Reached maximum block limit of {max_blocks}.")
	except Exception as e:
		print(f"[!] Error while reading blocks: {e}")

#Observer for NFC Raw Read
class RawNTAG215Observer(CardObserver):
	def update(self, observable, actions):
		(addedcards, _) = actions
		for card in addedcards:
			print(f"[*] Implant detected, ATR: {toHexString(card.atr)}")
			try:
				connection = card.createConnection()
				connection.connect()
				read_raw_blocks(connection)
			except Exception as e:
				print(f"[!] Unable to connect to implant: {e}")

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
			print(f"[!] Failed to write to page {page}: SW1={sw1:02X}, SW2={sw2:02X}")
			return False
		print(f"[*] Successfully wrote to page {page}")
		page += 1
	return True
		
#Observer for NFC Write
class WriteNTAG215Observer(CardObserver):
	def __init__(self, new_ndef_message):
		self.new_ndef_message = new_ndef_message
	def update(self, observable, actions):
		(addedcards, _) = actions
		for card in addedcards:
			print(f"[*] Implant detected, ATR: {toHexString(card.atr)}")
			print(f"[*] NDEF message:		  {self.new_ndef_message}")
			try:
				connection = card.createConnection()
				connection.connect()
				ndef_message = create_ndef_text_record(str(self.new_ndef_message))
				if write_ndef_message(connection, ndef_message):
					print("[*] NDEF message successfully written.")
			except Exception as e:
				print(f"[!] Unable to connect to implant: {e}")
		
#Parse NDEF as UTF8
def parse_ndef_raw_data(raw_data: bytes):
	try:
		if raw_data[0] == 0x03:
			length = raw_data[1]
			payload = raw_data[2:2 + length]
			print("[*] NDEF Payload:", payload.decode('utf-8', errors='ignore'))
		else:
			print("[!] Invalid NDEF start marker.")
	except Exception as e:
		print("[!] Error decoding NDEF message:", e)

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
				print(f"[!] Failed to read at page {read_command[3]}: SW1={sw1:02X}, SW2={sw2:02X}")
				return
		print("[*] Raw NDEF data:", raw_data.hex())
		parse_ndef_raw_data(raw_data)
	except Exception as e:
		print(f"[!] Error during reading: {e}")

#Observer for NFC Read
class ReadNTAG215Observer(CardObserver):
	def update(self, observable, actions):
		(addedcards, _) = actions
		for card in addedcards:
			print(f"[*] Implant detected, ATR: {toHexString(card.atr)}")
			try:
				connection = card.createConnection()
				connection.connect()
				read_ndef_message(connection)
			except Exception as e:
				print(f"[!] Unable to connect to implant: {e}")

#Decode ATR
def decode_atr(atr: str):
	atr_parts = atr.split(" ")
	rid = " ".join(atr_parts[7:12])
	standard = KNOWN_STANDARDS.get(atr_parts[12], "Unknown")
	card_name = KNOWN_CHIPS.get(" ".join(atr_parts[13:15]), "Unknown")
	print(f"[*] RID:		  {rid}")
	print(f"[*] Standard:	 {standard}")
	print(f"[*] Chip Type:	{card_name}")

#Attempt to get UID and manufacturer
def get_nfc_info(connection):
	get_uid_command = [0xFF, 0xCA, 0x00, 0x00, 0x00]
	try:
		response, sw1, sw2 = connection.transmit(get_uid_command)
		if sw1 == 0x90 and sw2 == 0x00:
			print(f"[*] UID: {toHexString(response)}")
			uid = bytes(response)
			manufacturer_byte = uid[0:1].hex().upper()
			manufacturer = KNOWN_MANUFACTURERS.get(manufacturer_byte, "Unknown")
			checksum = uid[-1]
			payload = uid.hex()
			formatted_payload = ' '.join([payload[i:i+2] for i in range(0, len(payload), 2)])
			print(f"[*] Manufacturer: {manufacturer}")
			print(f"[*] Checksum:	 {checksum:02X}")
			print(f"[*] Payload:	  {formatted_payload}")
			return uid
		else:
			print(f"[!] Failed to retrieve UID: SW1={sw1:02X}, SW2={sw2:02X}")
			return None
	except Exception as e:
		print(f"[!] Error retrieving NFC implant information: {e}")
		return None
					
#Observer for NFC Info
class InfoNTAG215Observer(CardObserver):
	def update(self, observable, actions):
		(addedcards, _) = actions
		for card in addedcards:
			print(f"[*] Implant detected, ATR: {toHexString(card.atr)}")
			try:
				connection = card.createConnection()
				connection.connect()
				get_nfc_info(connection)
				decode_atr(toHexString(card.atr))
			except Exception as e:
				print(f"[!] Unable to connect to implant: {e}")
		
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
		print("[*] NFC listener started.")
		input("[*] Place your implant near the reader. Press Enter to stop the listener.\n")
	finally:
		cardmonitor.deleteObserver(cardobserver)
		print("[*] NFC listener stopped.")

#Arguments
def process_arguments():
	parser = argparse.ArgumentParser(description="Sense-NET: A tool for interacting with bioimplants.")
	parser.add_argument("--get-rfid-info", action="store_true", help="Get RFID implant information.")
	parser.add_argument("--get-nfc-info", action="store_true", help="Get NFC implant information.")
	parser.add_argument("--read-ndef", action="store_true", help="Read NDEF contents from an NFC implant.")
	parser.add_argument("--read-raw", action="store_true", help="Read raw blocks from an NFC implant.")
	parser.add_argument("--write-ndef", type=str, help="Write NDEF content to an NFC implant.")
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
	else:
		print("[!] No valid action provided.")

#Main
def main():
	reader, mode = detect_reader_mode()
	if reader:
		print(f"[*] Reader: {reader}")
		print(f"[*] Compatible mode: {mode}\n")
		if mode == "RFID":
			rfid_menu()
		else:
			nfc_menu()
	else:
		print("[!] No compatible devices found.")

args = process_arguments()
#Non-interactive
if any(vars(args).values()):
	execute_action(args)
#Interactive
else:
	main();