# -*- coding: utf-8 -*-
#!/usr/bin/env python
# 	https://securitytrails.com/domain/altasadsl.vodafone.es/history/a
import sys, urllib, requests, json, argparse, time, re, socket, string
from termcolor import colored
from bs4 import BeautifulSoup

parser = argparse.ArgumentParser(description='Version: 1.0 - This script intend to obtain real ip bypassing WAFs by Historical DNS data')
parser.add_argument('-t','--target', help="Indicate domain to process \n\n",required=True)
args = parser.parse_args()

try:
	if args.target is not None: 
		cleanParam = args.target
		if 'http://' in cleanParam:
			cleanParam =  cleanParam.replace("http://", "")
			cleanParam =  socket.gethostbyname(cleanParam)

		if 'https://' in cleanParam:
			args.target =  args.target.replace("https://", "")
			args.target =  socket.gethostbyname(cleanParam)

		if 'www.' in cleanParam:
			cleanParam =  cleanParam.replace("www.", "")
			cleanParam =  socket.gethostbyname(cleanParam)
			args.target = cleanParam

		url = ('https://securitytrails.com/domain/' + args.target + '/history/a')

		print(colored(' Actual IP address: ', 'green'))
		ip_actual = socket.gethostbyname(args.target)
		print(' ' + colored(ip_actual, 'blue') + '\n')

		print(colored(' IP addresses Found: ', 'green'))
		html_content = requests.get(url).text
		soup = BeautifulSoup(html_content, "lxml")

		headers = [c.get_text() for c in soup.find('tr')]
		data = [[cell.get_text(strip=True) for cell in row.find_all('td')] for row in soup.find_all("tr", class_=True)]

		separator = "   |   "
		def converttostr(input_seq, separator):		# COMO SOY UN CAZURRO PASO LA LISTA A STRING
			final_str = separator.join(input_seq)
			return final_str

		print(" " + converttostr(headers, separator))
		print(" -------------------------------------------------------------------------------------------- ")
		
		cleanTable = ("[{0}]".format('\n'.join(map(str, data))))
		
		if "[['" in cleanTable:
			cleanTable =  cleanTable.replace("[['", "")

		if "']]" in cleanTable:
			cleanTable =  cleanTable.replace("']]", "")

		if "['" in cleanTable:
			cleanTable =  cleanTable.replace("['", "")

		if "']" in cleanTable:
			cleanTable =  cleanTable.replace("']", "")

		if "', '" in cleanTable:
			cleanTable =  cleanTable.replace("', '", "       ")
		
		print(cleanTable)

	else:
		print(colored(' Warning: Need indicate domain to process, use -h for help', 'yellow'))
		sys.exit(1)

	print(colored(' --- The execution has been completed --- ', 'yellow'))

except Exception as e:
	print(colored(' Fatal Error: {}'.format(e), 'yellow'))
	sys.exit(1)