import json
import requests
import time
import sys
import os


def clean():
        os.system('cls' if os.name=='nt' else 'clear')
clean()

def printer(Print):
    for c in Print + '\n':
        sys.stdout.write(c)
        sys.stdout.flush()
        time.sleep(1. / 100)
printer("[+]:Welcome To The OTXLookup")
printer ("[+]:Select A Indicator Data Type For Search Into OTX AlienVault \n" +"Example: Enter The 2 For IPv6")
time.sleep(1)
print ("""
[1]:IPv4 Indidator
[2]:IPv6 Indidator
[3]:Doamin Indidator
[4]:URL Indiator
[5]:HostName Indicator
[6]:Hash Indicator
[7]:CVE Indicator
""")


#SingUp To OTX Alienvault For Getting A API Key From API Integration Tab (https://otx.alienvault.com/api)
headers = {"X-OTX-API-KEY": "Paste OTX Key In Here",
		   "Accept": "application/json",
		   'User-Agent': 'Mozilla 5.0'}


def IPv4Indicator():
	#OTX Api For IPv4 Indicator -> /api/v1/indicators/IPv4/{ip}/{section}

	try:

		print ("Please Enter A IPv4")
		print ("Example: 8.8.8.8")
		IPv4 = input("> ")

		IPApi= "https://otx.alienvault.com//api/v1/indicators/IPv4/{0}".format(IPv4)
		output = requests.get(url=IPApi,headers=headers).content
		json_object = json.loads(output)

		print ("[+]: Indicator: {0}".format(json_object["indicator"]))
		print ("[+]: Type Of Indicator: {0}".format(json_object["type"]))
		print ("  Waiting For Pulses Info...")
		time.sleep(1)
		print ("  Pulses Info Resualt:")
		print ("  ...")
		print (json_object["pulse_info"])

	except KeyError:
		print ("[!] Error")
		print ("[!] Endpoint Not Found")


def IPv6Indicator():
	#OTX Api For IPv6 Indicator -> /api/v1/indicators/IPv6/{ip}/{section}
	
	try:
	
		print ("Please Enter A IPv6")
		print ("Example: 2001:0db8:85a3:0000:0000:8a2e:0370:7334")
		IPv6 = input("> ")


		IPv6Api= "https://otx.alienvault.com//api/v1/indicators/IPv6/{0}".format(IPv6)
		output = requests.get(url=IPv6Api,headers=headers).content
		json_object = json.loads(output)

		print ("[+]: Indicator: {0}".format(json_object["indicator"]))
		print ("[+]: Type Of Indicator: {0}".format(json_object["type"]))
		print ("  Waiting For Pulses Info...")
		time.sleep(1)
		print ("  Pulses Info Resualt:")
		print ("  ...")
		print (json_object["pulse_info"])

	except KeyError:
		print ("[!] Error")
		print ("[!] Endpoint Not Found")


def DomainNameIndicator():
	#OTX Api For Domain Indicator -> /api/v1/indicators/domain/{domain}/{section}
	
	try:

		print ("Please Enter A Domain Name")
		print ("Example: ExampleWeb.com")
		DomainName = input("> ")


		DomainAPI = "https://otx.alienvault.com//api/v1/indicators/domain/{0}".format(DomainName)
		output = requests.get(url=DomainAPI,headers=headers).content
		json_object = json.loads(output)

		print ("[+]: Indicator: {0}".format(json_object["indicator"]))
		print ("[+]: Type Of Indicator: {0}".format(json_object["type"]))
		print ("  Waiting For Pulses Info...")
		time.sleep(1)
		print ("  Pulses Info Resualt:")
		print ("  ...")
		print (json_object["pulse_info"])
	except KeyError:
		print ("[!] Error")
		print ("[!] Endpoint Not Found")



def URLIndicator():
	#OTX Api For URL Indicator -> /api/v1/indicators/url/{url}/{section}
	
	try:

		print ("Please Enter A URL")
		print ("Example: http://Example.com/cert/")
		Url = input("> ")

		UrlAPI = "https://otx.alienvault.com//api/v1/indicators/url/{0}".format(Url)
		output = requests.get(url=UrlAPI,headers=headers).content
		json_object = json.loads(output)

		print ("[+]: Indicator: {0}".format(Url))
		print ("[+]: Type Of Indicator: {0}".format("URL"))
		print ("  Waiting For Pulses Info...")
		time.sleep(1)
		print ("  Pulses Info Resualt:")
		print ("  ...")
		print (json_object["pulse_info"])
	except KeyError:
		print ("[!] Error")
		print ("[!] EndPoint Not Found")


def HostNameIndicator():
	#OTX Api For HostName Indicator -> /api/v1/indicators/hostname/{hostname}/{section}

	try: 

		print ("Please Enter A HostName")
		print ("Example: Example.Test-gte.org.br")
		HostName = input("> ")

		HostNameAPI = "https://otx.alienvault.com///api/v1/indicators/hostname/{0}".format(HostName)
		output = requests.get(url=HostNameAPI,headers=headers).content
		json_object = json.loads(output)

		print ("[+]: Indicator: {0}".format(json_object["indicator"]))
		print ("[+]: Type Of Indicator: {0}".format(json_object["type"]))
		print ("  Waiting For Pulses Info...")
		time.sleep(1)
		print ("  Pulses Info Resualt:")
		print ("  ...")
		print (json_object["pulse_info"])
	except KeyError:
		print ("[!] Error")
		print ("[!] HosTName Not Found")


def FileHashIndicator():
	#OTX Api For Hash Indicator -> /api/v1/indicators/file/{file_hash}/{section}
	
	try:

		print ("Please Enter A Hash")
		print ("Example: c1ffd59ce53351db4cb6a4a3c4428c7d")
		FileHash = input("> ")

		HashApi = "https://otx.alienvault.com//api/v1/indicators/file/{0}".format(FileHash)
		output = requests.get(url=HashApi,headers=headers).content
		json_object = json.loads(output)

		print ("[+]: Indicator: {0}".format(json_object["indicator"]))
		print("[+]: Type Of Indicator: {0}".format(json_object["type"]))
		print ("  Waiting For Pulses Info...")
		time.sleep(1)
		print ("  Pulses Info Resualt:")
		print ("  ...")
		print (json_object["pulse_info"])

	except KeyError:
		print ("[!] Error")
		print ("[!] File Hash Not Found")




def CVEIndicator():
	#OTX Api For Hash Indicator -> /api/v1/indicators/file/{file_hash}/{section}

	try:
		print ("Please Enter A CVE")
		print ("Example: CVE-2021-43890")
		CVEID = input("> ")

		CVEAPI = "https://otx.alienvault.com//api/v1/indicators/file/{0}".format(CVEID)
		output = requests.get(url=CVEAPI,headers=headers).content
		json_object = json.loads(output)

		print ("[+]: Indicator: {0}".format(json_object["indicator"]))
		print ("[+]: Type Of Indicator: {0}".format(json_object["type"]))
		print ("  Waiting For Pulses Info...")
		time.sleep(1)
		print ("  Pulses Info Resualt:")
		print ("  ...")
		print (json_object["pulse_info"])
	except KeyError:
		print ("[!] Error")
		print ("[!] CVE Not Found")



if __name__ == '__main__':
	while True:
		try:
			IndicatorNumber = int(input("> "))
		except KeyboardInterrupt:
			sys.exit("[!]Exited")
		if IndicatorNumber == 1:
			IPv4Indicator()
		if IndicatorNumber == 2:
			IPv6Indicator()
		if IndicatorNumber == 3:
			DomainNameIndicator()
		if IndicatorNumber == 4:
			URLIndicator()
		if IndicatorNumber == 5:
			HostNameIndicator()
		if IndicatorNumber == 6:
			CVEIndicator()
		if IndicatorNumber == 7:
			FileHashIndicator()
