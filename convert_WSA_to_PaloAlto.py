#!/usr/bin/env python
import xmltodict
from xml.parsers.expat import ParserCreate, ExpatError, errors
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

import pandas as pd

import sys
import re
import json

import collections
orderedDict = collections.OrderedDict()
from collections import OrderedDict

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
from collections import defaultdict

from paramiko import SSHClient
from scp import SCPClient
import paramiko

def print_sec_rule_neu(rule_name,url_list,desc,source):
	print("\n")
	print("del rulebase security rules URL_Filter_%s source" % (rule_name))
	print("set rulebase security rules URL_Filter_%s source any" % (rule_name))
	print("del rulebase security rules URL_Filter_%s source-user" % (rule_name))
	print("set rulebase security rules URL_Filter_%s source-user %s" % (rule_name, str(source).lower()))
	print("del rulebase security rules URL_Filter_%s category" % (rule_name))
	print("set rulebase security rules URL_Filter_%s category [ %s ]" % (rule_name,' '.join(sorted(url_list, key=str.lower))))
	print("set rulebase security rules URL_Filter_%s description \"%s\"" % (rule_name,str(desc).replace("\n", " ")))

def print_sec_rule_time_neu(rule_name,url_list,desc,source):
	print("\n")
	print("del rulebase security rules URL_Filter_%s_time source" % (rule_name))
	print("set rulebase security rules URL_Filter_%s_time source any" % (rule_name))
	print("del rulebase security rules URL_Filter_%s_time source-user" % (rule_name))
	print("set rulebase security rules URL_Filter_%s_time source-user %s" % (rule_name, str(source).lower()))
	print("del rulebase security rules URL_Filter_%s_time category" % (rule_name))
	print("set rulebase security rules URL_Filter_%s_time category [ %s ]" % (rule_name,' '.join(sorted(url_list, key=str.lower))))
	print("del rulebase security rules URL_Filter_%s_time schedule" % (rule_name))
	print("set rulebase security rules URL_Filter_%s_time schedule Non_Working_Hours" % (rule_name))
	print("set rulebase security rules URL_Filter_%s_time description \"%s\"" % (rule_name,str(desc).replace("\n", " ")))

def print_sec_rule(rule_name,url_list,desc,source):
	print("\n")
	print("set rulebase security rules URL_Filter_%s from \"palo zone 1\"" % (rule_name))
	print("set rulebase security rules URL_Filter_%s to palo_zone_2" % (rule_name))
	print("set rulebase security rules URL_Filter_%s source %s" % (rule_name, str(source).lower()))
	print("set rulebase security rules URL_Filter_%s source-user %s" % (rule_name, str(source).lower()))
	print("set rulebase security rules URL_Filter_%s category [ %s ]" % (rule_name,' '.join(sorted(url_list, key=str.lower))))
	print("set rulebase security rules URL_Filter_%s description \"%s\"" % (rule_name,str(desc).replace("\n", " ")))
	print("set rulebase security rules URL_Filter_%s destination any" % (rule_name))
	print("set rulebase security rules URL_Filter_%s application any" % (rule_name))
	print("set rulebase security rules URL_Filter_%s service http_https" % (rule_name))
	print("set rulebase security rules URL_Filter_%s action allow" % (rule_name))
	print("set rulebase security rules URL_Filter_%s log-start yes" % (rule_name))
	print("set rulebase security rules URL_Filter_%s profile-setting profiles file-blocking Block_Mandatory" % (rule_name))
	print("set rulebase security rules URL_Filter_%s profile-setting profiles virus Anti-Virus" % (rule_name))
	print("set rulebase security rules URL_Filter_%s profile-setting profiles spyware Anti-Spyware" % (rule_name))
	print("set rulebase security rules URL_Filter_%s profile-setting profiles vulnerability Vulnerability" % (rule_name))
	print("set rulebase security rules URL_Filter_%s profile-setting profiles wildfire-analysis Forward-Web" % (rule_name))
	print("set rulebase security rules URL_Filter_%s tag web_filter" % (rule_name))
	print("set rulebase security rules URL_Filter_%s log-setting Syslog" % (rule_name))
	print("set rulebase security rules URL_Filter_%s negate-destination no" % (rule_name))
	print("set rulebase security rules URL_Filter_%s group-tag web_filter" % (rule_name))

def print_sec_rule_time(rule_name,url_list,desc,source):
	print("\n")
	print("set rulebase security rules URL_Filter_%s from \"palo zone 1\"" % (rule_name))
	print("set rulebase security rules URL_Filter_%s to palo_zone_2" % (rule_name))
	print("set rulebase security rules URL_Filter_%s_time source-user %s" % (rule_name, str(source).lower()))
	print("set rulebase security rules URL_Filter_%s_time category [ %s ]" % (rule_name,' '.join(sorted(url_list, key=str.lower))))
	print("set rulebase security rules URL_Filter_%s_time schedule Non_working_Hours" % (rule_name))
	print("set rulebase security rules URL_Filter_%s_time description \"%s\"" % (rule_name,str(desc).replace("\n", " ")))
	print("set rulebase security rules URL_Filter_%s_time destination any" % (rule_name))
	print("set rulebase security rules URL_Filter_%s_time application any" % (rule_name))
	print("set rulebase security rules URL_Filter_%s service http_https" % (rule_name))
	print("set rulebase security rules URL_Filter_%s_time action allow" % (rule_name))
	print("set rulebase security rules URL_Filter_%s_time log-start yes" % (rule_name))
	print("set rulebase security rules URL_Filter_%s profile-setting profiles file-blocking Block_Mandatory" % (rule_name))
	print("set rulebase security rules URL_Filter_%s_time profile-setting profiles virus Anti-Virus" % (rule_name))
	print("set rulebase security rules URL_Filter_%s_time profile-setting profiles spyware Anti-Spyware" % (rule_name))
	print("set rulebase security rules URL_Filter_%s_time profile-setting profiles vulnerability Vulnerability" % (rule_name))
	print("set rulebase security rules URL_Filter_%s_time profile-setting profiles wildfire-analysis Forward-Web" % (rule_name))
	print("set rulebase security rules URL_Filter_%s tag web_filter" % (rule_name))
	print("set rulebase security rules URL_Filter_%s_time log-setting Syslog" % (rule_name))
	print("set rulebase security rules URL_Filter_%s_time negate-destination no" % (rule_name))
	print("set rulebase security rules URL_Filter_%s group-tag web_filter" % (rule_name))
	print("set rulebase security rules URL_Filter_%s_time schedule Working_Hours" % (rule_name))

def print_sec_rule_mod(rule_name,url_list,desc,source):
	print("\n")
	print("del rulebase security rules URL_Filter_%s category" % (rule_name))
	print("set rulebase security rules URL_Filter_%s category [ %s ]" % (rule_name,' '.join(sorted(url_list, key=str.lower))))
	print("del rulebase security rules URL_Filter_%s description" % (rule_name))
	print("set rulebase security rules URL_Filter_%s description \"%s\"" % (rule_name,str(desc).replace("\n", " ")))

def print_sec_rule_time_mod(rule_name,url_list,desc,source):
	print("\n")
	print("del rulebase security rules URL_Filter_%s_time category" % (rule_name))
	print("set rulebase security rules URL_Filter_%s_time category [ %s ]" % (rule_name,' '.join(sorted(url_list, key=str.lower))))
	print("del rulebase security rules URL_Filter_%s_time description" % (rule_name))
	print("set rulebase security rules URL_Filter_%s_time description \"%s\"" % (rule_name,str(desc).replace("\n", " ")))

### Prereq I
###
### Open WSA Configuration as dictionary
fd = open('<WSA_CONFIGURATION.XML>', 'r', encoding='utf-8')
doc = xmltodict.parse(fd.read())


### Prereq II
###
### https://www.cisco.com/c/dam/en/us/td/docs/security/wsa/wsa_10-0/WSA_10-5-1_UserGuide.pdf
### XLSX contains (PredifinedURL,Codes) mapping
### This is required as WSA XML config references Predefined URL categories with codes instead names
df = pd.read_excel('input.xlsx', sheet_name='URL_Cate_Mapping', index_col='acl_code', na_values=['NA'])
#name = df.loc[df['acl_code'] == 1049]
#print(df.loc[1049, 'acl_name'])

### Prereq III
###
fido = pd.read_excel('input.xlsx', sheet_name='Cisco_Palo', index_col='Cisco', na_values=['NA'])
#print(fido.loc['Arts','Palo'])
#print(fido.loc['Arts','Palo2'])

### Custom URL Categories (key is 10 digit integer)
dict={}
### Create Dictionary with Basic Info on every Group(Access policy) (key is 4digit integer)
basic_info={}
### Create Dictionary with detailed info of Custom and Predefined URLs for every Group(Access Policy) (key is 4digit integer)
acl_dict={}


### Part I
###
### Get a Custom URL Category and a list of associated URLs
for i in doc['config']['wga_config']['prox_acl_custom_categories']['prox_acl_custom_category']:
	code=i['prox_acl_custom_category_code']
	abbrev=i['prox_acl_custom_category_abbrev'] 
	name=i['prox_acl_custom_category_name']
	#print( ("%s,%s;%s") % (code,abbrev,name) )
	
	dict[code]={}
	inner_list=[]
	inner_dict = {}

	### list of URLs	
	URL_X = i['prox_acl_custom_category_servers']['prox_acl_custom_category_server']
	### type(URL_X) == 'list' won't work!
	### If more than one URL ...
	if type(URL_X) is list:
		for URL in URL_X:
			inner_list.append(URL)		
	### If only one URL ...
	else:
		inner_list.append(URL_X)
	
	### Check Advanced section which may contain additional URLs, regex, etc.
	### Note: REGEX validity is ensured by containing at least one DOT (".")
	if i['prox_acl_custom_category_regex_list'] is not None:
		URL_Y = i['prox_acl_custom_category_regex_list']['prox_acl_custom_category_regex']
		if type(URL_Y) is list:
			for URL in URL_Y:
				if re.findall("\.", URL):
					inner_list.append(URL)
		### If only one URL ...
		else:
			if re.findall("\.", URL_Y):
				inner_list.append(URL_Y)
	
	### inner_dict will contain abbreviation of Custom URL Category, Full Name and *list* of URLs
	inner_dict.update(abbrev=abbrev)
	inner_dict.update(name=name)
	inner_dict.update(URLs=inner_list)
	
	### Store inner_dictionary inside a dictionary
	### 'dict' key is Custom_URL_Code (random numberic value)
	dict[code]=inner_dict


### Part II
###
### Get Access Policy
### (1)Source Users === Identification Profile
### (2)Custom URL (one or more)
### (3)Predefined URL Category (one or more)
### For each Access Policy get a list of
###	0) Basic Info like name, ID, etc.
###	1) ALL Predefined URL Categories
###	2) ONLY those Custom URL Categories for which Global Settings are overridden
for i in doc['config']['wga_config']['prox_acl_policy_groups']['prox_acl_group']:
	inner_list=[]
	acl_list_of_predef_urls=[]

	# 0) Get Basic Access Policy Info like ID, Desc, UID
	if 'prox_acl_group_id' in i.keys(): 
		acl_id = i['prox_acl_group_id']
	else:
		acl_id = 'None'
	if 'prox_acl_group_uid' in i.keys():
               	acl_uid = i['prox_acl_group_uid']
	else:
		acl_uid = 0
	if 'prox_acl_group_description' in i.keys():
		acl_desc = i['prox_acl_group_description']
	else:
		acl_desc = "No Description"
	
	inner_list.append(acl_id)
	inner_list.append(acl_desc)
	# Print basic Access Policy INFO
	# UID is the key. 
	# Note: UID is 4 digit integer, ** which might overlap with Predefined URL Category ID **
	#print("\n\n",acl_id,acl_uid,acl_desc)
	#basic_info[acl_uid]=inner_lists
	
	# 1) Get info on ALL Predefined URL categories and how are they used inside an access policy
	if 'prox_acl_group_firestone_actions' in i.keys() and 'prox_acl_group_firestone_action' in i['prox_acl_group_firestone_actions'].keys():
		for k in i['prox_acl_group_firestone_actions']['prox_acl_group_firestone_action']:
			if type(k) is OrderedDict:
				acl_predef_cat_id = k['category_id']
				acl_predef_cat_action = k['category_action']

				try:
					#print("1>", df.loc[int(acl_predef_cat_id), 'acl_name'],acl_predef_cat_id,acl_predef_cat_action)
					category_name = df.loc[int(acl_predef_cat_id), 'acl_name']
					#print("1> DONE")

				except:
					#print("2>>>> 1 failed so we are here",(dict.get(int(acl_predef_cat_id))),acl_predef_cat_id,acl_predef_cat_action)
					try:
						variable = df.loc[int(acl_predef_cat_id), 'acl_name']
						#print(variable)
					except:
						break
					#if df.loc[int(acl_predef_cat_id), 'acl_name']:
					#	category_name = df.loc[int(acl_predef_cat_id), 'acl_name']
					#	new_category_name = fido.loc[category_name,'Palo']
					#	print(category_name,"->",new_category_name)
					#	quit()
					#else:
					#	print("OOOOO")
					#	quit()
				finally:
					#print("Finally working with:", acl_predef_cat_id,acl_predef_cat_action)
					pass
				
				if [acl_predef_cat_id,acl_predef_cat_action] not in acl_list_of_predef_urls:
					acl_list_of_predef_urls.append([acl_predef_cat_id,acl_predef_cat_action])
		acl_dict[acl_uid]=acl_list_of_predef_urls

	# 3) Get info ONLY on those Custom URL categories which are used inside an access policy (these categories OVERRIDE Global settings)
	# Custom URL Categories that do appear in this section override Global Policy settings by Allowing or Denying something 'extra'
	if 'prox_acl_group_customcat_actions' in i.keys() and 'prox_acl_group_customcat_action' in i['prox_acl_group_customcat_actions'].keys():
		for p in i['prox_acl_group_customcat_actions']['prox_acl_group_customcat_action']:
			if type(p) is OrderedDict:
				acl_custom_cat_id = p['category_id']
				acl_custom_cat_action = p['category_action']
				#print((dict.get(acl_custom_cat_id))['name'],acl_custom_cat_id,acl_custom_cat_action)
			if type(p) is str:
				#print("P2",p)
				#print(type(p))
				acl_custom_cat_id = i['prox_acl_group_customcat_actions']['prox_acl_group_customcat_action']['category_id']
				acl_custom_cat_action = i['prox_acl_group_customcat_actions']['prox_acl_group_customcat_action']['category_action']
				#print((dict.get(acl_custom_cat_id))['name'],acl_custom_cat_id,acl_custom_cat_action)
			#if acl_custom_cat_id not in acl_list_of_predef_urls:
			if [acl_custom_cat_id,acl_custom_cat_action] not in acl_list_of_predef_urls:
				acl_list_of_predef_urls.append([acl_custom_cat_id,acl_custom_cat_action])

		acl_dict[acl_uid]=acl_list_of_predef_urls

	# Get info on source users of an access group
	if 'prox_acl_group_identities' in i.keys():
		source_user = i['prox_acl_group_identities']['prox_acl_group_identity']
		

		# If result is type dictionary
		if isinstance(i['prox_acl_group_identities']['prox_acl_group_identity'], OrderedDict):
			#print("Source Users:  >>>",(i['prox_acl_group_identities']['prox_acl_group_identity']).get('prox_acl_group_identity_name'))
			inner_list.append( (i['prox_acl_group_identities']['prox_acl_group_identity']).get('prox_acl_group_identity_name') )
			basic_info[acl_uid]=inner_list
						
		# If result is list: select first [0] element of that list and result is - dictionary!
		if isinstance(i['prox_acl_group_identities']['prox_acl_group_identity'], list):

			# What I'm looking for here is AD Group of source users. It might be stored in different places so therefore:
			try:
				#print(("Source Users: ",i['prox_acl_group_identities']['prox_acl_group_identity'][0]['prox_acl_group_auth_groups']['prox_acl_group_auth_groups_of_realm']['prox_acl_group_auth_realm_groups']['prox_acl_group_auth_group']))
				inner_list.append(i['prox_acl_group_identities']['prox_acl_group_identity'][0]['prox_acl_group_auth_groups']['prox_acl_group_auth_groups_of_realm']['prox_acl_group_auth_realm_groups']['prox_acl_group_auth_group'])
				basic_info[acl_uid]=inner_list

			except AttributeError as error:
				#print(("Source Users: ",i['prox_acl_group_identities']['prox_acl_group_identity'][0]['prox_acl_group_identity_name']))
				inner_list.append( i['prox_acl_group_identities']['prox_acl_group_identity'][0]['prox_acl_group_identity_name'] )
				basic_info[acl_uid]=inner_list

			except TypeError as error:
				#print(("Source Users: ",i['prox_acl_group_identities']['prox_acl_group_identity'][0]['prox_acl_group_identity_name']))
				inner_list.append( i['prox_acl_group_identities']['prox_acl_group_identity'][0]['prox_acl_group_identity_name'] )
				basic_info[acl_uid]=inner_list

#print("\n\n\n Custom URL Categories")
#print(dict.get(acl_custom_cat_id)['name'],"--->",dict.get(acl_custom_cat_id)['URLs'])

'''
	for k in i:
		if k == 'prox_acl_custom_category_abbrev':
			inner_dict={}
			key = None
			key=i[k]
			dict[key]={}
		if k == 'prox_acl_custom_category_servers':			
			for item in i[k]['prox_acl_custom_category_server']:
				ip = '<IP_ADDRESS_OF_PA_OR_PANORAMA>'
				api_key = '....'
				url = """https://%s/api/9.0/?key=%s&type=op&cmd=<test><url>%s</url></test>""" % (ip,api_key,item)
				r = requests.get(url,verify=False)
				r_ = xmltodict.parse(r.text)
				res = r_['response']['result']
				resu = re.split(' ',res)
				inner_list = []; inner_list.append(resu[-4]);  inner_list.append(resu[-3])
				inner_dict[item]=inner_list
				dict[key]=inner_dict 
for CUC in dict:
	for URL in dict[CUC]:
		print(("%s	%s	%s	%s") % (CUC, URL, dict[CUC][URL][0], dict[CUC][URL][1]) )
'''



### Create Custom URL Category on Palo based on basic_info and acl_dict dictionary
for m in basic_info:
	#print("\n",basic_info[m])
	url_list_allowed = []
	url_list_time = []
	inner_dict_time={}
	inner_dict_url={}
	for n in acl_dict[m]:
		#print(n, df.loc[n[0],'acl_name'])
		#print(n)
		#print(">>",df.loc[1024, 'acl_name'])
		url_id = int(n[0])

		### Predefined URL
		if len(str(url_id)) == 4:
			cisco_cat_name = df.loc[url_id, 'acl_name']
			palo_cat_name_01 = fido.loc[cisco_cat_name, 'Palo']
			palo_cat_name_02 = fido.loc[cisco_cat_name, 'Palo2']
			
			# Cisco category maps to only one Palo category (regular case!)
			if isinstance(palo_cat_name_02, float):
				#print('$ Cisco: %s Palo01: %s >> Action: %s' % (cisco_cat_name,palo_cat_name_01,n[1]))
				if n[1] == 'scan' and palo_cat_name_01 not in url_list_allowed:
					url_list_allowed.append(palo_cat_name_01)
				if n[1] == 'time' and palo_cat_name_01 not in url_list_time:
					url_list_time.append(palo_cat_name_01)
			
			# One Cisco URL category maps to 2 (two!) Palo categories according to Excel sheet
			if isinstance(palo_cat_name_02, str):
				#print(' $$ Cisco: %s Palo01: %s Palo02: %s >> Action: %s' % (cisco_cat_name,palo_cat_name_01,palo_cat_name_02,n[1]))
				if n[1] == 'scan':
					url_list_allowed.append(palo_cat_name_01)
					url_list_allowed.append(palo_cat_name_02)
				if n[1] == 'time':
					url_list_time.append(palo_cat_name_01)
					url_list_time.append(palo_cat_name_02)

		
		### Custom URL -- Format Custom URL the same as used in Palo Alto
		elif len(str(url_id)) == 10:
			#print(">> >> >>",dict[str(url_id)]['name'])
			c_url = dict[str(url_id)]['name']
			c_url = c_url.replace(" ", "_")
			c_url = "0_EXT_DYN_LIST_"+c_url
			url_list_allowed.append(c_url)
		
		### Something else which should result in error
		else:
			print("NOT_GOOD")
			quit()

	if url_list_time:
		print_sec_rule_time(basic_info[m][0],url_list_time,basic_info[m][1],basic_info[m][2])
		#print("set profiles custom-url-category %s_URL_Category_Time \"Category Match\"" % (basic_info[m][0]))
		#print("set profiles custom-url-category %s_URL_Category_Time list [ %s ]" % (basic_info[m][0],' '.join(url_list_time)))
		inner_dict_time['time']=url_list_time
		basic_info[m].append(inner_dict_time)

	if url_list_allowed:
		print_sec_rule(basic_info[m][0],url_list_allowed,basic_info[m][1],basic_info[m][2])
		#print("set profiles custom-url-category %s_URL_Category type \"Category Match\"" % (basic_info[m][0]))
		#print("set profiles custom-url-category %s_URL_Category list [ %s ]" % (basic_info[m][0],' '.join(url_list_allowed)))
		inner_dict_url['allowed']=url_list_allowed
		basic_info[m].append(inner_dict_url)


for m in basic_info:
	print(m,basic_info[m])

for m in dict:
	print(m,dict[m])
quit()

### Create HTML index.html file
w = open('./index.html', 'w')
w.write("<!DOCTYPE html>\n")
w.write("<html>\n")
w.write("  <head>\n")
w.write("    <!-- Metadata goes here -->\n")
w.write("  </head>\n")
w.write("  <body>\n")
w.write("  <h1>Palo Alto External Dynamic Lists</h1>\n")
for m in dict:
	full_name = dict[m].get('name')
	name = full_name.replace(' ', '_')
	w.write('    <a href="output/0_EXT_DYN_LIST_%s.txt">%s<br></a>\n' % (name,full_name) )
	f = open('output/0_EXT_DYN_LIST_%s.txt' % (name), 'w')
	print('set external-list 0_EXT_DYN_LIST_%s type url recurring five-minute' % name)
	print('set external-list 0_EXT_DYN_LIST_%s type url url http://<IP_ADDRESS_OF_SERVER_WHERE_PA_EDL_WILL_BE_STORED>/output/0_EXT_DYN_LIST_%s.txt' % (name,name))
	print('set external-list 0_EXT_DYN_LIST_%s type url description "%s"' % (name,full_name))
	for url in dict[m].get('URLs'):
		f.write(url)
		f.write("\n")
	f.close()
w.write("  </body>\n")
w.write("</html>\n")
w.close()


### Copy files to HTTP server from where PA will read
ssh = SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.load_system_host_keys()
ssh.connect('<IP_ADDRESS_OF_SERVER_WHERE_PA_EDL_WILL_BE_STORED>', username='username', password=None)

scp = SCPClient(ssh.get_transport())
print("\nCopying files to <IP_ADDRESS_OF_SERVER_WHERE_PA_EDL_WILL_BE_STORED>:/var/www/html/output/ ...")
scp.put('./output',recursive=True,  remote_path='/var/www/html/output')
scp.put('./index.html',recursive=True,  remote_path='/var/www/html/index.html')
scp.close()
print("Done.")


for m in basic_info:
	print(m,basic_info[m])
for m in dict:
	print(m,dict[m])
quit()

json_object = json.dumps(basic_info, indent = 4)
print("\n\n\n")
#print(json_object)
quit()