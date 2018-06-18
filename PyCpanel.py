import requests
import logging

# Cpanel API Documentation here:
# https://documentation.cpanel.net/display/DD/Guide+to+cPanel+API+2

class Record(object):
	def __init__(self, domain, attributes):
		self.domain = domain
		self.attributes = attributes
		self.attributes.update({"domain": domain})


	def __getattr__(self, name):
		if name in self.attributes:
			return self.attributes[name]
		return None

	def __repr__(self):
		return "({name}){obj_type}".format(name=self.attributes.get("name"), obj_type=str(self.__class__))


class TXTRecord(Record):
	def __init__(self, domain, name, value, ttl):
		attrs = {
			"class": "IN",
			"type": "TXT",
			"name": name,
			"ttl": ttl,
			"txtdata": value
		}
		super(TXTRecord, self).__init__(domain, attrs)

class ARecord(Record):
	def __init__(self, domain, name, address, ttl):
		attrs = {
			"class": "IN",
			"type": "A",
			"name": name,
			"ttl": ttl,
			"address": address
		}
		super(ARecord, self).__init__(domain, attrs)


class CpanelClient(object):
	"""
	Barebones API to progromatically add and delete Zone records for cPanel account.
	"""

	def __init__(self, host, port, username, password, verbose=True):
		# basic params
		self.host = host
		self.username = username
		self.password = password

		# http connection
		self.http = requests.Session()

		# cpanel variables
		self.base_url = "https://{host}:{port}/".format(host=self.host, port=port)
		self.cpanel_api_url = "{base_url}{security_token}/json-api/cpanel"
		self.security_token = None
		self.cpanel_jsonapi_version = 2

		# state
		self.zones = {}

		# logging
		logging.basicConfig()
		self.logger = logging.getLogger(__name__)
		self.logger.setLevel(logging.DEBUG)
		if verbose:
			self.logger.setLevel(logging.INFO)

		# Initialize client state
		self.login()
		self.get_domains()

	def login(self):
		"""
		Logs in using authentication settings provided in CpanelClient and stores the cPanel security
		token.
		"""

		login_url = self.base_url + "login/?login_only=1"
		data = {
			"user": self.username,
			"pass": self.password
		}
		r = self.http.post(login_url, data=data)
		if r.status_code == 200:
			r = r.json()
			if r["status"]:
				self.security_token = r["security_token"]
				self.cpanel_api_url = self.cpanel_api_url.format(base_url=self.base_url, security_token=self.security_token)
				self.logger.info("Login successful.")
		else:
			raise Exception("Login failed")

	def is_logged_in(self):
		"""
		Returns if user is logged in based on precense of cPanel security token.
		"""

		return self.security_token != None

	def cpanel_api_params(self, module, function):
		"""
		Returns the default headers used for cPanel API v2.
		"""

		return {
			"cpanel_jsonapi_version": self.cpanel_jsonapi_version,
			"cpanel_jsonapi_module": module,
			"cpanel_jsonapi_func": function
		}

	def get_domains(self):
		"""
		Gets all the domains configurable for this cPanel account.
		"""

		params = self.cpanel_api_params("DomainLookup", "getbasedomains")

		r = self.http.get(self.cpanel_api_url, params=params)
		if r.status_code == 200:
			result = r.json()["cpanelresult"]
			if result["event"]["result"]:
				for domain in result["data"][0]["domain"].split(","):
					domain = domain.strip()
					self.get_records(domain)
				return True
		raise Exception("Failed to get domains")

	def get_records(self, domain, customonly=1):
		"""
		Gets and updates the records for a specified DNS zone. Defaults to user defined zones only to
		limit the number of zones that the user has to filter though.
		"""

		params = self.cpanel_api_params("ZoneEdit", "fetchzone_records")
		params.update({
			"domain": domain,
			"customonly": customonly
			})

		r = self.http.get(self.cpanel_api_url, params=params)
		if r.status_code == 200:
			result = r.json()["cpanelresult"]
			if result["event"]["result"]:
				zone_records = []
				for record_attrs in result["data"]:
					zone_records.append(Record(domain, record_attrs))
				self.zones[domain] = zone_records
				return True
		raise Exception("Failed to get records for domain: {domain}".format(domain=domain))

	def add_record(self, record):
		"""
		Checks if domain in Record object is a domain accessible by this cPanel account and adds it.
		"""

		if record.domain in self.zones:
			params = self.cpanel_api_params("ZoneEdit", "add_zone_record")
			params.update(record.attributes)

			r = self.http.get(self.cpanel_api_url, params=params)
			if r.status_code == 200:
				result = r.json()["cpanelresult"]
				if result["event"]["result"]:
					self.logger.info("Record: {record} added successfully".format(record=record.name))
					self.get_records(record.domain)
					return True
			raise Exception("Failed to add record for domain: {domain}".format(domain=record.domain))
		raise Exception("Domain in record: {domain} not a domain managed by this cPanel account".format(domain=record.domain))

	def del_record(self, record):
		"""
		Checks if domain in Record object is a domain accessible by this cPanel account and deletes it.
		"""

		if record.domain in self.zones:
			params = self.cpanel_api_params("ZoneEdit", "remove_zone_record")
			params.update({
				"domain": record.domain,
				"line": record.line
				})

			r = self.http.get(self.cpanel_api_url, params=params)
			if r.status_code == 200:
				result = r.json()["cpanelresult"]
				if result["event"]["result"]:
					if result["data"][0]["result"]["status"]:
						self.logger.info("Record: {record} removed successfully".format(record=record.name))
						self.get_records(record.domain)
						return True
			raise Exception("Failed to remove zone for domain: {domain}".format(domain=record.domain))
		raise Exception("Domain in record: {domain} not a domain managed by this cPanel acount".format(domain=record.domain))

	def add_TXT_record(self, domain, name, value, ttl=14400):
		"""
		Easier wrapper function that creates and adds a TXT Record object with specified parameters.
		"""

		txt = TXTRecord(domain, name, value, ttl=ttl)
		self.add_record(txt)

	def add_A_record(self, domain, name, address, ttl=14400):
		"""
		Easier wrapper function that creates and adds an A Record object with specified parameters.
		"""

		a = ARecord(domain, name, address, ttl=ttl)
		self.add_record(a)

	def find_records_by_name(self, domain, name):
		"""
		Easier wrapper function that finds all records with given name and returns them as a list.
		Names are stored with an extra period at the end so comparison omits the '.' at the end of the Record name.
		"""

		results = []
		for record in self.zones[domain]:
			if name == record.name[:-1]:
				results.append(record)
		return results



