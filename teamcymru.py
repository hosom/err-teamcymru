
import dns.resolver

from errbot import BotPlugin, botcmd


class TeamCyrmu(BotPlugin):

	_IP_API = 'origin.asn.cymru.com'
	_ASN_API = 'asn.cymru.com'
	_MHR_API = 'malware.hash.cymru.com'

	@botcmd(admin_only=False)
	def ip2asn(self, msg, args):
		'''Lookup an IP address in Team Cymru's IP ASN database.'''

		ip = args.strip()
		reverse_ip = '.'.join(reversed(ip.split('.')))
		try:
			answers = dns.resolver.query('%s.%s' % (reverse_ip, self._IP_API), 'TXT')
		except dns.resolver.NXDOMAIN:
			return 'Invalid IP or IP not found.'
		ip_answer = str(answers[0])
		self.log.info('received answer: %s' % (ip_answer))
		ip_fields = ip_answer.split('|')
		ip_fields = [field.strip().strip('"') for field in ip_fields]

		asn = ip_fields[0]
		subnet = ip_fields[1]
		country = ip_fields[2]
		issuer = ip_fields[3]

		try:
			answers = dns.resolver.query('AS%s.%s' % (ip_fields[0], self._ASN_API), 'TXT')
		except dns.resolver.NXDOMAIN:
			return 'Error occurred on ASN lookup.'

		asn_answer = str(answers[0])
		asn_fields = asn_answer.split('|')
		asn_fields = [field.strip().strip('"') for field in asn_fields]

		registry_date = asn_fields[3]
		registrant = asn_fields[4]

		return '''
		```
		Subnet: 		%s
		Registrant: 	%s
		AS: 			%s
		Country: 		%s
		Issuer: 		%s
		Registry Date: 	%s
		```
		''' % (subnet, 
			registrant,
			asn,
			country,
			issuer,
			registry_date)

	@botcmd(admin_only=False)
	def mhr(self, msg, args):
		'''Lookup a file in the malware hash registry.'''

		ahash = args
		try:
			answers = dns.resolver.query('%s.%s' % (ahash, self._MHR_API), 'TXT')
		except dns.resolver.NXDOMAIN:
			return 'File not found in MHR.'

		answer = str(answers[0])
		answer_fields = answer.split(' ')
		answer_fields = [field.strip().strip('"') for field in answer_fields]


		ts = datetime.datetime.fromtimestamp(int(answer_fields[0]))
		detection_rate = answer_fields[1]

		return 'Malicious file %s last seen %s with a detection rate of %s' % (
										args,
										ts,
										detection_rate
										)
