
import dns.resolver

from errbot import BotPlugin, botcmd


class TeamCyrmu(BotPlugin):

	_IP_API = 'origin.asn.cymru.com'
	_ASN_API = 'asn.cymru.com'

	@botcmd(admin_only=False)
	def ip2asn(self, msg, args):
		'''Lookup an IP address in Team Cymru's IP ASN database.'''

		ip = args.strip()
		reverse_ip = '.'.join(reversed(ip.split('.')))
		try:
			answers = dns.resolver.query('%s.%s' % (reverse_ip, self._IP_API))
		except dns.resolver.NXDOMAIN:
			return "Invalid IP or IP not found."
		ip_answer = str(answers[0])
		ip_fields = ip_answer.split('|')
		ip_fields = [field.strip().strip('"') for field in ip_fields]

		asn = ip_fields[0]
		subnet = ip_fields[1]
		country = ip_fields[2]
		issuer = ip_fields[3]

		try:
			answers = dns.resolver.query('AS%s.%s' % (ip_fields[0], self._ASN_API))
		except dns.resolver.NXDOMAIN:
			return "Error occurred on ASN lookup."

		asn_answer = answers[0]
		asn_fields = asn_answer.split('|')
		asn_fields = [field.strip().strip('"') for field in asn_fields]

		registry_date = asn_fields[3]
		registrant = asn_fields[4]

		return '''
		```
		Subnet: %s
		Registrant: %s
		AS: %s
		Country: %s
		Issuer: %s
		Registry Date: %s
		```
		''' % (subnet, 
			registrant,
			asn,
			country,
			issuer,
			registry_date)