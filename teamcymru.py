import dns.resolver
import datetime

from errbot import BotPlugin, botcmd
from collections import namedtuple

OriginReply = namedtuple('OriginReply', 'asn subnet country issuer registry_date')
ASReply = namedtuple('ASReply', 'asn country issuer registry_date registrant')
MHRReply = namedtuple('MHReply', 'ts detection_rate')

class TeamCyrmu(BotPlugin):

	_IP_API = 'origin.asn.cymru.com'
	_ASN_API = 'asn.cymru.com'
	_MHR_API = 'malware.hash.cymru.com'

	@botcmd(admin_only=False)
	def ip2asn(self, msg, args):
		'''Lookup an IP address in Team Cymru's IP ASN database.'''

		ip = args
		reverse_ip = '.'.join(reversed(ip.split('.')))
		try:
			answers = dns.resolver.query('%s.%s' % (reverse_ip, self._IP_API), 'TXT')
		except dns.resolver.NXDOMAIN:
			return 'Invalid IP or IP not found.'
		answer = answers[0].to_text().strip('"')
		ip_answer = OriginReply(*[field for field in answer.split(' |')])
		#self.log.info('received answer: %s' % (ip_answer))

		try:
			answers = dns.resolver.query('AS%s.%s' % (ip_fields.asn, self._ASN_API), 'TXT')
		except dns.resolver.NXDOMAIN:
			return 'Error occurred on ASN lookup.'
		answer = answers[0].to_text().strip('"')
		asn_answer = ASReply(*[field for field in answer.split(' |')])
		#self.log.info('received answer: %s' % (asn_answer))
		return '''
		```
		Subnet: 		%s
		Registrant: 	%s
		AS: 			%s
		Country: 		%s
		Issuer: 		%s
		Registry Date: 	%s
		```
		''' % (ip_answer.subnet, 
			asn_answer.registrant,
			ip_answer.asn,
			ip_answer.country,
			ip_answer.issuer,
			ip_answer.registry_date)

	@botcmd(admin_only=False)
	def mhr(self, msg, args):
		'''Lookup a file in the malware hash registry.'''

		ahash = args
		try:
			answers = dns.resolver.query('%s.%s' % (ahash, self._MHR_API), 'TXT')
		except dns.resolver.NXDOMAIN:
			return 'File not found in MHR.'

		answer = answers[0].to_text().strip('"')
		answer = MHRReply(*[field for field in answer.split(' ')])

		ts = datetime.datetime.fromtimestamp(int(answer.ts))

		return 'Malicious file %s last seen %s with a detection rate of %s' % (
										args,
										ts,
										answer.detection_rate
										)
