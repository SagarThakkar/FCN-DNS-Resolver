import sys
import dns.name
import dns.message
import dns.query
import dns.flags
import dns.opcode
import string
import time
import dns.rcode
from mydnsresolver import get_authoritative_nameserver
f = open("mydig_output.txt","wb")

starttime = 0
domain = sys.argv[1]
name_server = get_authoritative_nameserver(domain,nsrecieved=True)
print " got control back to dig"
Typed = sys.argv[2]
#print Typed
ADDITIONAL_RDCLASS = 65535
#global starttime
starttime = time.time()
domain = dns.name.from_text(domain)
if not domain.is_absolute():
    domain = domain.concatenate(dns.name.root)

request = dns.message.make_query(domain, dns.rdatatype.from_text(Typed))
request.flags |= dns.flags.AD
request.find_rrset(request.additional, dns.name.root, ADDITIONAL_RDCLASS,
                   dns.rdatatype.OPT, create=True, force_unique=True)
try:
	response = dns.query.udp(request, name_server,timeout=5)
except dns.exception.Timeout:
	name_server='8.8.8.8'
	response= dns.query.udp(request, name_server,timeout=5)
#print response
Status = dns.rcode.to_text(response.rcode())
Opcode = dns.opcode.to_text(response.opcode())
f.write("Staus : %s " % Status)
f.write("\nOpcode: %s" % Opcode)

print "Status: ",Status
print "Opcode :",Opcode 
count = 0
for ns in response.answer:	
	count = count+ len(ns)	
	print ns
	f.write(str(ns))
Id = response.id
flags = dns.flags.to_text(response.flags)
quest = len(response.question)
autho = len(response.authority)
add = len(response.additional)
questresp = response.question
querytime = time.time()-starttime
f.write("\nId: %s "% Id)
f.write("	flags: %s"% flags)
f.write("\nNumber of questions : %s" % quest)
f.write("	Number of answers : %s"% count)
f.write("\nNumber of Authority : %s" % autho)
f.write("	Number of Additional:%s" % add)
f.write("\n Question: %s" % questresp)
f.write("\nQuerytime: %s msec" % querytime)
print "Id : {0}".format(response.id) , "flags :" ,dns.flags.to_text(response.flags)
print "Number of Question: ",len(response.question) , "Number of Answers: {0}	".format(count)
print  "Authority: {0}".format(len(response.authority)),  "Additional: {0}	".format(len(response.additional))
print "Question: " , response.question 
print "Query time: {0:.2f}msec" .format(time.time()-starttime) 
f.close()
