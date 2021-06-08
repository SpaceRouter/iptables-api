# iptables-api
[![Go Report Card](https://goreportcard.com/badge/github.com/SpaceRouter/iptables-api)](https://goreportcard.com/report/github.com/SpaceRouter/iptables-api)

GO REST API for iptables using jwt authentication

Compile:
--------
export GO111MODULE=on  
go build -o iptables-api

Run:
----
    ./iptables-api OR go run .

API List :
---------

**Chain:**

SHOW a chain content:

	const response = await fetch("http://127.0.0.1:8080/chain/{table}/{name}/", {
		method: "GET"
		headers: { "Authorization": "bearer token" }
		});

	curl -H 'Authorization: bearer token' -i -X GET http://127.0.0.1:8080/chain/{table}/{name}/

Return example:

	{
    	"Ok": true,
    	"Rules": [
        	{
            	"Mproto": "tcp",
            	"Pproto": "tcp",
            	"Dport": "3389",
            	"Dest": "192.168.1.60:3389"
        	},
        	{
            	"Mproto": "udp",
            	"Pproto": "udp",
            	"Dport": "32323",
            	"Dest": "193.23.23.24:9988"
        	}
    	]
	}

DELETE a chain:

	const response = await fetch("http://127.0.0.1:8080/chain/{table}/{name}/", {
		method: "DELETE"
		headers: { "Authorization": "bearer token" }
		});

	curl -H 'Authorization: bearer token' -i -X DELETE http://127.0.0.1:8080/chain/{table}/{name}/

RENAME a chain:

	const response = await fetch("http://127.0.0.1:8080/mvchain/{table}/{oldname}/{newname}/", {
		method: "PUT"
		headers: { "Authorization": "bearer token" }
		});

	curl -H 'Authorization: bearer token' -i -X PUT http://127.0.0.1:8080/mvchain/{table}/{oldname}/{newname}/


**Rules:**

Test,Add,Del iptables rule in table filter with the parameters

	GET/PUT/DELETE /rules/{action}/{chain}/{proto}/{iface_in}/{iface_out}/{source}/{destination}/?sports=00&dports=00&state=XXXX&fragment=true&icmptype=XXXX&log-prefix=XXXXX

	curl -H 'Authorization: bearer token' -i -X GET/PUT/DELETE http://127.0.0.1:8080/rules/{action}/{chain}/{proto}/{iface_in}/{iface_out}/{source}/{destination}/?sports=00&dports=00&state=XXXX&fragment=true&icmptype=XXXX&log-prefix=XXXXX

	with for source and destination _ instead / : 10.0.0.0_8 or range 10.0.0.0-10.255.0.0_32
	log-prefix only if action = LOG


**Nat:**

Test,Add,Del iptables rule in table nat with the parameters

	GET/PUT/DELETE /nat/{action}/{chain}/{proto}/{iface}/{source}/{destination}/{nat_final}/?dport=00&except=true

	curl -H 'Authorization: bearer token' -i -X GET/PUT/DELETE http://127.0.0.1:8080/nat/{action}/{chain}/{proto}/{iface}/{source}/{destination}/{nat_final}/?dport=00&except=true

	with for source and destination _ instead / : 10.0.0.0_8


**Raw:**

Test,Add,Del iptables rule in table raw with the parameters

	GET/PUT/DELETE /raw/{action}/{chain}/{proto}/{iface_in}/{iface_out}/{source}/{destination}/?sports=00&dports=00&tcpflag1=XYZ&tcpflag2=Y&notrack=true&log-prefix=XXXXX

	curl -H 'Authorization: bearer token' -i -X GET/PUT/DELETE http://127.0.0.1:8080/raw/{action}/{chain}/{proto}/{iface_in}/{iface_out}/{source}/{destination}/?sports=00&dports=00&tcpflag1=XYZ&tcpflag2=Y&notrack=true&log-prefix=XXXXX

	with for source and destination _ instead / : 10.0.0.0_8 or range 10.0.0.0-10.255.0.0_32
	log-prefix only if action = LOG


**Save & Restore:**

- Save: iptables-save > /etc/iptables/rules.v4 && cp /etc/iptables/rules.v4 /var/backups/iptables-api/rules.v4.2006-01-02.15-04-05


	GET /save/
	curl -H 'Authorization: bearer token' -i -X GET http://127.0.0.1:8080/save/


- Restore: iptables-restore $file


	PUT /restore/{file}
	curl -H 'Authorization: bearer token' -i -X PUT http://127.0.0.1:8080/restore/{file}
	
