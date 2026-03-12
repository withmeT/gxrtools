use std::collections::HashMap;

pub const DEFAULT_PORTS: &[u16] = &[
    7, 19, 20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 111, 123, 135, 137, 138, 139, 143, 161,
    162, 179, 389, 443, 445, 500, 514, 515, 520, 546, 547, 587, 631, 993, 995, 1080, 1433, 1521,
    1723, 1883, 2049, 2082, 2083, 2181, 2375, 2379, 2483, 2484, 3306, 3389, 3690, 4369, 5000, 5001,
    5222, 5223, 5432, 5672, 5800, 5900, 5984, 5985, 5986, 6000, 6379, 6443, 7001, 7002, 7199, 7443,
    7777, 8000, 8009, 8080, 8081, 8443, 8500, 8600, 8765, 8888, 9000, 9042, 9090, 9200, 9300, 9418,
    9999, 10000, 11211, 15672, 27017, 27018, 28017, 50070, 50075, 50470, 60020, 60030, 61616,
    62078, 65535,5601,
];

lazy_static::lazy_static! {
    pub static ref DEFAULT_PORT_BANNERS: HashMap<u16, &'static str> = {
        let mut m = HashMap::new();
        // 常见服务
        m.insert(7, "Echo");
        m.insert(19, "Chargen");
        m.insert(20, "FTP-Data");
        m.insert(21, "FTP");
        m.insert(22, "SSH");
        m.insert(23, "Telnet");
        m.insert(25, "SMTP");
        m.insert(53, "DNS");
        m.insert(67, "DHCP Server");
        m.insert(68, "DHCP Client");
        m.insert(69, "TFTP");
        m.insert(110, "POP3");
        m.insert(111, "RPCbind");
        m.insert(123, "NTP");
        m.insert(135, "MS RPC");
        m.insert(137, "NetBIOS Name Service");
        m.insert(138, "NetBIOS Datagram Service");
        m.insert(139, "NetBIOS Session Service");
        m.insert(143, "IMAP");
        m.insert(161, "SNMP");
        m.insert(162, "SNMP Trap");
        m.insert(179, "BGP");
        m.insert(389, "LDAP");
        m.insert(445, "Microsoft-DS/SMB");
        m.insert(500, "ISAKMP/IKE");
        m.insert(514, "Syslog");
        m.insert(515, "LPD (Printer)");
        m.insert(520, "RIP");
        m.insert(546, "DHCPv6 Client");
        m.insert(547, "DHCPv6 Server");
        m.insert(587, "SMTP (submission)");
        m.insert(631, "IPP (Printer)");
        m.insert(993, "IMAPS");
        m.insert(995, "POP3S");
        m.insert(1080, "SOCKS Proxy");
        m.insert(1433, "Microsoft SQL Server");
        m.insert(1521, "Oracle Database");
        m.insert(1723, "PPTP");
        m.insert(1883, "MQTT");
        m.insert(2049, "NFS");
        m.insert(2082, "cPanel");
        m.insert(2083, "cPanel (SSL)");
        m.insert(2181, "Zookeeper");
        m.insert(2375, "Docker API");
        m.insert(2379, "etcd");
        m.insert(2483, "Oracle DB Listener (TCP)");
        m.insert(2484, "Oracle DB Listener (SSL)");
        m.insert(3306, "MySQL");
        m.insert(3389, "RDP");
        m.insert(3690, "Subversion (SVN)");
        m.insert(4369, "Erlang Port Mapper");
        m.insert(5000, "UPnP / Flask Dev Server");
        m.insert(5001, "HTTP Alternate");
        m.insert(5222, "XMPP Client");
        m.insert(5223, "XMPP Client SSL");
        m.insert(5432, "PostgreSQL");
        m.insert(5601, "Kibana");
        m.insert(5672, "RabbitMQ/AMQP");
        m.insert(5800, "VNC over HTTP");
        m.insert(5900, "VNC");
        m.insert(5984, "CouchDB");
        m.insert(5985, "WinRM (HTTP)");
        m.insert(5986, "WinRM (HTTPS)");
        m.insert(6000, "X11");
        m.insert(6379, "Redis");
        m.insert(6443, "Kubernetes API");
        m.insert(7001, "WebLogic Admin");
        m.insert(7002, "WebLogic SSL");
        m.insert(7199, "Cassandra JMX");
        m.insert(7443, "HTTPS Alt");
        m.insert(7777, "Oracle TNS");
        m.insert(8000, "Common Dev Server");
        m.insert(8009, "AJP (Tomcat)");
        m.insert(8081, "HTTP-Alt2");
        m.insert(8443, "HTTPS Alt");
        m.insert(8500, "Consul");
        m.insert(8600, "Consul DNS");
        m.insert(8765, "WebSocket Test");
        m.insert(8888, "HTTP API / Jupyter");
        m.insert(9000, "PHP-FPM / SonarQube");
        m.insert(9042, "Cassandra CQL");
        m.insert(9090, "Prometheus");
        m.insert(9200, "Elasticsearch");
        m.insert(9300, "Elasticsearch Internal");
        m.insert(9418, "Git");
        m.insert(9999, "HBase / Debug Port");
        m.insert(10000, "Webmin / Bacula");
        m.insert(11211, "Memcached");
        m.insert(15672, "RabbitMQ Web UI");
        m.insert(27017, "MongoDB");
        m.insert(27018, "MongoDB Alt");
        m.insert(28017, "MongoDB Web Status");
        m.insert(50070, "Hadoop NameNode Web UI");
        m.insert(50075, "Hadoop DataNode Web UI");
        m.insert(50470, "Hadoop Secured NameNode");
        m.insert(60020, "HBase Master");
        m.insert(60030, "HBase RegionServer");
        m.insert(61616, "Apache ActiveMQ");
        m.insert(62078, "iTunes Sync Service");
        m.insert(65535, "Reserved");

        m
    };
}
