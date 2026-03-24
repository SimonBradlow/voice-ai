"""
PDF report generator for network security scan results.

Produces a professional, plain-English security report that non-technical
users can understand. Each finding explains what it is, why it matters,
and how to fix it.

Usage:
    from pdf_report import generate_pdf
    pdf_bytes = generate_pdf(scan_results_dict)
"""

from datetime import datetime
from io import BytesIO

from fpdf import FPDF, XPos, YPos

# ── Per-service explanations ──────────────────────────────────────────────────
# Keys match the "service" label in scanner.py RISKY_PORTS.
# Each value is a tuple: (what_it_means, why_its_a_problem, how_to_fix_it)

RISK_EXPLANATIONS: dict[str, tuple[str, str, str]] = {

    # ── Remote Access ─────────────────────────────────────────────────────────

    "Telnet": (
        "Telnet is an old remote-access tool that lets someone control a device over the "
        "network, similar to sitting in front of it.",
        "Everything sent over Telnet - including usernames and passwords - travels across "
        "your network in plain text with zero encryption. Anyone monitoring your Wi-Fi can "
        "read your credentials instantly without any hacking skills.",
        "Disable Telnet on the device immediately and replace it with SSH, which encrypts "
        "all communication. If you are not sure how, check the device's manual or contact "
        "the manufacturer's support team. There is no safe way to run Telnet on a network.",
    ),
    "SSH": (
        "SSH (Secure Shell) provides encrypted remote access to a device's command line, "
        "allowing someone to control it over the network.",
        "While SSH itself is encrypted and generally safe, an exposed SSH port is a constant "
        "target for automated bots that run around the clock trying thousands of password "
        "combinations (called brute-force attacks). A weak password is all it takes to "
        "lose full control of a device.",
        "Disable password-based login and require SSH key authentication instead - keys "
        "cannot be brute-forced. If you must keep passwords, use a tool like Fail2Ban to "
        "block repeated failed attempts. Consider changing the default port (22) to reduce "
        "automated scanning, and restrict SSH access by IP address in your firewall.",
    ),
    "RDP": (
        "RDP (Remote Desktop Protocol) is Microsoft's built-in tool for viewing and "
        "controlling a Windows computer remotely, as if you were sitting in front of it.",
        "RDP is among the most attacked services on the internet. Automated bots scan "
        "billions of IP addresses daily looking for open RDP. A successful brute-force "
        "attack gives the attacker complete, graphical control of the machine - they can "
        "install ransomware, steal data, or use it as a launchpad for further attacks. "
        "RDP vulnerabilities like BlueKeep have been classified as wormable (able to "
        "spread automatically without user action).",
        "Disable RDP entirely if you do not need it (Control Panel > System > Remote "
        "Settings). If you do need remote access, connect via VPN first and then RDP "
        "to the local IP address - never expose RDP directly. Enable Network Level "
        "Authentication (NLA), use a strong unique password, and keep Windows fully patched.",
    ),
    "VNC": (
        "VNC (Virtual Network Computing) is a cross-platform remote desktop tool that "
        "lets you see and control another computer's screen over the network.",
        "VNC is frequently set up with weak or no passwords and has poor default security. "
        "Unlike RDP, many VNC implementations use outdated or no encryption. It is "
        "regularly found in breach reports as an initial access point - attackers gain "
        "full screen control of the victim machine.",
        "Disable VNC if it is not actively needed. If you must use it, set a strong "
        "unique password, enable encryption (TLS/SSL if your VNC version supports it), "
        "and use a firewall rule to only allow connections from specific trusted IP "
        "addresses. Preferably, access it only through a VPN.",
    ),
    "rlogin": (
        "rlogin is a very old Unix remote login service, a predecessor to SSH from the "
        "1980s.",
        "rlogin has no real security. It can be configured to trust certain hosts "
        "completely without any password, and all traffic is unencrypted. It is "
        "considered dangerously obsolete and has been exploited since the early days "
        "of the internet.",
        "Disable rlogin (port 513) immediately and remove the rsh-server or rlogin "
        "package. Replace with SSH. There is no legitimate reason to run rlogin on a "
        "modern network.",
    ),
    "rexec": (
        "rexec (remote execution) is an ancient Unix service that allows running commands "
        "on a remote machine by providing a username and password.",
        "rexec sends credentials in plain text and has no protection against interception "
        "or replay attacks. It was designed before network security was a concern and "
        "should be considered fully compromised on any network with untrusted devices.",
        "Disable rexec (port 512) and the rsh-server package immediately. Use SSH with "
        "key-based authentication for all remote command execution.",
    ),
    "rsh": (
        "rsh (remote shell) is an old Unix service for running commands on remote machines "
        "without a password if the source host is 'trusted.'",
        "rsh's trust model - based only on IP address - is trivially bypassed by IP "
        "spoofing. It sends all data including any credentials in plain text. It has "
        "been exploited in real attacks for decades and has no place on modern networks.",
        "Disable rsh (port 514) and remove the rsh-server package. Use SSH instead. "
        "Also remove any .rhosts or /etc/hosts.equiv files that grant passwordless trust.",
    ),

    # ── File Transfer ─────────────────────────────────────────────────────────

    "FTP": (
        "FTP (File Transfer Protocol) is used to upload and download files between devices "
        "over a network.",
        "FTP sends your login credentials and every file you transfer in completely plain "
        "text - there is no encryption at all. Anyone on your network or internet path can "
        "see your username, password, and file contents as if reading a printed letter.",
        "Replace FTP with SFTP (SSH File Transfer Protocol) or FTPS, both of which encrypt "
        "the connection. All modern file transfer clients support these. Disable the FTP "
        "service entirely if it is not actively being used.",
    ),
    "TFTP": (
        "TFTP (Trivial File Transfer Protocol) is a simplified file transfer service with "
        "no authentication at all - anyone can read or write files.",
        "TFTP has zero authentication. Any device on the network can download or upload "
        "files without providing any credentials. It is commonly used by attackers to "
        "exfiltrate data or plant malicious files. Network equipment like routers sometimes "
        "use TFTP to load firmware, which can be hijacked.",
        "Disable TFTP (port 69) unless it is absolutely required for a specific purpose "
        "like network device provisioning. If it must run, restrict access to specific "
        "devices using firewall rules and monitor it closely.",
    ),
    "rsync": (
        "rsync is a file synchronization and transfer tool commonly used on Linux and macOS "
        "systems to keep files in sync between machines.",
        "An exposed rsync daemon with no authentication (the default in many configurations) "
        "allows anyone on the network to read or overwrite files. Attackers have used open "
        "rsync to steal databases, source code, and backups - or to plant malicious files.",
        "Require authentication in your rsync configuration (use 'auth users' and "
        "'secrets file' directives). Restrict access by IP using 'hosts allow'. "
        "Consider tunneling rsync over SSH instead of running it as a daemon.",
    ),
    "NFS": (
        "NFS (Network File System) allows directories from one computer to be mounted and "
        "used by other computers on the network, similar to a shared drive.",
        "NFS has historically weak access controls - it relies on IP addresses and Unix "
        "user IDs for security, both of which are easily spoofed. Exposed NFS shares have "
        "led to major data breaches. NFSv3 and earlier have no encryption.",
        "Restrict NFS exports to specific trusted IP addresses in /etc/exports. Use "
        "NFSv4 with Kerberos authentication where possible. Block NFS ports (2049, 111) "
        "at the firewall from untrusted segments.",
    ),
    "AFP": (
        "AFP (Apple Filing Protocol) is Apple's legacy network file sharing protocol, "
        "used by older Macs to share files over a network.",
        "AFP is deprecated and has known vulnerabilities. Apple replaced it with SMB. "
        "Older AFP implementations have authentication weaknesses and have been targeted "
        "by ransomware that specifically hunts for Apple network shares.",
        "Disable AFP and migrate to SMB for file sharing. Go to System Preferences > "
        "Sharing and turn off AFP. Use macOS's built-in SMB sharing instead, which is "
        "more secure and supported.",
    ),

    # ── Web ───────────────────────────────────────────────────────────────────

    "HTTP": (
        "HTTP is the foundation of the web - it is the protocol that serves web pages to "
        "browsers. This device is running a web server without encryption.",
        "HTTP sends all data in plain text. Any login forms, personal information, or "
        "sensitive content served over HTTP can be read by anyone on your network or "
        "anyone positioned between you and the server (called a man-in-the-middle attack).",
        "Enable HTTPS on the web server by installing an SSL/TLS certificate. Free "
        "certificates are available through Let's Encrypt. Redirect all HTTP traffic to "
        "HTTPS automatically. Most web hosting panels (cPanel, Plesk) have one-click "
        "HTTPS setup.",
    ),
    "HTTPS": (
        "HTTPS is the encrypted standard for web communication. This device is running a "
        "secure web server with SSL/TLS encryption.",
        "While HTTPS is generally safe, an expired, self-signed, or misconfigured "
        "certificate can create a false sense of security. Outdated web server software "
        "can also carry vulnerabilities even when HTTPS is enabled.",
        "Verify the SSL/TLS certificate is valid, not expired, and issued by a trusted "
        "certificate authority. Keep the web server software (Apache, Nginx, IIS, etc.) "
        "fully updated. Run a quick SSL check using a free tool like SSL Labs to "
        "identify any configuration weaknesses.",
    ),
    "HTTP-Alt": (
        "A web server is running on port 8080 - a non-standard alternative to the usual "
        "port 80. This is often a development server, admin panel, or internal tool.",
        "Non-standard port web servers are frequently development or admin interfaces that "
        "were never intended to be publicly accessible. They often lack proper "
        "authentication, run outdated software, or have debug features enabled that "
        "expose sensitive system information.",
        "Identify what service is running on this port. If it is an admin interface or "
        "development server, restrict access to it using a firewall rule (allow only "
        "specific IPs). Add authentication if it lacks any. Enable HTTPS and keep "
        "the underlying software updated.",
    ),
    "HTTPS-Alt": (
        "An encrypted HTTPS web server is running on port 8443 - a non-standard "
        "alternative to the usual port 443.",
        "While the connection is encrypted, non-standard HTTPS ports often host admin "
        "panels, control interfaces, or internal tools. These are frequently not kept "
        "as up-to-date as public-facing servers and may have weaker access controls.",
        "Verify what application is running on this port. Ensure the SSL/TLS certificate "
        "is valid and not expired. Restrict access to trusted IP addresses via firewall "
        "if this is an internal tool. Keep the application and its dependencies updated.",
    ),
    "HTTP-Dev": (
        "A web server is running on a development or alternate port (such as 3000, 8000, "
        "or 8888). This is typically a development framework, API server, or internal tool.",
        "Development servers are almost never hardened for security. They commonly run "
        "with debug mode on (which exposes source code, stack traces, and environment "
        "variables), have no authentication, and use outdated dependencies. They are "
        "frequently left running accidentally.",
        "If this is a development server, stop it when not in use. If it needs to be "
        "accessible, add authentication, disable debug mode, and restrict access by "
        "IP. Never expose a development server to the internet.",
    ),
    "Webmin": (
        "Webmin is a web-based server administration panel that lets you manage a Linux "
        "or Unix system through your browser.",
        "Webmin gives full server administration access through a web interface. It has "
        "had several serious vulnerabilities over the years, including a backdoor that "
        "was present in official downloads for over a year. If compromised, an attacker "
        "gets complete root-level control of the server.",
        "Keep Webmin strictly updated. Restrict access to trusted IP addresses only using "
        "Webmin's own IP access control or a firewall rule. Enable two-factor "
        "authentication. Consider replacing it with a more modern alternative or "
        "SSH-based management.",
    ),
    "cPanel": (
        "cPanel is a web hosting control panel that lets you manage websites, email "
        "accounts, databases, and server settings through a browser.",
        "cPanel exposes a broad attack surface - it manages everything on a web hosting "
        "account. Weak passwords or outdated cPanel versions can give an attacker full "
        "control over all hosted websites and email, often leading to mass website "
        "defacement or spam sending.",
        "Use a strong, unique password for cPanel. Enable two-factor authentication in "
        "the security settings. Keep cPanel and its applications updated. Restrict login "
        "access to known IP addresses if possible.",
    ),

    # ── Email ─────────────────────────────────────────────────────────────────

    "SMTP": (
        "SMTP is the protocol used to send email. An SMTP server on your network handles "
        "outgoing email messages.",
        "An improperly configured SMTP server becomes an 'open relay,' meaning spammers and "
        "attackers can use your server to send bulk spam or phishing emails to the world. "
        "This can get your network's IP address blacklisted, causing all your legitimate "
        "email to be blocked, and may expose you to legal liability.",
        "Ensure your mail server requires authentication before allowing anyone to send "
        "email. Configure it to only relay messages from your own domain. Have your IT "
        "team or email provider audit the configuration using an open-relay test tool.",
    ),
    "SMTPS": (
        "SMTPS is the encrypted version of SMTP used for secure email submission. "
        "Port 465 is the legacy SSL/TLS submission port.",
        "While the connection itself is encrypted, a misconfigured SMTPS server can still "
        "act as an open relay. Weak credentials allow attackers to send spam through your "
        "server, leading to blacklisting and reputational damage.",
        "Require strong authentication (SASL) before allowing message relay. Restrict "
        "submission to authenticated users only. Monitor outbound email volume for "
        "sudden spikes that might indicate credential compromise.",
    ),
    "SMTP-Sub": (
        "Port 587 is the standard email submission port - it is how email clients "
        "(Outlook, Apple Mail, Thunderbird) send outgoing messages through a mail server.",
        "If not properly secured, attackers with stolen email credentials can use this "
        "port to send large volumes of spam or phishing email that appears to come from "
        "your legitimate domain, damaging your reputation and getting you blacklisted.",
        "Require STARTTLS encryption and authenticated login (SMTP AUTH) on port 587. "
        "Implement rate limiting per account. Monitor for unusual sending volume and "
        "alert on accounts sending abnormally high numbers of messages.",
    ),
    "POP3": (
        "POP3 (Post Office Protocol) is a protocol email clients use to download messages "
        "from a mail server to a local device.",
        "POP3 (port 110) sends email credentials in plain text. Anyone monitoring the "
        "network can capture your email username and password. Emails downloaded via "
        "POP3 are typically removed from the server, making recovery difficult.",
        "Disable POP3 and use POP3S (port 995) which encrypts the connection, or switch "
        "to IMAP over TLS. Encourage users to use webmail or modern email clients that "
        "support encrypted protocols.",
    ),
    "POP3S": (
        "POP3S is the encrypted version of POP3, used to securely download email from "
        "a mail server.",
        "While the connection is encrypted, weak email account passwords can still be "
        "brute-forced over POP3S. Compromised email accounts expose all stored messages "
        "and can be used to send spam or reset passwords for other services.",
        "Enforce strong password policies for all email accounts. Enable account lockout "
        "after repeated failed login attempts. Consider using two-factor authentication "
        "if your mail server supports it.",
    ),
    "IMAP": (
        "IMAP (Internet Message Access Protocol) allows email clients to access and "
        "manage messages stored on a mail server without downloading them.",
        "IMAP (port 143) sends credentials and email content in plain text. Credentials "
        "intercepted over an unencrypted IMAP connection give an attacker full access "
        "to all email in the account.",
        "Disable unencrypted IMAP and use IMAPS (port 993) instead. Configure your mail "
        "server to reject connections that do not use STARTTLS. Update email clients to "
        "use encrypted connections.",
    ),
    "IMAPS": (
        "IMAPS is the encrypted version of IMAP for securely accessing email stored on "
        "a mail server.",
        "While the connection is encrypted, weak account passwords or a compromised "
        "certificate can still expose email. Email accounts are high-value targets "
        "because they often contain sensitive information and password reset links for "
        "other services.",
        "Use strong, unique passwords for all email accounts. Enable two-factor "
        "authentication. Ensure the SSL certificate is valid and from a trusted "
        "authority. Monitor logins from unusual locations.",
    ),

    # ── Databases ─────────────────────────────────────────────────────────────

    "MSSQL": (
        "Microsoft SQL Server is a database system used to store and manage data. Having "
        "it directly reachable on the network means anyone on the network can attempt "
        "to connect to your database.",
        "Databases contain your most sensitive information - customer records, financial "
        "data, credentials, business data. An exposed database is a primary target for "
        "automated attacks trying default passwords (like 'sa' with a blank password), "
        "SQL injection, and direct data theft.",
        "Configure SQL Server to only accept connections from localhost (127.0.0.1) unless "
        "remote access is strictly required. Use the SQL Server Configuration Manager to "
        "change the listening address. If remote access is needed, use an encrypted VPN "
        "or SSH tunnel rather than exposing the port. Change the default 'sa' account "
        "password and disable it if not used.",
    ),
    "MSSQL-Mon": (
        "This is the Microsoft SQL Server Browser service, which advertises SQL Server "
        "instances and their port numbers to clients on the network.",
        "The SQL Server Browser leaks information about your database server configuration "
        "to anyone who asks - including which instances are running and on which ports. "
        "This information helps attackers target your database directly.",
        "Disable the SQL Server Browser service if you do not need clients to auto-discover "
        "your SQL Server. In SQL Server Configuration Manager, stop and disable the "
        "SQL Server Browser service.",
    ),
    "MySQL": (
        "MySQL is one of the most widely-used database systems in the world. An exposed "
        "MySQL port means the database engine is directly reachable over the network.",
        "Databases are the crown jewels of most systems. Exposed MySQL ports are targeted "
        "constantly by automated scanners looking for default credentials ('root' with no "
        "password is surprisingly common). A successful connection gives attackers direct "
        "access to read, modify, or delete all your data.",
        "Add 'bind-address = 127.0.0.1' to your MySQL configuration file (my.cnf or "
        "my.ini) and restart MySQL - this makes it only accept local connections. If "
        "remote access is genuinely needed, create a specific user with limited "
        "permissions and connect through an encrypted SSH tunnel.",
    ),
    "PostgreSQL": (
        "PostgreSQL (often called Postgres) is a powerful open-source database system "
        "used by many web applications and businesses.",
        "An exposed PostgreSQL port allows anyone on the network to attempt login. The "
        "default superuser account is 'postgres' - if it has a weak or default password, "
        "an attacker gains full control of all databases. PostgreSQL can also be used to "
        "execute operating system commands if the attacker gains admin access.",
        "Edit postgresql.conf to set 'listen_addresses = localhost' so it only accepts "
        "local connections. If remote access is needed, use an SSH tunnel. Ensure the "
        "'postgres' account has a strong password. Review pg_hba.conf to ensure "
        "only trusted hosts and authentication methods are allowed.",
    ),
    "MongoDB": (
        "MongoDB is a popular database that stores data in a flexible, document-based "
        "format. It is widely used in web applications.",
        "MongoDB has a long history of being left open with no authentication enabled - "
        "the default in older versions. Hundreds of thousands of databases have been "
        "exposed publicly. Attackers run automated scripts that scan for open MongoDB "
        "instances, steal the data, delete it, and leave a ransom note.",
        "Enable authentication in MongoDB (security.authorization: enabled in mongod.conf). "
        "Bind MongoDB to localhost only (net.bindIp: 127.0.0.1). If remote access is "
        "needed, use a VPN or SSH tunnel and create specific users with minimal "
        "permissions for each application.",
    ),
    "Redis": (
        "Redis is an in-memory data store used by applications for caching, session "
        "storage, message queuing, and other high-speed data operations.",
        "Redis was designed for trusted networks and has no authentication by default. "
        "An exposed Redis instance allows anyone to read all cached data (which may "
        "include session tokens, user data, or API keys), overwrite it, or use Redis "
        "to write files to the server's filesystem - a common technique for gaining "
        "full server access.",
        "Bind Redis to localhost only (bind 127.0.0.1 in redis.conf). Set a strong "
        "password with 'requirepass'. Disable dangerous commands like CONFIG, FLUSHALL, "
        "and DEBUG using the 'rename-command' directive. If remote access is needed, "
        "tunnel through SSH.",
    ),
    "Elasticsearch": (
        "Elasticsearch is a search and analytics engine used to index and query large "
        "amounts of data quickly. It is common in logging, e-commerce, and analytics.",
        "Older versions of Elasticsearch had no authentication at all. Exposed instances "
        "have been responsible for some of the largest data breaches ever recorded - "
        "billions of records have been leaked from open Elasticsearch clusters. Even "
        "with security enabled, misconfigurations are extremely common.",
        "Enable X-Pack security (now free) in elasticsearch.yml with "
        "'xpack.security.enabled: true'. Set strong passwords for built-in accounts. "
        "Bind to localhost or a private network interface only. Never expose "
        "Elasticsearch ports (9200, 9300) to the internet.",
    ),
    "Cassandra": (
        "Apache Cassandra is a distributed database designed for handling large amounts "
        "of data across multiple servers.",
        "Cassandra has historically shipped with weak defaults - no authentication, "
        "default credentials (cassandra/cassandra), and open inter-node communication "
        "ports. Exposed Cassandra instances have been ransacked and held for ransom "
        "in automated attacks.",
        "Enable authentication and authorization in cassandra.yaml "
        "(authenticator: PasswordAuthenticator). Change the default cassandra user "
        "password immediately. Restrict inter-node and client ports to trusted IPs "
        "using a firewall.",
    ),
    "Memcached": (
        "Memcached is an in-memory caching system that applications use to speed up "
        "performance by storing frequently accessed data in RAM.",
        "Memcached has no authentication. Any client that can reach port 11211 can read "
        "all cached data (which may include user sessions, API responses, or sensitive "
        "business data) or flush the entire cache, crashing application performance. "
        "It has also been massively abused for DDoS amplification attacks.",
        "Bind Memcached to localhost only (use the -l 127.0.0.1 flag or equivalent). "
        "Block port 11211 at the firewall. There is no reason for Memcached to be "
        "accessible outside the local machine.",
    ),
    "OracleDB": (
        "Oracle Database is a major enterprise database system used in large businesses "
        "and critical infrastructure.",
        "Exposed Oracle listener ports allow attackers to enumerate database instances "
        "and attempt authentication. Oracle's default accounts (like SCOTT/TIGER and "
        "SYS/CHANGE_ON_INSTALL) are well-known and frequently targeted. A compromised "
        "Oracle database typically contains highly sensitive enterprise data.",
        "Restrict Oracle listener access to application servers only using TCP Valid Node "
        "Checking. Change all default passwords. Apply Oracle's Critical Patch Updates "
        "regularly. Use Oracle's own security hardening guide as a checklist.",
    ),

    # ── Windows Services ──────────────────────────────────────────────────────

    "SMB": (
        "SMB (Server Message Block) is the Windows file and printer sharing protocol - it "
        "is how computers share folders and printers on a Windows network.",
        "Exposed SMB is one of the most dangerous findings possible. The WannaCry ransomware "
        "attack in 2017 (which cost billions globally) and the NotPetya attack both spread "
        "exclusively through open SMB ports. A single unpatched device can infect every "
        "machine on your network within minutes.",
        "Block SMB ports (445 and 139) in your firewall so they are not reachable from "
        "untrusted devices. Apply all Windows security updates immediately - Microsoft "
        "released patches for the critical SMB vulnerabilities years ago, but many devices "
        "remain unpatched. Disable the outdated SMBv1 protocol in Windows Features.",
    ),
    "NetBIOS": (
        "NetBIOS is an older Windows networking protocol originally used for file sharing "
        "and printer discovery on local networks.",
        "NetBIOS actively broadcasts your computer names, workgroup names, and network "
        "layout to anyone who asks - it leaks your internal network map. It has been "
        "exploited in countless malware campaigns and is frequently targeted because many "
        "systems still have it enabled from legacy configurations.",
        "Disable NetBIOS over TCP/IP in Windows network adapter settings if it is not "
        "required for older devices. Go to: Network Connections > Adapter Properties > "
        "TCP/IPv4 Properties > Advanced > WINS tab > Disable NetBIOS. Block port 139 at "
        "the firewall.",
    ),
    "RPC": (
        "RPC (Remote Procedure Call) is a Windows system service that allows programs on "
        "one computer to run code on another computer across the network.",
        "Windows RPC has a long history of critical security vulnerabilities and has been "
        "exploited by major worms (like Blaster and Conficker) to spread automatically "
        "across networks without any user interaction. Any Windows machine with this "
        "exposed is at elevated risk.",
        "Block port 135 at your firewall so it is not accessible from untrusted machines. "
        "Keep all Windows devices fully updated - Microsoft regularly releases patches "
        "for RPC vulnerabilities. This port should never be exposed to the internet.",
    ),
    "RPC-HTTP": (
        "RPC over HTTP allows Windows Remote Procedure Call traffic to be tunneled through "
        "HTTP, commonly used by Microsoft Outlook to connect to Exchange servers.",
        "Exposing RPC over HTTP on port 593 can allow attackers to reach internal Windows "
        "services through web proxies that would otherwise block direct RPC traffic. "
        "It has been targeted in Exchange Server attacks.",
        "Restrict access to port 593 to known Exchange clients and networks only. "
        "Ensure the server is fully patched - Exchange servers in particular have had "
        "numerous critical RPC-related vulnerabilities. Consider migrating to "
        "modern Exchange protocols (MAPI over HTTPS).",
    ),
    "WinRM": (
        "WinRM (Windows Remote Management) is Microsoft's remote management service that "
        "allows administrators to run commands on Windows machines over the network.",
        "WinRM is a powerful administrative interface that gives remote command execution "
        "on Windows. It is increasingly targeted by attackers for lateral movement inside "
        "corporate networks once they have initial access. Credential theft attacks "
        "heavily target WinRM-enabled systems.",
        "Restrict WinRM access using firewall rules to only trusted management hosts. "
        "Require HTTPS (not HTTP) for WinRM. Disable WinRM on machines that do not "
        "need remote management. Monitor for unexpected WinRM connections in event logs.",
    ),
    "LDAP": (
        "LDAP (Lightweight Directory Access Protocol) is used to access and manage "
        "directory information - most commonly Active Directory in Windows environments.",
        "Unencrypted LDAP (port 389) exposes directory queries and authentication in "
        "plain text. An attacker who can read LDAP traffic can harvest usernames, "
        "group memberships, and potentially credentials. LDAP is also targeted for "
        "null-bind attacks that enumerate users without authentication.",
        "Use LDAPS (port 636) or LDAP with STARTTLS to encrypt all directory traffic. "
        "Disable null/anonymous LDAP binds in Active Directory. Restrict LDAP access "
        "to applications that genuinely need it.",
    ),
    "LDAPS": (
        "LDAPS is the encrypted version of LDAP, using SSL/TLS to protect directory "
        "queries and authentication traffic.",
        "While the transport is encrypted, exposed LDAPS still allows enumeration of "
        "Active Directory users and groups with valid credentials. A compromised "
        "service account with LDAP read access can map your entire user directory.",
        "Restrict LDAPS access to application servers and management hosts only. "
        "Use minimal-privilege service accounts for applications that query the directory. "
        "Monitor for unusual LDAP query patterns that may indicate enumeration.",
    ),
    "Kerberos": (
        "Kerberos is the authentication protocol used by Windows Active Directory. "
        "It issues 'tickets' that prove a user's identity to services on the network.",
        "Exposed Kerberos (port 88) on non-domain-controller machines is unusual and "
        "suspicious. On domain controllers it is expected, but attackers target Kerberos "
        "for attacks like Kerberoasting (extracting and cracking service account "
        "password hashes offline) and Pass-the-Ticket attacks.",
        "Ensure Kerberos is only running on legitimate domain controllers. Use strong, "
        "long, random passwords for all service accounts (managed service accounts are "
        "ideal). Audit Kerberos ticket-granting activity for unusual patterns.",
    ),
    "GlobalCatalog": (
        "The Global Catalog is a feature of Active Directory that provides a searchable "
        "index of all objects across a domain forest.",
        "Global Catalog ports (3268 unencrypted, 3269 encrypted) expose your full Active "
        "Directory structure to queries. Attackers use Global Catalog access to enumerate "
        "every user account, group, and computer in the organization.",
        "Restrict Global Catalog ports to domain-joined machines and management hosts "
        "only. Block access from untrusted network segments. Monitor for bulk "
        "enumeration queries.",
    ),

    # ── Network Infrastructure ────────────────────────────────────────────────

    "DNS": (
        "DNS (Domain Name System) is the internet's phonebook - it translates domain names "
        "like google.com into the IP addresses computers use to connect.",
        "An open DNS resolver responds to queries from anyone on the internet, not just "
        "your own network. Attackers abuse open resolvers to amplify DDoS attacks - they "
        "send small requests that generate massive responses directed at a victim, using "
        "your bandwidth. This can slow your network and get your IP flagged.",
        "Configure your DNS server to only answer queries from devices on your own network "
        "(this is called 'restricting recursive queries'). Most router DNS settings have "
        "this option. If you are running a standalone DNS server, consult its documentation "
        "for access control lists.",
    ),
    "SNMP": (
        "SNMP (Simple Network Management Protocol) is used to monitor and manage network "
        "devices like routers, switches, printers, and servers.",
        "SNMPv1 and v2c use 'community strings' as passwords - the default is almost "
        "always 'public' or 'private.' Anyone who knows the community string can read "
        "detailed information about your network topology, connected devices, and "
        "configuration. With write access, they can reconfigure or disable network devices.",
        "Upgrade to SNMPv3 which provides proper authentication and encryption. Change "
        "default community strings. Restrict SNMP access to your monitoring server's IP "
        "only using firewall rules and SNMP access control lists. Disable SNMP on "
        "devices that do not need to be monitored.",
    ),
    "rpcbind": (
        "rpcbind (also called portmapper) is a Unix service that maps RPC program numbers "
        "to network ports, essentially acting as a directory for RPC services.",
        "An exposed rpcbind service leaks information about all RPC services running on "
        "the system (including NFS, NIS, and others). It has had several exploitable "
        "vulnerabilities and is frequently used as a reconnaissance tool by attackers "
        "to understand what services are available.",
        "Block port 111 at the firewall from all untrusted networks. Disable rpcbind "
        "if NFS and other RPC-based services are not in use. On Linux, this is typically "
        "done with 'systemctl disable rpcbind'.",
    ),
    "UPnP": (
        "UPnP (Universal Plug and Play) allows devices on a network to automatically "
        "discover each other and configure network settings without manual intervention.",
        "UPnP has no authentication. Any device on your network can instruct your router "
        "to open ports to the internet, potentially exposing internal services. Malware "
        "actively exploits UPnP to create persistent backdoors. UPnP should never be "
        "accessible from the internet.",
        "Disable UPnP on your router (in the router admin panel under Advanced settings). "
        "Disable it on all devices that do not strictly require it. Block UPnP traffic "
        "(port 1900 UDP, port 5000 TCP) at your firewall.",
    ),
    "IPP": (
        "IPP (Internet Printing Protocol) is used to share printers over a network. "
        "CUPS (Common Unix Printing System) uses IPP on port 631.",
        "Exposed print servers can be exploited to gain access to documents being printed, "
        "crash the printer service, or in some configurations execute code on the print "
        "server. Network printers are frequently overlooked in security audits but store "
        "print job histories.",
        "Restrict IPP access to trusted hosts only using firewall rules. Disable remote "
        "printing if it is not needed. If running CUPS on Linux, configure it to only "
        "listen on localhost unless printer sharing is required.",
    ),

    # ── VPN & Tunneling ───────────────────────────────────────────────────────

    "PPTP": (
        "PPTP (Point-to-Point Tunneling Protocol) is an old VPN protocol developed by "
        "Microsoft in the 1990s.",
        "PPTP's encryption is fundamentally broken and has been for years. Tools exist "
        "that can crack PPTP VPN credentials captured from the network in hours. Using "
        "PPTP provides a false sense of security - traffic that appears protected can "
        "be decrypted by an attacker.",
        "Disable PPTP immediately and replace it with a modern VPN protocol such as "
        "WireGuard, OpenVPN, or IKEv2/IPSec. All modern VPN clients support these. "
        "PPTP should be considered equivalent to no VPN.",
    ),
    "OpenVPN": (
        "OpenVPN is a widely-used open-source VPN that creates encrypted tunnels for "
        "secure network access.",
        "While OpenVPN itself is secure, an exposed OpenVPN service is subject to "
        "brute-force attacks against user credentials. Outdated OpenVPN versions may "
        "have known vulnerabilities.",
        "Require certificate-based authentication rather than username/password alone. "
        "Keep OpenVPN updated. Restrict access to the VPN port to known IP ranges "
        "if possible. Monitor authentication logs for repeated failures.",
    ),

    # ── Container & Cloud Infrastructure ─────────────────────────────────────

    "Docker": (
        "This device is running Docker - software used to run applications in isolated "
        "containers - with its management API exposed on the network.",
        "The Docker API (port 2375 unencrypted, 2376 TLS) gives complete control over "
        "all containers on the host. Attackers who reach an open Docker API can launch "
        "privileged containers that escape to the underlying host, giving them full "
        "root access to the server. This is a critical finding.",
        "Never expose the Docker API on a network interface. Docker should communicate "
        "only through a Unix socket (/var/run/docker.sock). If remote Docker management "
        "is needed, use SSH tunneling or Docker's TLS mutual authentication with "
        "client certificates.",
    ),
    "Kubernetes-API": (
        "Kubernetes is a system for managing containerized applications at scale. The "
        "API server is its central control plane - everything is managed through it.",
        "An exposed Kubernetes API server (port 6443) that accepts unauthenticated "
        "requests gives an attacker complete control over all workloads and data in "
        "the cluster. Even with authentication, overly permissive roles are common. "
        "Kubernetes clusters have been actively exploited for cryptocurrency mining "
        "and data theft.",
        "Require authentication and authorization for all API server access. Enable "
        "audit logging. Restrict network access to the API server to administrator "
        "machines only. Regularly audit RBAC (role-based access control) permissions "
        "and remove excess privileges.",
    ),
    "Kubernetes-Kubelet": (
        "The Kubernetes kubelet is the agent that runs on every node in a Kubernetes "
        "cluster. Its API manages containers running on that specific node.",
        "An exposed kubelet API (port 10250) without authentication allows anyone to "
        "list and execute commands in any container on the node - effectively giving "
        "full access to all workloads and their data. It can also be used to escape "
        "to the underlying host.",
        "Enable kubelet authentication (--authentication-token-webhook=true) and "
        "authorization (--authorization-mode=Webhook). Block port 10250 from all "
        "sources except the Kubernetes control plane. Audit kubelet configuration "
        "against the CIS Kubernetes Benchmark.",
    ),
    "etcd": (
        "etcd is the distributed key-value store that Kubernetes uses as its database, "
        "storing all cluster configuration, secrets, and state.",
        "etcd contains all Kubernetes secrets, including service account tokens and "
        "TLS certificates. An attacker with access to etcd essentially has the keys "
        "to the entire cluster. etcd instances with no authentication have been found "
        "exposed publicly, leading to complete cluster takeovers.",
        "Restrict etcd ports (2379, 2380) to the Kubernetes control plane nodes only. "
        "Enable TLS and client certificate authentication. Never expose etcd to the "
        "internet or untrusted networks.",
    ),

    # ── Message Brokers & Streaming ───────────────────────────────────────────

    "RabbitMQ": (
        "RabbitMQ is a message broker - it passes messages between different parts of "
        "an application or between different applications.",
        "RabbitMQ's default credentials are 'guest/guest' and it ships with a web "
        "management interface on port 15672. Exposed instances with default credentials "
        "have been found containing sensitive business data and have been used to "
        "inject malicious messages into application workflows.",
        "Change the default 'guest' password immediately and restrict the guest account "
        "to localhost only (this is the default but is sometimes changed). Create "
        "specific user accounts with minimal permissions for each application. "
        "Restrict access to RabbitMQ ports via firewall.",
    ),
    "AMQP": (
        "AMQP (Advanced Message Queuing Protocol) is used by message brokers like "
        "RabbitMQ to pass messages between applications.",
        "An exposed AMQP port allows anyone on the network to connect to your message "
        "broker. Depending on permissions, this could allow reading messages meant for "
        "other services, injecting false messages, or disrupting application workflows.",
        "Require authentication for all AMQP connections. Use TLS-encrypted AMQP "
        "(AMQPS, port 5671) instead of plain AMQP. Restrict access to the AMQP port "
        "to application servers that genuinely need it.",
    ),
    "ZooKeeper": (
        "Apache ZooKeeper is a coordination service used by distributed systems like "
        "Kafka, Hadoop, and HBase to manage configuration and synchronization.",
        "ZooKeeper has no authentication or encryption by default. Anyone who can "
        "reach port 2181 can read and modify all configuration data stored in it, "
        "potentially disrupting or taking control of the distributed systems that "
        "depend on it.",
        "Enable ZooKeeper's SASL authentication and configure TLS for client "
        "connections. Restrict access to port 2181 to application servers only using "
        "a firewall. Do not expose ZooKeeper to untrusted networks.",
    ),

    # ── Monitoring & Observability ────────────────────────────────────────────

    "Prometheus": (
        "Prometheus is a monitoring system that collects metrics from applications and "
        "infrastructure, storing time-series data about system performance.",
        "An exposed Prometheus endpoint (port 9090) reveals detailed information about "
        "your infrastructure - server names, application versions, performance metrics, "
        "and internal architecture. This is valuable reconnaissance data for attackers. "
        "The admin API can also be used to delete all metrics data.",
        "Restrict access to Prometheus to monitoring staff and systems only using a "
        "firewall rule or reverse proxy with authentication. Enable Prometheus's built-in "
        "basic authentication and TLS. Never expose Prometheus to the internet.",
    ),
    "Kibana": (
        "Kibana is a visualization dashboard for Elasticsearch data, commonly used for "
        "log analysis and security monitoring.",
        "An exposed Kibana instance (port 5601) without authentication gives read access "
        "to all data in Elasticsearch - which often includes application logs, security "
        "events, and user data. In older versions, Kibana vulnerabilities have allowed "
        "remote code execution.",
        "Enable Kibana's security features (requires Elasticsearch security to be enabled). "
        "Place Kibana behind a reverse proxy with authentication. Restrict access to "
        "the Kibana port to security and operations staff only.",
    ),

    # ── Application Servers ───────────────────────────────────────────────────

    "WebLogic": (
        "Oracle WebLogic Server is an enterprise Java application server used to run "
        "large business applications.",
        "WebLogic has a history of critical deserialization vulnerabilities that allow "
        "remote code execution without authentication. Several WebLogic vulnerabilities "
        "have been exploited in the wild within days of disclosure, including by "
        "ransomware groups and nation-state actors.",
        "Apply Oracle's Critical Patch Updates immediately - WebLogic patches should be "
        "treated as urgent. Restrict access to WebLogic administration (port 7001) to "
        "administrators only. Disable T3 and IIOP protocols if not needed, as these "
        "are the most commonly exploited.",
    ),
    "GlassFish": (
        "GlassFish is an open-source Java application server. Port 4848 is its "
        "administration console.",
        "The GlassFish admin console has had multiple authentication bypass and remote "
        "code execution vulnerabilities. An exposed admin console with weak or default "
        "credentials gives an attacker the ability to deploy malicious applications "
        "to the server.",
        "Restrict access to port 4848 to administrator IP addresses only. Use a strong "
        "password for the admin account. Keep GlassFish updated. Disable the admin "
        "console entirely if it is not needed for day-to-day operations.",
    ),
    "ActiveMQ": (
        "Apache ActiveMQ is a message broker. Port 8161 is its web administration "
        "console.",
        "ActiveMQ's default credentials (admin/admin) are well-known and rarely changed. "
        "It has also had critical vulnerabilities including a 2023 remote code execution "
        "flaw (CVE-2023-46604) that was actively exploited by ransomware groups within "
        "days of disclosure.",
        "Change default credentials immediately. Apply all security patches - the 2023 "
        "RCE vulnerability is particularly severe. Restrict access to ActiveMQ ports "
        "(8161, 61616) to application servers only. Disable unnecessary transport "
        "protocols.",
    ),
    "ADB": (
        "ADB (Android Debug Bridge) is a development tool that gives full command-line "
        "access to an Android device over a network connection.",
        "An exposed ADB port (5555) gives complete, unrestricted access to the Android "
        "device - equivalent to having the device in hand. Attackers can install "
        "malware, read all data including messages and photos, record the screen, "
        "and use the device as part of a botnet. This has been exploited at scale.",
        "Disable ADB over network immediately. On Android, go to Developer Options and "
        "turn off USB Debugging, or specifically disable wireless debugging. ADB should "
        "only ever be used over a direct USB cable, never over a network.",
    ),
    "VMware": (
        "VMware ESXi and vSphere use port 902 for remote console connections to virtual "
        "machines.",
        "Exposed VMware management ports give attackers the ability to control virtual "
        "machines directly. VMware ESXi has been a major ransomware target - attackers "
        "encrypt entire VM disk files, taking down all virtual machines on a host "
        "simultaneously.",
        "Restrict access to all VMware management ports to administrator workstations "
        "only. Apply VMware security patches promptly. Enable two-factor authentication "
        "for vCenter and ESXi. Back up VM configurations regularly and store backups "
        "offline.",
    ),

    # ── Printing ──────────────────────────────────────────────────────────────

    "LPD": (
        "LPD/LPR (Line Printer Daemon) is an old Unix printing protocol on port 515.",
        "LPD has no authentication. Anyone who can reach port 515 can submit print jobs, "
        "query printer status, or in some implementations interact with the underlying "
        "print spooler in ways that have led to code execution. It is largely obsolete "
        "but still found on older devices.",
        "Disable LPD if not in active use. If printing is needed, migrate to IPP (used "
        "by CUPS) which has better access control. Block port 515 at the firewall.",
    ),

    # ── Real-Time & Streaming ─────────────────────────────────────────────────

    "RTSP": (
        "RTSP (Real Time Streaming Protocol) is used to stream audio and video. It is "
        "commonly found on IP cameras, DVRs, and media servers.",
        "IP cameras with exposed RTSP streams (port 554) are often accessible with "
        "no credentials or with default manufacturer passwords that are never changed. "
        "Thousands of cameras are indexed on public sites and watchable by anyone. "
        "Beyond privacy, compromised cameras have been recruited into botnets.",
        "Change the default username and password on the camera or streaming device. "
        "If remote viewing is needed, use a VPN to access it rather than exposing RTSP "
        "directly. Check the manufacturer's site for firmware updates.",
    ),
}

# Severity → RGB fill color for badges and accents
SEVERITY_COLORS: dict[str, tuple[int, int, int]] = {
    "CRITICAL": (190, 30, 30),
    "HIGH":     (210, 80, 10),
    "MEDIUM":   (180, 120, 0),
    "LOW":      (20, 140, 60),
}


# ── PDF class ─────────────────────────────────────────────────────────────────

class _ReportPDF(FPDF):
    """Custom FPDF subclass with header/footer."""

    def __init__(self, network: str, timestamp: str):
        super().__init__()
        self._network = network
        self._timestamp = timestamp
        self.set_auto_page_break(auto=True, margin=18)

    def header(self):
        if self.page_no() == 1:
            return
        self.set_font("Helvetica", "B", 8)
        self.set_text_color(140, 140, 140)
        self.cell(
            self.w - self.l_margin - self.r_margin - 20,
            7,
            f"Network Security Report  ·  {self._network}",
            align="L",
        )
        self.set_font("Helvetica", "", 8)
        self.cell(20, 7, f"Page {self.page_no()}", align="R", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_draw_color(200, 210, 220)
        self.line(self.l_margin, self.get_y(), self.w - self.r_margin, self.get_y())
        self.ln(3)
        self.set_text_color(0, 0, 0)

    def footer(self):
        self.set_y(-14)
        self.set_font("Helvetica", "I", 7)
        self.set_text_color(160, 160, 160)
        self.cell(
            0,
            8,
            f"Generated {self._timestamp}  ·  Network Security Voice Scanner",
            align="C",
        )


# ── Internal helpers ──────────────────────────────────────────────────────────

def _section_heading(pdf: FPDF, title: str) -> None:
    """Bold section title with a dividing rule."""
    pdf.set_font("Helvetica", "B", 13)
    pdf.set_text_color(20, 30, 50)
    pdf.cell(0, 8, title, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    y = pdf.get_y()
    pdf.set_draw_color(180, 195, 215)
    pdf.line(pdf.l_margin, y, pdf.w - pdf.r_margin, y)
    pdf.ln(4)
    pdf.set_text_color(0, 0, 0)


def _body_text(pdf: FPDF, text: str, indent: float = 0) -> None:
    """Render wrapped body text with optional left indent."""
    pdf.set_x(pdf.l_margin + indent)
    available = pdf.w - pdf.l_margin - pdf.r_margin - indent
    pdf.multi_cell(available, 5.5, text, new_x=XPos.LMARGIN, new_y=YPos.NEXT)


def _labeled_block(pdf: FPDF, label: str, text: str, indent: float = 4) -> None:
    """Bold label on its own line, followed by wrapped body text."""
    pdf.set_x(pdf.l_margin + indent)
    pdf.set_font("Helvetica", "B", 9)
    pdf.set_text_color(60, 75, 100)
    pdf.cell(0, 5, label, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_x(pdf.l_margin + indent)
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(30, 41, 59)
    available = pdf.w - pdf.l_margin - pdf.r_margin - indent
    pdf.multi_cell(available, 5.5, text, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(1.5)


def _severity_chip(pdf: FPDF, severity: str, x: float, y: float) -> None:
    """Draw a small colored pill with the severity label."""
    color = SEVERITY_COLORS.get(severity, (100, 116, 139))
    chip_w, chip_h = 24, 7
    pdf.set_fill_color(*color)
    pdf.rect(x, y, chip_w, chip_h, style="F")
    pdf.set_xy(x, y)
    pdf.set_font("Helvetica", "B", 7)
    pdf.set_text_color(255, 255, 255)
    pdf.cell(chip_w, chip_h, severity, align="C")
    pdf.set_text_color(0, 0, 0)


def _summary_box(pdf: FPDF, label: str, value: str, color: tuple[int, int, int],
                 x: float, y: float, w: float, h: float) -> None:
    """Draw a colored summary statistic box."""
    pdf.set_fill_color(*color)
    pdf.rect(x, y, w, h, style="F")
    # Value (large)
    pdf.set_xy(x, y + 3)
    pdf.set_font("Helvetica", "B", 17)
    pdf.set_text_color(255, 255, 255)
    pdf.cell(w, 10, value, align="C", new_x=XPos.RIGHT, new_y=YPos.TOP)
    # Label (small)
    pdf.set_xy(x, y + h - 9)
    pdf.set_font("Helvetica", "", 7)
    pdf.cell(w, 7, label, align="C")
    pdf.set_text_color(0, 0, 0)


# ── Section renderers ─────────────────────────────────────────────────────────

def _render_cover(pdf: _ReportPDF, scan: dict, timestamp: str) -> None:
    """Title, metadata, and summary stat boxes."""
    pdf.ln(16)

    # Title
    pdf.set_font("Helvetica", "B", 26)
    pdf.set_text_color(15, 23, 42)
    pdf.cell(0, 13, "Network Security Report", align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    # Subtitle
    network = scan.get("network", "Unknown")
    pdf.set_font("Helvetica", "", 12)
    pdf.set_text_color(80, 100, 130)
    pdf.cell(0, 8, f"Network: {network}", align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.cell(0, 6, f"Generated: {timestamp}", align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(10)

    # Stat boxes
    risks = scan.get("security_risks", [])
    stats = [
        ("Devices Found",  str(scan.get("hosts_found", 0)),       (50, 115, 220)),
        ("Total Findings", str(len(risks)),                         (90, 100, 120)),
        ("Critical",       str(scan.get("critical_count", 0)),     (190, 30, 30)),
        ("High",           str(scan.get("high_count", 0)),         (210, 80, 10)),
    ]
    total_w = pdf.w - pdf.l_margin - pdf.r_margin
    gap = 3
    box_w = (total_w - gap * (len(stats) - 1)) / len(stats)
    box_h = 24
    y0 = pdf.get_y()
    for i, (label, value, color) in enumerate(stats):
        _summary_box(pdf, label, value, color,
                     x=pdf.l_margin + i * (box_w + gap),
                     y=y0, w=box_w, h=box_h)

    pdf.ln(box_h + 8)
    pdf.set_text_color(0, 0, 0)


def _render_summary(pdf: _ReportPDF, scan: dict) -> None:
    """Plain-English executive summary paragraph."""
    _section_heading(pdf, "Executive Summary")

    if "error" in scan:
        pdf.set_font("Helvetica", "", 11)
        pdf.set_text_color(180, 30, 30)
        _body_text(pdf, f"Scan error: {scan['error']}")
        return

    hosts = scan.get("hosts_found", 0)
    network = scan.get("network", "your network")
    risks = scan.get("security_risks", [])
    critical = scan.get("critical_count", 0)
    high = scan.get("high_count", 0)
    medium = sum(1 for r in risks if r["severity"] == "MEDIUM")

    if critical > 0:
        overall = (
            "CRITICAL issues were found that expose devices on your network to immediate "
            "risk of ransomware, complete takeover, or data theft. These require urgent action."
        )
    elif high > 0:
        overall = (
            "High-severity issues were found that significantly increase your network's "
            "exposure to attacks. These should be addressed as soon as possible."
        )
    elif medium > 0:
        overall = (
            "Moderate-severity issues were found. While not immediately critical, "
            "they represent real security gaps that should be closed."
        )
    elif risks:
        overall = (
            "Only low-severity findings were detected. Your network is in relatively "
            "good shape, but the items below are worth reviewing."
        )
    else:
        overall = (
            "No significant security risks were detected on this scan. "
            "Your network appears to be well-configured."
        )

    parts = [
        f"A network scan of {network} found {hosts} connected device{'s' if hosts != 1 else ''}. "
        f"The scan identified {len(risks)} security finding{'s' if len(risks) != 1 else ''} "
        f"across {hosts} device{'s' if hosts != 1 else ''}. {overall}"
    ]

    if critical:
        parts.append(
            f"There {'are' if critical > 1 else 'is'} {critical} CRITICAL "
            f"finding{'s' if critical > 1 else ''}  -  these should be resolved before "
            f"anything else. Critical findings typically mean a service is running with "
            f"no encryption or is a known ransomware entry point."
        )
    if high:
        parts.append(
            f"There {'are' if high > 1 else 'is'} {high} HIGH severity "
            f"finding{'s' if high > 1 else ''} that significantly raise your exposure "
            f"to attack. These represent services that are frequently targeted and "
            f"have a strong track record of being exploited."
        )
    if not risks:
        parts.append(
            "No devices on this network had monitored risky ports open. "
            "Continue practicing regular patching and reviewing who has network access."
        )

    pdf.set_font("Helvetica", "", 10.5)
    pdf.set_text_color(30, 41, 59)
    for para in parts:
        _body_text(pdf, para)
        pdf.ln(2)
    pdf.ln(3)


def _render_findings(pdf: _ReportPDF, scan: dict) -> None:
    """One card per security risk, sorted by severity."""
    risks = scan.get("security_risks", [])
    if not risks:
        return

    _section_heading(pdf, "Security Findings")

    pdf.set_font("Helvetica", "", 9.5)
    pdf.set_text_color(90, 105, 125)
    _body_text(
        pdf,
        f"The {len(risks)} finding{'s' if len(risks) != 1 else ''} below are listed from most "
        f"to least severe. Each entry explains what the finding is, why it is a problem, "
        f"and practical steps to fix it."
    )
    pdf.ln(4)

    for risk in risks:
        _render_finding_card(pdf, risk)


def _render_finding_card(pdf: FPDF, risk: dict) -> None:
    """Render a single finding with what/why/fix explanation."""
    service  = risk.get("service", "Unknown")
    severity = risk.get("severity", "LOW")
    port     = risk.get("port", "?")
    host     = risk.get("host", "?")
    hostname = risk.get("hostname", host)
    raw_desc = risk.get("description", "")

    explanation = RISK_EXPLANATIONS.get(service)

    # Page break if insufficient space (approximate 55mm per card)
    if pdf.get_y() > pdf.h - pdf.b_margin - 55:
        pdf.add_page()

    sev_color = SEVERITY_COLORS.get(severity, (100, 116, 139))
    card_x = pdf.l_margin
    card_y = pdf.get_y()
    card_w = pdf.w - pdf.l_margin - pdf.r_margin

    # Left severity stripe
    pdf.set_fill_color(*sev_color)
    pdf.rect(card_x, card_y, 3.5, 11, style="F")

    # Finding heading
    pdf.set_xy(card_x + 7, card_y + 1)
    pdf.set_font("Helvetica", "B", 12)
    pdf.set_text_color(15, 23, 42)
    title_w = card_w - 7 - 28
    pdf.cell(title_w, 6, f"{service}  (Port {port})", new_x=XPos.RIGHT, new_y=YPos.TOP)

    # Severity chip top-right
    _severity_chip(pdf, severity, card_x + card_w - 26, card_y + 2)

    # Host info line
    pdf.set_xy(card_x + 7, card_y + 8)
    pdf.set_font("Helvetica", "", 8.5)
    pdf.set_text_color(110, 125, 145)
    display_host = f"{hostname} ({host})" if hostname != host else host
    pdf.cell(0, 5, f"Detected on: {display_host}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(2)

    # Content
    if explanation:
        what, why, fix = explanation
        _labeled_block(pdf, "What this means", what, indent=6)
        _labeled_block(pdf, "Why this is a problem", why, indent=6)
        _labeled_block(pdf, "How to fix it", fix, indent=6)
    else:
        _labeled_block(pdf, "Description", raw_desc, indent=6)

    # Divider
    pdf.ln(2)
    pdf.set_draw_color(215, 225, 235)
    y_div = pdf.get_y()
    pdf.line(card_x, y_div, card_x + card_w, y_div)
    pdf.ln(6)


def _render_devices(pdf: _ReportPDF, scan: dict) -> None:
    """Device inventory  -  one entry per discovered device."""
    devices = scan.get("devices", [])
    if not devices:
        return

    _section_heading(pdf, "Device Inventory")

    network = scan.get("network", "your network")
    pdf.set_font("Helvetica", "", 9.5)
    pdf.set_text_color(90, 105, 125)
    _body_text(
        pdf,
        f"All {len(devices)} device{'s' if len(devices) != 1 else ''} discovered on {network}. "
        f"Only ports in the security-monitored list were scanned."
    )
    pdf.ln(4)

    for dev in devices:
        _render_device_row(pdf, dev)


def _render_device_row(pdf: FPDF, device: dict) -> None:
    """Render one device entry in the inventory."""
    ip        = device.get("ip", "?")
    hostname  = device.get("hostname", ip)
    vendor    = device.get("vendor", "")
    ports     = device.get("open_ports", [])
    dev_risks = device.get("risks", [])

    if pdf.get_y() > pdf.h - pdf.b_margin - 32:
        pdf.add_page()

    # IP / hostname title
    pdf.set_font("Helvetica", "B", 10.5)
    pdf.set_text_color(20, 35, 55)
    display = ip if hostname == ip else f"{ip}   -   {hostname}"
    pdf.cell(0, 6, display, new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    # Vendor
    if vendor and vendor.lower() not in ("unknown device", "unknown", ""):
        pdf.set_x(pdf.l_margin + 4)
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(80, 95, 115)
        pdf.cell(0, 5, f"Identified as: {vendor}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    # Open ports
    if ports:
        port_strs = []
        for p in ports:
            entry = f"{p['port']}/{p.get('service', '?')}"
            if p.get("product"):
                entry += f" ({p['product']})"
            port_strs.append(entry)
        pdf.set_font("Helvetica", "", 8.5)
        pdf.set_text_color(80, 95, 115)
        _body_text(pdf, "Open ports: " + ", ".join(port_strs), indent=4)
    else:
        pdf.set_x(pdf.l_margin + 4)
        pdf.set_font("Helvetica", "I", 8.5)
        pdf.set_text_color(130, 145, 165)
        pdf.cell(0, 5, "No monitored ports open.", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    # Risk summary for this device
    if dev_risks:
        risk_parts = [f"{r['severity']}: {r['service']} (port {r['port']})" for r in dev_risks]
        pdf.set_font("Helvetica", "I", 8.5)
        pdf.set_text_color(170, 50, 50)
        _body_text(pdf, "Risks: " + " | ".join(risk_parts), indent=4)

    pdf.ln(2)
    pdf.set_draw_color(215, 225, 235)
    pdf.line(pdf.l_margin, pdf.get_y(), pdf.w - pdf.r_margin, pdf.get_y())
    pdf.ln(4)


# ── Public API ────────────────────────────────────────────────────────────────

def generate_pdf(scan_results: dict) -> bytes:
    """
    Generate a PDF security report from a scan result dict (as returned by
    scanner.run_network_scan).

    Returns raw PDF bytes suitable for sending as an HTTP response or
    writing to a file.
    """
    timestamp = datetime.now().strftime("%B %d, %Y at %I:%M %p")
    network   = scan_results.get("network", "Unknown Network")

    pdf = _ReportPDF(network=network, timestamp=timestamp)
    pdf.add_page()

    _render_cover(pdf, scan_results, timestamp)
    _render_summary(pdf, scan_results)
    _render_findings(pdf, scan_results)
    _render_devices(pdf, scan_results)

    return bytes(pdf.output())
