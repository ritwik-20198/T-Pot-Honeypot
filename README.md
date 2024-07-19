# T-Pot-Honeypot
Executed an independent project involving the deployment, configuration, and implementation of a honeypot on multiple **Amazon Web Services (AWS)** and **Google Cloud Platform (GCP)** cloud instances based in London (As per reports, the _United Kingdom (UK)_ suffers more cyberattacks compared to any other European country), _Israel region (Tel Aviv)_ amidst the heightened tension between Israel and Palestine, _Korea region_ (constant conflict between North and South Korea) to gain insights into threat actor’s tactics, techniques, and procedures (TTPs) and malware behavior. 


## HONEYPOTS ANALYSED
Honeypots have been considered in such a way that they help the security analyst learn and understand various fields of cybersecurity. Email security (Mailoney), Mobile Security (ADBhoney), and Network Security (Citrix honeypot, Ddospot) have been analysed in this project. 

### Mailoney honeypot
Mailoney is a type of SMTP honeypot written in Python and runs on SMTP port 25. Mailoney module has different modes of operation such as open_relay (logging all emails attempted to be sent), postfix_creds (used to log credentials from login attempts) and schizo_open_relay (which allows you to log everything). It acts as SMTP email relay server and captures all the emails being tried to be forwarded by it. Mailoney is a Spam honeypot that can be used to detect spam emails.

### ADBhoney Honeypot
The Android Debug Bridge or ADB is a type of protocol that is implemented to monitor and communicate with Android devices. ADB is enabled by default on devices when shipped by manufacturers for developers for initial setup. However, when these devices are sold in the market, their port 5555 is still enabled to allow users to communicate with the device with the same elevated privileges (root) as developers. This increases the attack surface for threat actors. 
ADBHoney is a low-interaction honeypot that is particularly designed for Android Debug Bridge over TCP/IP. It is used to catch whichever malware the attacker is pushing to innocent victims which have port 5555 exposed.

### Citrix honeypot
Citrix Honeypot has been developed to log and analyse exploit attempts on the critical (9.8 CVSS) vulnerability CVE-2019-19781 in Citrix Application Delivery Controller (ADC) and Gateway that allows directory traversal.

### Ddospot honeypot
DDosPot is a type of low-interaction honeypot used for logging and detection of UDP-based Distributed Denial of Service (DDoS) attacks. It uses ports 19, 53, 123, 1900 for detection. The platform presently accommodates various honeypot services and servers (DNS, NTP, SSDP, CHARGEN, UDP) through user-friendly plugins known as "pots":

|Honeypot                |Port               |Protocol                         |
|----------------|-------------------------------|-----------------------------|
|ADBHoney|`5555` |TCP   |
|CitrixHoneypot|`443`  |TCP |
|Ddospot|`19, 53, 123, 1900`|UDP|
|Mailoney|`25`|TCP|

## _Firewall Rule Setup_
In order to allow traffic into our instance’s individual honeypot ports, ingress traffic rules/VPC firewall rules were customised.

In order to allow traffic into our instance’s individual honeypot ports, we need to setup/modify ingress traffic rules on the Firewall. To do so, we head to VPC firewall rules and create custom firewall rules with the following configuration:

- Traffic Direction: **Ingress**

- Allowed Source IPs: **0.0.0.0/0** (a CIDR notation, IP block containing all possible IP addresses)

- Allowed Ports: **TCP (25, 80, 443, 5555, 64294, 64295, 64297)**

This rule allows any network traffic coming to the aforementioned ports directed towards the respective honeypots.

## HONEYPOT DATA ANALYSIS
All this traffic data is logged using Logstash (ELK stack) and visualized using Kibana dashboards. 

Leveraged **Amazon S3** for log storage of set-up honeypots, **AWS Glue** for ETL to build table schema, and **Athena** to query log tables via Glue data catalog.

To analyse the data visualisation of the threat landscape, the **Kibana** Dashboard and **Discover ** components of the **ELK stack** were utilised. Additionally, I utilized tools such as **VirusTotal, AbuseIPDB, MITRE Attack and Defend** framework to swiftly generate comprehensive reports for efficient analysis.
![](https://github.com/ritwik-20198/T-Pot-Honeypot/blob/2c01b279ea936559bc2e48817671d81da8ddb976/Honeypot%20Project%20SS/Dashboard.jpg)

Interpreted the TTPs used by threat actors in the case of observed ADBhoney-Mailoney attacks and mapped them to MITRE Attack and Defend framework provided actionable threat intelligence in the form of TTPs and security recommendations. 

## Key Highlights
- I was successfully able to **detect 1 million plus attacks** in Mailoney, ADBhoney and Citrix honeypot.
![](https://github.com/ritwik-20198/T-Pot-Honeypot/blob/2c01b279ea936559bc2e48817671d81da8ddb976/Honeypot%20Project%20SS/total%20attack%20metrics.jpg)
- Interestingly, I was able to **trackdown** an attack attempt on ADBhoney honeypot to **Trinity botnet malware** via examining the Kibana Discover logs and writing detection queries. On analysing the attack chain on Trinity malware I interpreted the TTPs, mapped them to MITRE Attack and Defend framework, provided IoCs and security recommendations.
-   I was also able to track an IP involved in famous **financial ‘419 scams’** by analysing SMTP log in my Mailoney instance.


## Skills showcased: 
Network Monitoring Tools · Cybercrime Investigation · Network Security Implementation · Cloud · Cyber Threat Hunting (CTH) · SOC analyst · Log analysis
