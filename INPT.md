#  INTERNAL PENETRATION TEST


[Virtual Infosec Africa,(Cyberlab KNUST)](https://virtualinfosecafrica.com) [Department of Telecommunications Engineering](https://teleng.knust.edu.gh/)
___
Submitted by:
Agbugblah Nathaniel


[Github Url](https://github.com/EsselKobby/VIA-LAB)

___

## Table of Contents

- [INTERNAL PENETRATION TEST](#internal-penetration-test)
          - [Ethical Hacking Bootcamp](#ethical-hacking-bootcamp)
  - [Table of Contents](#table-of-contents)
    - [Executive Summary](#executive-summary)
    - [Analysis of Overall Security Posture](#analysis-of-overall-security-posture)
    - [Key Recommendations](#key-recommendations)
    - [Testing Methodology](#testing-methodology)
     - [HOSTS DISCOVERY](#hosts-discovery)
            - [SUBDOMAIN ENUMERATION](#subdomain-enumeration)
        - [SERVICE DISCOVERY](#service-discovery)
              - [NMAP,SERVICE DISCOVERY \& PORT SCANNING](#nmapservice-discovery--port-scanning)
              - [Nmap Service Discovery Output](#nmap-service-discovery-output)
        - [VULNERABILITY SCANNING](#vulnerability-scanning)
            - [DETAILED FINDINGS](#detailed-findings)
              - [APACHE 2.4.49(SSL \& HTTP)](#apache-2449ssl--http)
            - [Finding Summary](#finding-summary)
            - [Evidence](#evidence)
            - [Affected Resources:](#affected-resources)
            - [Recommendations:](#recommendations)
            - [References:](#references)
              - [SQL 5.6.49 (mysql)](#sql-5649-mysql)
            - [Finding Summary](#finding-summary-1)
            - [Evidence](#evidence-1)
            - [Affected Resources:](#affected-resources-1)
            - [Recommendations:](#recommendations-1)
            - [References:](#references-1)
              - [RealVNC 5.3.2 (vnc)](#realvnc-532-vnc)
            - [Finding Summary](#finding-summary-2)
            - [Evidence](#evidence-2)
            - [Affected Resources:](#affected-resources-2)
            - [Recommendations:](#recommendations-2)
            - [References:](#references-2)
              - [rdp MICROSOFT TERMINAL SERVICES (rdp)](#rdp-microsoft-terminal-services-rdp)
            - [Finding Summary](#finding-summary-3)
            - [Evidence](#evidence-3)
            - [Affected Resources:](#affected-resources-3)
            - [Recommendations:](#recommendations-3)
            - [References:](#references-3)
           - [THE 'CEWL' TOOL](#the-cewl-tool)
       - [WEB-BASED ATTACK SURFACES](#web-based-attack-surfaces)
          - [CVSS v3.0 Reference Table](#cvss-v30-reference-table)
            
        
___
    

### Executive Summary

This report summarizes the internal network penetration test conducted on the IP range 10.10.10.0/24 for Virtual Infosec Africa, evaluating the security of the network infrastructure through targeted assessments. Using **Nmap** for host and service discovery, several active devices and critical services (HTTP, SSH, FTP) were identified, some running outdated versions or misconfigured settings. Following this, **Metasploit** was employed for vulnerability scanning, uncovering multiple high-risk vulnerabilities, including unpatched software and misconfigured services that could allow unauthorized access. Additionally, **Eyewitness** was used to assess web application security, revealing known vulnerabilities and improper configurations in several web applications that could lead to sensitive data exposure. The findings highlight significant security gaps that require immediate attention, with specific recommendations for patch management, service hardening, and improvements in web application security to enhance the overall security posture of the network.
___
### Analysis of Overall Security Posture

The penetration test identified several critical vulnerabilities within the network infrastructure, indicating a compromised security posture. During the host and service discovery phase, multiple active devices with open ports and outdated or misconfigured services were found, suggesting susceptibility to various attacks, including unauthorized access and exploitation of known vulnerabilities. The presence of unpatched services, particularly for critical roles such as HTTP and SSH, significantly increases the risk of exploitation by potential attackers.

Moreover, vulnerability scanning with Metasploit revealed serious security flaws, including unpatched software and configuration issues that could be exploited for unauthorized access. The analysis of the web application surface using Eyewitness also uncovered vulnerabilities that could result in data breaches or system compromises. Taken together, these findings underscore the urgent need for a comprehensive security overhaul. Implementing recommended remediation strategies—such as regular patching, service hardening, and securing web applications—is essential for strengthening the network and mitigating potential threats. Without these enhancements, the network remains at risk of exploitation and breaches.

___

### Key Recommendations
* Ensure that all software is kept up to date with the latest security patches and establish a consistent patch management process.
* Evaluate and close unnecessary open ports while strengthening the configurations of critical services.
* Enhance authentication measures by implementing multifactor authentication (MFA) and applying the principle of least privilege to user accounts and services.
* Conduct regular vulnerability assessments and penetration tests, prioritizing and addressing high-risk vulnerabilities without delay.
* Review and secure web applications by implementing web application firewalls (WAFs) and following secure coding standards.
* Enable comprehensive logging and monitoring to identify suspicious activities, and create or regularly update an incident response plan.

___

### Testing Methodology

The penetration test commenced with a comprehensive **Host and Service Discovery** phase utilizing Nmap, a popular network scanning tool. This phase involved scanning the designated IP range (10.10.10.0/24) to identify active hosts and catalog the services operating on their ports. By mapping the network and documenting open ports and services, this step laid the groundwork for understanding the network's architecture and potential entry points for further exploitation.

Next, the **Vulnerability Scanning** phase leveraged Metasploit to evaluate the identified services for known vulnerabilities. This automated scanning process aimed to identify weaknesses such as outdated software, unpatched vulnerabilities, and misconfigurations that attackers could exploit. The findings underscored critical security issues, allowing for the prioritization of remediation efforts based on the severity of the vulnerabilities uncovered.

Lastly, the **Web Application Security Assessment** was performed using Eyewitness, focusing on the security of web applications within the network. This tool documented the web services present and assessed their security posture, identifying vulnerabilities and misconfigurations that could result in data breaches or system compromises. The goal of this phase was to provide insights into the security of web applications and recommend strategies to strengthen defenses against potential attacks.
___

### HOSTS DISCOVERY

The Nmap tool was utilized to scan for hosts within the specified network scope. The command used for host discovery is as follows:

![hostdiscover](/assets/hostdiscover.jpg)

The output from the host discovery was filtered to extract the IP addresses using the grep and awk commands. The filtering command is as follows:

![hostfilter](/assets/hostfilter1.jpg)

##### SUBDOMAIN ENUMERATION

The subdomain enumeration was done using the **aiodnsbrute** on the hosts in the network scope(10.10.10.1/24)

![aiodnsbrute](/assets/aiodnsbrute.jpg)

___

### SERVICE DISCOVERY
Service discovery is crucial for identifying and understanding the services running on a network, including the ports they're using. This process not only highlights the available services but also provides insights into the network's attack surface.

By pinpointing specific services and their versions, testers can identify potential vulnerabilities associated with them, allowing for proactive measures against potential threats. For instance, if a service is outdated or misconfigured, it could serve as an entry point for attackers.

Port scanning complements service discovery by identifying open ports, which act as gateways for communication between devices. Knowing which ports are open helps testers determine which services are accessible and might possess vulnerabilities. An open port running an outdated or misconfigured service could expose the network to exploitation, making both service discovery and port scanning essential components of a robust security strategy.
###### NMAP,SERVICE DISCOVERY & PORT SCANNING

Service discovery and port scanning were conducted using the Nmap tool. Below are the command used, its output, and various file formats generated from the scan. 

![NmapService](/assets/nmapservice.jpg)

The **HTTP** service scan discovery using the nmap tool is show below:

![NmapServiceHttp](/assets/nmapservice_http.jpg)

###### Nmap Service Discovery Output

![nmapserviceoutput](/assets/servicescantype.png)

---

### VULNERABILITY SCANNING
##### DETAILED FINDINGS



###### APACHE 2.4.49(SSL & HTTP)

**Apache 2.4.49 Analysis**

|Current Rating|CVSS            |
|    ---       |   ---          |
|    High      |         8.8    |

##### Finding Summary
A vulnerability was identified in APACHE HTTP Server 2.4.49 that allows attackers to conduct path traversal attacks, potentially mapping URLs to files beyond the intended directories specified by Alias configurations. If these files lack the default protection setting of "require all denied," attackers may successfully access them. Furthermore, if CGI scripts are enabled in these aliased paths, this could lead to remote code execution, significantly increasing the risk of exploitation.

##### Evidence

The **Metasploit Auxiliary Module** was utilized to perform a vulnerability scan on the HTTP server, as demonstrated below:

![apache http](/assets/apachehttp.png)

##### Affected Resources:

  10.10.10.2,  10.10.10.30,   10.10.10.45,      10.10.10.55


##### Recommendations:

* **Upgrade Apache**: Move to Apache HTTP Server 2.4.51 or a later version to address these vulnerabilities.
* **Secure Aliased Directories**: Ensure proper configuration and protection of Alias and AliasMatch directives.
* **Enforce Access Controls**: Apply "Require all denied" settings where applicable.
* **Disable CGI Scripts**: Turn off CGI scripts in aliased directories unless absolutely necessary.
* **Review Configurations**: Conduct regular audits of directory configurations and access controls.
* **Implement Rate Limiting**: Utilize modules like mod_evasive to manage request rates and reduce the risk of DoS attacks.
* **Monitor Server Performance**: Employ monitoring tools to identify and respond to any unusual server activity.

##### References:

[https://www.cve.org/CVERecord?id=CVE-2021-42013](https://www.cve.org/CVERecord?id=CVE-2021-42013)



###### SQL 5.6.49 (mysql)

**MySQL 5.6.49  Analysis**

|Current Rating|CVSS            |
|    ---       |   ---          |
|    Medium      |         4.3    |

##### Finding Summary

The remote host is currently running MySQL version 5.6.x, up to and including 5.6.48, which is known to be vulnerable to multiple security issues. Specifically, **CVE-2020-14539** impacts the MySQL Server's optimizer, allowing low-privileged attackers with network access to trigger a denial of service by causing the server to hang or crash. Similarly, **CVE-2020-14550** affects the MySQL Client's C API, enabling comparable denial of service attacks. Additionally, **CVE-2020-1967** concerns MySQL Connectors that utilize OpenSSL, permitting unauthenticated attackers with network access via TLS to induce a denial of service. These vulnerabilities affect MySQL versions up to 5.6.48, 5.7.30, and 8.0.20, as identified from the reported version number, given that Nessus has not conducted direct tests on these vulnerabilities.


##### Evidence

##### Evidence

The *Metasploit Auxiliary Module* was employed to conduct a vulnerability scan on the MySQL server, as detailed below:

![mysql img](/assets/mysql.png)

##### Affected Resources:

  10.10.10.5, 10.10.10.40


##### Recommendations:

##### Recommendations:

* **Upgrade MySQL**: Update to the latest stable version of MySQL that includes fixes for the identified vulnerabilities. For users on MySQL 5.6, consider transitioning to a more recent, supported version such as MySQL 5.7.x or 8.0.x, if feasible.
* **Check for Patches**: Review MySQL release notes and apply all relevant security patches that address these vulnerabilities. Ensure your system is fully patched with the latest updates to mitigate the identified risks.
* **Regular Backups**: Maintain current backups of your MySQL databases, ensuring they are stored securely and can be quickly restored in the event of an attack or system failure.
* **Test Recovery Procedures**: Periodically test your backup and recovery processes to verify they function correctly and can be executed promptly in an emergency situation.
* **Restrict Network Access**: Limit network access to your MySQL server through firewall rules or network segmentation. Only permit connections from trusted IP addresses and networks to minimize the risk of exploitation.

##### References:

[https://www.tenable.com/plugins/nessus/138571](https://www.tenable.com/plugins/nessus/138571)

###### RealVNC 5.3.2 (vnc)
*RealVNC 5.3.2   Analysis*

|Current Rating|CVSS            |
|    ---       |   ---          |
|    High      |         7.8    |

##### Finding Summary
There are several vulnerabilities associated with VNC Viewer and Server that require attention. **CVE-2008-4770** affects VNC Viewer versions 4.0 to 4.4.2, allowing a remote VNC Server to execute arbitrary code via crafted RFB protocol data. Additionally, **CVE-2008-3493** can lead to a denial of service (application crash) in VNC Viewer version 4.1.2.0 through a malicious framebuffer update packet. **CVE-2006-2369** represents a significant risk in VNC Enterprise Edition 4.1.1 and other RealVNC products, enabling remote attackers to bypass authentication via insecure security type requests. Finally, **CVE-2004-1750** impacts VNC Server versions 4.0 and earlier, allowing denial of service through an overwhelming number of connections to port 5900. For further information on additional security issues related to VNC, please contact the Help Center.


##### Evidence

The *Metasploit Auxiliary Module* was utilized to perform a vulnerability scan on the RealVNC server, as illustrated below:

![vnc img](/assets/vnc.png)

##### Affected Resources:

10.10.10.10, 10.10.10.50


##### Recommendations:

* **Update VNC Viewer**: Upgrade to the latest version of VNC Viewer that addresses the vulnerabilities identified in CVE-2008-4770 and CVE-2008-3493. Ensure that you are using a patched version.
* **Review Authentication Settings**: Regularly assess and update authentication settings to align with best security practices, preventing unauthorized access.
* **Apply Security Patches**: Consistently check for and implement security patches provided by VNC software vendors to ensure your systems are equipped with the latest updates.
* **Conduct Vulnerability Assessments**: Perform routine security audits and vulnerability assessments on your VNC installations to identify and mitigate any new or existing security risks.
* **Review Logs**: Regularly examine VNC server logs for unusual activity or signs of attempted exploitation, and respond promptly to any suspicious incidents.
* **Monitor and Limit Connections**: Monitor the number of connections to port 5900 and implement rate limiting or connection limits to help mitigate potential denial of service attacks.

##### References:

[https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=realvnc+5.3.2](https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=realvnc+5.3.2)


###### rdp MICROSOFT TERMINAL SERVICES (rdp)
**rdp  Analysis**

|Current Rating|CVSS            |
|    ---       |   ---          |
|    Critical      |         9.8    |

##### Finding Summary

Various versions of xrdp prior to 0.10.0 are susceptible to **CVE-2024-39917**, which enables attackers to bypass the `MaxLoginRetry` configuration parameter, allowing for an unlimited number of login attempts. In FreeRDP, **CVE-2023-40576** pertains to an Out-Of-Bounds Read in the `RleDecompress` function, stemming from insufficient data length in the `pbSrcBuffer` variable, which may lead to errors or crashes. Additionally, **CVE-2023-40575** affects FreeRDP with an Out-Of-Bounds Read in the `general_YUV444ToRGB_8u_P3AC4R_BGRX` function, resulting in crashes due to inadequate data in the `pSrc` variable. Both FreeRDP vulnerabilities have been resolved in version 3.0.0-beta3, and users are strongly advised to upgrade, as no known workarounds exist.


##### Evidence

The **Metasploit Auxiliary Module** was used to scan for vulnerabilities on the rdp server which is shown below:

![rdp img](/assets/rdp.png)

##### Affected Resources:

10.10.10.11, 10.10.10.31, 10.10.10.60


##### Recommendations:

* **Implement Rate Limiting**: If an immediate upgrade is not feasible, consider introducing rate-limiting mechanisms at the network level to reduce excessive login attempts.
* **Monitor for Exploits**: Stay informed about security advisories and updates related to FreeRDP to ensure timely application of any additional patches or enhancements.
* **Implement Monitoring and Alerts**: Establish monitoring and alerting systems to promptly detect unusual activities and potential security incidents.
* **Apply Security Patches**: Regularly review and apply security patches and updates for all software to address vulnerabilities effectively.
* **Upgrade xrdp**: Update to xrdp version 0.10.0 or later, which contains the fix for the login attempt issue.


##### References:

[https://www.cve.org/CVERecord](https://www.cve.org/CVERecord?id=CVE-2023-40576)

---


#### THE 'CEWL' TOOL

CEWL (Custom Word List generator) is a command-line utility designed to create tailored word lists for password cracking and security testing. It functions by spidering websites to extract words from various content types, including HTML, JavaScript, and other text elements. CEWL offers users the ability to customize several parameters, such as minimum and maximum word length, crawling depth, and the inclusion of specific file types, making it a flexible tool for generating targeted word lists based on website content.

The **cewl** tool was employed to develop a custom word list by targeting the company’s website, [Virtual Infosec Africa](https://www.virtualinfosecafrica.com).


### WEB-BASED ATTACK SURFACES

###### THE EYEWITNESS TOOL

**EyeWitness** is a powerful open-source tool designed for web application reconnaissance and assessment. It automates the process of capturing screenshots of web servers and applications by spidering a list of URLs or IP addresses. Supporting both HTTP and HTTPS protocols, EyeWitness can handle various types of web applications, providing visual snapshots that help evaluate web server configurations, identify exposed services, and conduct security assessments. This tool is especially beneficial for security professionals and penetration testers who need to quickly gather visual data about web assets and their vulnerabilities.

The screenshots of web servers generated using **EyeWitness** are created from a prepared list of HTTP and HTTPS hosts, which is saved in a file. The command used to process the list of URLs with EyeWitness is shown below:

![eyewitness img](/assets/eyewitness1.png)

###### Eyewitness Output

![eyewitness output](/assets/eyewitness.png)


###### THE MFSVENOM TOOL

**msfvenom** is a powerful tool within the Metasploit Framework, designed for generating custom payloads for exploitation and penetration testing. It enables security professionals to create a wide variety of payloads, including reverse shells, bind shells, and Meterpreter sessions, in multiple formats such as executables, scripts, and documents. By allowing users to specify payload types, options like local or remote ports, and output formats (e.g., executable, script, or shellcode), msfvenom facilitates the crafting of tailored payloads for specific testing scenarios. It is widely utilized to generate payloads for attacks against identified vulnerabilities, thereby aiding in the assessment of system security and the response to potential threats.

###### PAYLOAD GENERATION

**Web Server: Apache Tomcat (Java-based)**; **Host: 10.10.10.55**

The Metasploit tool, *msfvenom*, was utilized to generate payloads specifically tailored for the Java-based web server. The results are displayed below:

![java img](/assets/java.png)

A specific payload was selected to trigger a TCP bind shell when executed by an attacker. The details of the output are shown below:

![java img](/assets/javapayload.png)

The resulted payload was then saved in the *payload.war*, The Java Based web server payload has an extension of *war*. The output of this process is further shown below: 

![javafile img](/assets/javafile.png)

**Web Server: Python server(base64 encode)**; **Host:10.10.10.30**

The Metasploit tool, *msfvenom*, was utilized to generate payloads specifically tailored for the Python-based web server. The results are displayed below:

![java img](/assets/python.png)

A specific payload was selected to execute base64 encoding. The details of the output are shown below:

![java img](/assets/pythonpayload.png)

The resulted payload was then saved in the *payload.cmd*, The Python server payload has an extension of *cmd*. The output of this process is further shown below: 

![javafile img](/assets/pythonfile.png)

---
## CVSS v3.0 Reference Table

| Qualitative Rating |  CVSS Score |
| ---                |        ---  |
|**None/Informational**|      N/A  |
|**Low**             |0.1 - 3.9    |
|**Medium**          |4.0 - 6.9    |
|**High**            |7.0 - 8.9    |
|**Criticial**       | 9.0 - 10.0  |

##### Table1: Common Vulnerability Scoring System Version 3.0