RESTful API

Interface Description

UPDATED: 17 June 2022

RESTful API

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights
reserved.

These materials and all Progress® software products are copyrighted and all rights are reserved by
Progress Software Corporation. The information in these materials is subject to change without
notice, and Progress Software Corporation assumes no responsibility for any errors that may appear
therein. The references in these materials to specific platforms supported are subject to change.

#1 Load Balancer in Price/Performance, 360 Central, 360 Vision, Chef, Chef (and design), Chef
Habitat, Chef Infra, Code Can (and design), Compliance at Velocity, Corticon, Corticon.js, DataDirect
(and design), DataDirect Cloud, DataDirect Connect, DataDirect Connect64, DataDirect XML
Converters, DataDirect XQuery, DataRPM, Defrag This, Deliver More Than Expected, DevReach (and
design), Driving Network Visibility, Flowmon, Inspec, Ipswitch, iMacros, K (stylized), Kemp, Kemp
(and design), Kendo UI, Kinvey, LoadMaster, MessageWay, MOVEit, NativeChat, OpenEdge, Powered
by Chef, Powered by Progress, Progress, Progress Software Developers Network, SequeLink,
Sitefinity (and Design), Sitefinity, Sitefinity (and design), Sitefinity Insight, SpeedScript, Stylized
Design (Arrow/3D Box logo), Stylized Design (C Chef logo), Stylized Design of Samurai, TeamPulse,
Telerik, Telerik (and design), Test Studio, WebSpeed, WhatsConfigured, WhatsConnected, WhatsUp,
and WS_FTP are registered trademarks of Progress Software Corporation or one of its affiliates or
subsidiaries in the U.S. and/or other countries.

Analytics360, AppServer, BusinessEdge, Chef Automate, Chef Compliance, Chef Desktop, Chef
Workstation, Corticon Rules, Data Access, DataDirect Autonomous REST Connector, DataDirect Spy,
DevCraft, Fiddler, Fiddler Classic, Fiddler Everywhere, Fiddler Jam, FiddlerCap, FiddlerCore,
FiddlerScript, Hybrid Data Pipeline, iMail, InstaRelinker, JustAssembly, JustDecompile, JustMock,
KendoReact, OpenAccess, PASOE, Pro2, ProDataSet, Progress Results, Progress Software, ProVision,
PSE Pro, Push Jobs, SafeSpaceVR, Sitefinity Cloud, Sitefinity CMS, Sitefinity Digital Experience Cloud,
Sitefinity Feather, Sitefinity Thunder, SmartBrowser, SmartComponent, SmartDataBrowser,
SmartDataObjects, SmartDataView, SmartDialog, SmartFolder, SmartFrame, SmartObjects,
SmartPanel, SmartQuery, SmartViewer, SmartWindow, Supermarket, SupportLink, Unite UX, and
WebClient are trademarks or service marks of Progress Software Corporation and/or its subsidiaries
or affiliates in the U.S. and other countries. Java is a registered trademark of Oracle and/or its
affiliates. Any other marks contained herein may be trademarks of their respective owners.

Please refer to the NOTICE.txt or Release Notes – Third-Party Acknowledgements file applicable to a
particular Progress product/hosted service offering release for any related required third-party
acknowledgements.

2

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

Table of Contents

1 Introduction

1.1 Document Purpose

1.2 Intended Audience

2 The RESTful API Interface

2.1 How the LoadMaster RESTful API Works

2.2 JSON-based Input and Output

2.3 Security

2.3.1 Configure Certificate-Based Authentication

2.3.1.1 Enable Session Management

2.3.1.2 Create a User (If Needed)

2.3.1.3 Enable Client Certificate Authentication on the LoadMaster

2.3.1.4 Generate and Download the Client Certificate

2.3.1.5 Specify the Certificate Details in the API

2.3.1.6 Create a PFX File (If Running Commands using a Web Browser)

2.3.2 How to Use API Keys

2.3.2.1 Delete an API Key

2.4 Enabling the LoadMaster RESTful API Interface

2.5 Using get and set commands

2.6 Error Reports

2.7 Notation

3 RESTful API Commands

3

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

19

19

19

20

20

21

22

23

23

24

24

26

27

27

28

28

29

29

30

30

31

RESTful API

3.1 Command Syntax

3.2 List All API Commands and get/set Parameters

3.3 Home Screen Information

3.3.1 Retrieve the LoadMaster Firmware Version

3.3.2 Retrieve the Boot Time and Active Time

3.3.3 Retrieve the Serial Number

3.3.4 Retrieve the Virtual Service and Real Service Statuses

3.3.5 Retrieve Licensing Information

3.4 Initial Configuration

3.4.1 Read the EULA

3.4.2 Accept the EULA and Set the License Type

3.4.3 Specify Whether or not to use the Kemp Analytics Feature

3.4.4 Retrieve the Available License Types

3.4.5 License the LoadMaster

3.4.6 Set the Initial Password

3.5 Licensing using the Activation Server Functionality

3.6 Virtual Services

3.6.1 Virtual Service Control

3.6.1.1 Properties

3.6.1.2 Basic Properties

3.6.1.3 Standard Options

3.6.1.4 SSL Properties

31

31

31

31

32

32

32

32

32

32

33

34

34

34

34

35

36

36

38

40

40

46

4

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3.6.1.4.1 TLSType Parameter

3.6.1.5 Advanced Properties

3.6.1.5.1 Upload Error File

3.6.1.5.2 Verify Parameter

3.6.1.6 WAF Settings

3.6.1.6.1 WAF InterceptOpts Parameter

3.6.1.6.2 Assign an WAF Rule to a Virtual Service

3.6.1.6.3 Unassign an WAF Rule from a Virtual Service

3.6.1.7 ESP Options

3.6.1.8 Real Servers

3.6.1.9 Miscellaneous

3.6.2 Adding a Virtual Service Using a Template

3.6.3 Manage Templates

3.6.3.1 Export a Virtual Service as a Template

3.6.3.2 Upload a Template

3.6.3.3 Display a List of Installed Templates

3.6.3.4 Delete a Template

3.6.4 Manage SSO

3.6.4.1 SSO Domains

3.6.4.1.1 Upload RSA Files

3.6.4.1.2 Upload an Identity Provider (IdP) Metadata File (if using SAML)

3.6.4.1.3 Download the Service Provider Certificate (if using SAML)

5

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

51

54

62

62

63

64

67

68

69

88

93

94

94

94

94

94

95

95

95

106

107

107

RESTful API

3.6.4.1.4 Sessions

3.6.4.2 SSO Image Sets

3.6.5 Cache Configuration

3.6.6 Compression Options

3.6.7 Kubernetes Settings

3.6.7.1 Upload a Kube Config File

3.6.7.2 Delete the Kube Config File

3.6.7.3 List the Contexts in the Kube Config File

3.6.7.4 Check the Operations Mode

3.6.7.5 Set the Operations Mode

3.6.7.6 Check the Namespace being Watched

3.6.7.7 Set the Namespace to Watch

3.6.7.8 Check the Watch Timeout

3.6.7.9 Set the Watch Timeout

3.6.7.10 Restart the Ingress Controller

3.6.8 Legacy WAF Settings

3.6.8.1 Commands Relating to Commercial Rule Files

3.6.8.1.1 Display the Commercial WAF Rule Settings

3.6.8.1.2 Enable Automatic Commercial Rule File Updates

3.6.8.1.3 Enable/Disable Automatic Installation of Commercial Rule File Updates

3.6.8.1.4 Set the Time of the Automatic Commercial Rule File Installation

3.6.8.1.5 Download WAF Commercial Rule File Updates Now

6

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

107

108

108

109

109

109

109

110

110

110

110

110

110

110

110

111

111

111

111

112

112

112

RESTful API

3.6.8.1.6 Display the WAF Rule Change Log

3.6.8.1.7 Manually Install Commercial Rule Files

3.6.8.2 Commands Relating to Custom Rule Files

3.6.8.2.1 Upload a Custom Rule File or Rule Set

3.6.8.2.2 Delete a Custom Rule File

3.6.8.2.3 Download a Custom Rule File

3.6.8.2.4 Upload a Custom Rule Data File

3.6.8.2.5 Delete a Custom Rule Data File

3.6.8.2.6 Download a Custom Rule Data File

3.6.8.3 Command Relating to Custom and Commercial Rules

3.6.8.3.1 List WAF Rules

3.6.8.4 Commands Relating to Remote Logging

3.6.8.4.1 Set the WAF Logging Format

3.6.8.4.2 Disable Remote Logging

3.6.8.4.3 Enable Remote Logging

3.6.8.4.4 Save Temporary WAF Remote Log Data

3.6.8.4.5 Clear Temporary WAF Remote Log Data

3.6.9 WAF Settings

3.6.9.1 OWASP Custom Rulesets

3.6.9.2 OWASP Custom Data File

3.6.9.3 OWASP Rules

3.7 Global Balancing

113

113

113

113

114

114

114

115

115

115

115

115

116

116

116

116

116

116

120

120

121

122

7

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3.7.1 Manage Fully Qualified Domain Names (FQDNs)

3.7.1.1 Add FQDN

3.7.1.2 Delete FQDN

3.7.1.3 List FQDNs

3.7.1.4 Show FQDN

3.7.1.5 Modify FQDN

3.7.1.6 Add Map

3.7.1.7 Modify a Map

3.7.1.8 Delete a Map

3.7.1.9 Change the Location of a Map

3.7.1.10 Add a Location

3.7.1.11 Remove a Location

3.7.1.12 Change Checker Address

3.7.1.13 Additional Records

3.7.2 Manage Clusters

3.7.2.1 List Clusters

3.7.2.2 Show Cluster

3.7.2.3 Add Cluster

3.7.2.4 Delete Cluster

3.7.2.5 Modify Cluster

3.7.2.6 Change Cluster Location

3.7.3 Miscellaneous Params

122

122

122

122

123

124

128

128

130

130

131

132

133

133

134

134

134

134

134

135

135

136

8

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3.7.3.1 List the Miscellaneous Parameters

3.7.3.2 Modify Miscellaneous Parameters

3.7.3.3 Upload a Location Data Patch File

3.7.4 IP Range Selection Criteria

3.7.4.1 List the IP Addresses

3.7.4.2 Show IP Address Details

3.7.4.3 Add IP Address

3.7.4.4 Delete IP Address

3.7.4.5 Change the Location for an IP Address

3.7.4.6 Delete IP Location

3.7.4.7 Add IP Country

3.7.4.8 Remove IP Country

3.7.4.9 List the Custom Locations

3.7.4.10 Add a Custom Location

3.7.4.11 Edit a Custom Location

3.7.4.12 Delete a Custom Location

3.7.5 IP Access List Settings

3.7.5.1 Retrieve the IP Access List Settings

3.7.5.2 Enable/Disable Automatic IP Access List Updates

3.7.5.3 Enable/Disable Automatic Installation of the IP Access List Updates

3.7.5.4 Set the Time of the Automatic Installation

3.7.5.5 Download the Updates Now

9

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

136

136

139

139

139

139

139

139

140

140

140

141

141

141

141

141

141

141

142

142

142

142

RESTful API

3.7.5.6 Install the Updates Now

3.7.5.7 View the Access List

3.7.5.8 View Changes to the Access List

3.7.5.9 View the User-Defined Allow List

3.7.5.10 Add an Address to the Allow List

3.7.5.11 Remove an IP Address or Network from the Allow List

3.7.6 Configure DNSSEC

3.7.6.1 Generate the Key Signing Keys (KSKs)

3.7.6.2 Import the KSKs

3.7.6.3 Delete the KSK Files

3.7.6.4 Enable/Disable DNSSEC

3.7.6.5 Retrieve the DNSSEC Configuration Settings

3.7.7 GSLB Statistics

3.7.8 Enable/Disable GEO

3.7.8.1 Check if GEO is Enabled

3.7.8.2 Enable GEO

3.7.8.3 Disable GEO

3.8 Statistics

3.9 SDN Statistics

3.10 Real Servers

3.10.1 Enabling/Disabling Real Servers

3.10.1.1 Globally Enable/Disable a Real Server

142

142

142

142

143

143

143

143

143

143

143

144

144

144

144

144

144

144

157

165

168

168

10

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3.10.1.2 Locally Enable/Disable a Real Server

3.11 Rules & Checking

3.11.1 Show Rules

3.11.2 Delete a Rule from the System

3.11.3 Add/Modify a Rule on the System

3.11.4 Add/Delete Real Server Rule

3.11.5 Add/Delete SubVS Rule

3.11.6 Add Virtual Service Rules

3.11.7 Delete Virtual Service Rules

3.11.8 Check Parameters

3.12 Certificates & Security

3.12.1 Certificate Management

3.12.2 Let's Encrypt Certs

3.12.2.1 Register a Let's Encrypt Account

3.12.2.2 Get an existing Let's Encrypt account

3.12.2.3 Let's Encrypt Global Parameters

3.12.2.4 Request a New Certificate from Let's Encrypt

3.12.2.5 Renew a Let's Encrypt Certificate

3.12.2.6 Delete a Let's Encrypt Certificate

3.12.2.7 List the Let's Encrypt Certificates

3.12.2.8 Get the Let's Encrypt Account Information

3.12.2.9 Get Details about a Specific Let's Encrypt Certificate

168

169

169

169

169

175

176

176

177

177

179

179

181

181

182

182

182

183

183

183

183

184

11

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3.12.3 Cipher Sets

3.12.3.1 Modify a Custom Cipher Set/Create a New Custom Cipher Set

3.12.3.2 Retrieve the Details of an Existing Cipher Set

3.12.3.3 Delete a Custom Cipher Set

3.12.4 Remote Access

3.12.4.1 Set Admin Access

3.12.4.2 Get GEO Partner Status

3.12.4.3 WUI Authentication and Authorization Options

3.12.5 Admin WUI Access

3.12.6 OCSP Configuration

3.12.7 LDAP Configuration

3.12.7.1 Add an LDAP Endpoint

3.12.7.2 Modify an LDAP Endpoint

3.12.7.3 Delete an LDAP Endpoint

3.12.7.4 Retrieve Details of All LDAP Endpoints

3.12.7.5 Retrieve Details of a Specific LDAP Endpoint

3.12.8 Intrusion Detection Options (IPS/IDS)

3.13 Interfaces

3.13.1 Get Interface Details

3.13.2 Modify Interface Details

3.13.3 Additional Addresses

3.13.4 Bonded Interfaces

184

184

184

185

185

190

190

190

194

198

199

199

200

202

202

202

202

203

203

203

205

205

12

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3.13.5 VLANs

3.13.6 VXLANs

3.14 Host & DNS Configuration

3.14.1 Resolve DNS Names Now

3.14.2 Hosts for Local Resolution

3.15 Route Management

3.15.1 Default Gateway

3.15.2 Additional Routes

3.15.3 Packet Routing Filter

3.15.4 VPN Management

3.15.4.1 Create a New VPN Connection

3.15.4.2 Delete an Existing IPsec Connection

3.15.4.3 Set the VPN Addresses

3.15.4.4 Set the Perfect Forward Secrecy Option

3.15.4.5 Set the Connection Secret

3.15.4.6 Start the Connection

3.15.4.7 Stop the Connection

3.15.4.8 Get the Connection Status

3.15.4.9 List All Existing Connections

3.15.4.10 Stop the IKE Daemon

3.15.4.11 Start the IKE Daemon

3.15.4.12 Get the IKE Daemon Status

206

206

206

208

208

209

209

209

209

211

211

211

211

212

212

213

213

213

213

213

213

213

13

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3.16 Access Lists

3.17 Cluster Control

3.17.1 Clustering API Commands

3.17.1.1 Get the Status of the Cluster

3.17.1.2 Create a Cluster

3.17.1.3 Initiate a Node Joining a Cluster

3.17.1.4 Add a Node to the Cluster

3.17.1.5 Enable a Node

3.17.1.6 Disable a Node

3.17.1.7 Delete a Node

3.17.2 RESTful API Clustering Example

3.18 QoS/Limiting

3.18.1 Maximum Client Concurrent Connection Limit

3.18.2 Client CPS Limit

3.18.3 Legacy Client CPS Limit Commands

3.18.4 Client RPS Limit

3.18.5 Client Bandwidth Limit

3.18.6 Per-Virtual Service Limits

3.18.7 URL-Based Limiting Rules

3.19 System Administration

3.19.1 User Management

3.19.1.1 Change the System Password

214

215

216

216

217

217

217

218

218

218

218

219

220

221

221

222

222

222

223

224

224

224

14

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3.19.1.2 Set the Minimum Password Length

3.19.1.3 List All Local Users

3.19.1.4 Display Permissions for a Particular Local User

3.19.1.5 Add a New Local User

3.19.1.6 Delete a Local User

3.19.1.7 Change the Password of a Local User

3.19.1.8 Set Permissions for a Local User

3.19.1.9 Local Certificate Management

3.19.1.10 Remote User Group Management

3.19.1.11 Extended Permissions Management

3.19.2 Licensing

3.19.2.1 License

3.19.2.2 AlsiLicense

3.19.2.3 Accesskey

3.19.2.4 KillASLInstance

3.19.2.5 Deactivate a non-SPLA License

3.19.2.6 Disable/Enable the Activation Licensing Text for Kemp 360 Central

3.19.3 System Reboot

3.19.4 Update Software

3.19.4.1 Upgrade to a Newer Version of Software

3.19.4.2 Check the Previously Installed Firmware Version

3.19.4.3 Restore to a Previously Installed Version of Software

224

224

224

224

225

225

225

227

227

228

228

228

230

230

230

230

231

231

231

231

231

232

15

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3.19.4.4 List the Installed Add-On Packs

3.19.4.5 Upload or Update an Add-On Pack

3.19.4.6 Delete Add-On Pack

3.19.5 Backup/Restore

3.19.5.1 Automated Backups

3.19.6 Date/Time Settings

3.20 Logging Options

3.20.1 Manage System Logs

3.20.2 Ping Host

3.20.3 Run a Traceroute

3.20.4 Debug Options

3.20.4.1 Get/Set Debug Options

3.20.4.2 Retrieve RAID Information

3.20.4.3 Retrieve RAID Disk Information

3.20.4.4 Reset Statistics

3.20.4.5 Flush SSO Authentication Cache

3.20.5 Extended Log Files

3.20.5.1 List the Extended Log Files

3.20.5.2 Clear Extended Log Files

3.20.5.3 Save Extended Log Files

3.20.5.4 Enable/Disable Extended ESP Logging

3.20.6 Syslog Options

232

232

232

232

233

235

236

236

236

237

237

237

239

239

239

239

239

239

239

240

240

240

16

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3.20.7 SNMP Options

3.20.8 Email Options

3.20.9 SDN Log Files

3.20.9.1 Debug Options

3.21 Troubleshooting

3.21.1 Get/Set Debug Options

3.21.2 Run a Top

3.21.3 Run the Other Debug Options

3.21.4 Run a TCP Dump

3.22 Miscellaneous Options

3.22.1 WUI Settings

3.22.2 L7 Configuration

3.22.3 Network Options

3.22.4 HA Management

3.22.5 Cloud HA Parameters

3.22.5.1 Azure HA Parameters

3.22.5.2 AWS HA Parameters

3.22.6 SDN Configuration

3.22.6.1 Add an SDN Controller

3.22.6.2 Modify an SDN Controller

3.22.6.3 Delete an SDN Controller

3.22.6.4 Show the Existing SDN Controllers

242

244

245

245

245

245

246

247

247

248

248

249

253

256

260

261

261

262

262

263

266

266

17

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3.23 Network Telemetry

3.24 Setting Up HA using the RESTful API

3.24.1 Set up HA on a Regular LoadMaster using RESTful API

3.24.2 Set up HA on a LoadMaster for Azure using RESTful API

4 Scripting Examples with the LoadMaster RESTful API

5 List All API Commands and get/set Parameters

References

Last Updated Date

268

271

271

272

273

274

275

276

18

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

1 Introduction

1 Introduction

Kemp leads the industry in driving the price/performance value proposition for application delivery
and load balancing to levels that our customers can afford. Our products’ versatile and powerful
architecture provide the highest value, while enabling our customers to optimize their businesses
that rely on Internet-based infrastructure to conduct business with their customers, employees and
partners.

Kemp products optimize web and application infrastructure as defined by High Availability (HA),
high-performance, flexible scalability, security and ease of management. They maximize the total
cost-of-ownership for web infrastructure, while enabling flexible and comprehensive deployment
options.

1.1 Document Purpose

This document describes the RESTful API Interface to the Kemp LoadMaster. It describes in detail
how to configure the various features of the Kemp LoadMaster using the RESTful API.

This document does not explain each of the features or options in detail. For further information,
please refer to the relevant Feature Description document on
www.kemptechnologies.com/documentation.

1.2 Intended Audience

This document is intended to help anyone who wishes to configure the Kemp LoadMaster using the
RESTful API.

19

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

2 The RESTful API Interface

2 The RESTful API Interface

This document describes an interface designed to allow remote applications access to the
LoadMaster in a simple and consistent manner. The interface is a REST-like interface. REST
(Representational State Transfer) is a style of software architecture for distributed systems and is
one of the predominant web service design models.

2.1 How the LoadMaster RESTful API Works

The LoadMaster RESTful API works in a RESTful manner, by allowing a user or application to pass
HTTPS requests to the LoadMaster. The LoadMaster answers the request with an XML formatted
response. The HTTPS request is in the format:

https://<LoadMaster IP
Address>/access/<command>?<parameter1>=value&<parameter2>=value

The basic interface is a simple HTTPS GET operation where the command is specified by the URL. If
any parameters are required by the operation, they are passed as QUERY parameters.

When using the API there is a maximum URL length of 1K. If you
want to set a value which is longer than this, use a POST
operation instead.

The following points should be noted regarding the formatting of the HTTPS request:

l Only one command can be given at a time.

l The '?' character signifies the end of a command.

l The '&' character signifies the end of a parameter/value pair.

l If there are any unnecessary parameter/value pairs, they will be ignored.

l The order in which the parameter/value pairs appear does not matter.

l There cannot be any spaces within the query. Although some applications, like browsers,

would convert spaces to HTML code prior to sending the string to the LoadMaster.

l Multiple parameters can be modified within the same command.

For example, the following query will return the maximum cache size from a LoadMaster with the IP
address of 10.11.0.20.

https://10.11.0.20/access/get?param=cachesize

20

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

2 The RESTful API Interface

The response to the query, from the LoadMaster, is returned in an easily decoded XML format, for
example:

----------------------------------------------------------

<?xml version="1.0" encoding="ISO-8859-1"?>

<Response stat="200" code="ok">

<Success>

<Data>

<cachesize>

100

</cachesize>

</Data>

</Success>

</Response>

---------------------------------------------------------

Not all commands in this document are allowed on all
LoadMasters. Some functions are only available for certain
LoadMaster licenses.

The connection drops if more than 30 calls are performed in
less than 3 seconds over all API interfaces.

2.2 JSON-based Input and Output

In LoadMaster firmware version 7.2.50, beta functionality was added which allows you to specify API
requests as a POST of a JSON object and receive a JSON-based API payload response. As of firmware
version 7.2.52, this functionality is no longer in beta and is officially part of the LoadMaster product.

When using JSON-based input and output, the supported
authentication method is token-based, API keys. Certificate-
based authentication is not supported. For further details, refer
to the How to Use API Keys section of the RESTful API
Interface Description document.

To use JSON-based input and output, all requests must be a POST of a JSON object. For
authorization purposes, an API key (apikey) or a username/password pair (apiuser, apipass) can

21

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

2 The RESTful API Interface

also be given. Once the machine has been licensed, one or the other must be provided for access to
be allowed. If an apikey is provided, this has precedence over any username/passwords provided.

Each request is a JSON object. The only mandatory field is cmd which is the name of the command
to execute.

Some commands have sub-commands, for example logging, ssodomain, aclcontrol, geoacl, and
cluster. In the old format, most of these sub-commands are run like this:
<LoadMasterIPAddress>/access/logging/df. In the new format, here is an example of how a sub-
command is run: logging.df.

Here is an example of a simple request (-d tells cURL to send the following string as a POST request):

curl -k -d '{ "apikey" : "<APIKey>", "cmd" : "listapi" } '
https://<LoadMasterIPAddress>/accessv2

Here is another example that sets a parameter value:

curl -k -d '{ "apikey" : "<APIKey>", "cmd" : "set", "param" : "enableapi", "val" : true } '
https://<LoadMasterIPAddress>/accessv2

For reference, here is how these requests would look if you ran these API v1 commands using the old
format:

https://<LoadMasterIPAddress>/access/listapi

https://<LoadMasterIPAddress>/access/set?param=enable&value=1

Any parameters given to the accessv2 request are ignored. For example,
<LoadMasterIPAddress>/accessv2/example is the same as <LoadMasterIPAddress>/accessv2.

If a command requires binary data, for example a certificate, this data must be passed in the "data"
string and be base64-encoded.

If a command returns binary data, this is returned as a base64-encoded string. This field normally
has the name "data".

2.3 Security

An application can only access the LoadMaster using the standard WUI IP address. Security is
provided in exactly the same way as over the standard WUI, that is, valid credentials must be passed
on every access when using Basic Authentication.

22

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

2 The RESTful API Interface

The user bal naturally has access to all functionality; other users have access to the subsystems that
have been assigned to them using the LoadMaster permissions.

Currently there is no way to modify user permissions using this interface.

Depending on security settings and whether the browser has ever connected to the WUI before
adding login information may be required. In this case instead of a standard command format such
as:

https://<LoadMasterIPAddress>/access/<command>?params

the login information would need to be included, for example:

https://<UserName>:<UserPassword>@<LoadMasterIPaddress>/access/<command>?para
ms

You can also use certificate-based authentication or API keys.

For instructions on how to use certificate based authentication, refer to the Configure Certificate-
Based Authentication section.

For instructions on how to use API keys, refer to the How to Use API Keys section.

2.3.1 Configure Certificate-Based Authentication

Follow the steps in the sections below to configure certificate-based authentication.

Certificate-based authentication is not supported in version 2 of the API (which is currently in beta).

Certificate-based authentication will be deprecated for version 1 at some point in the future. Instead,
use API keys. For further details, refer to the How to Use API Keys section.

2.3.1.1 Enable Session Management

You must enable Session Management before you can enable client certificate authentication. To
enable Session Management, follow the steps below:

1. In the main menu of the LoadMaster WUI, navigate to Certificates & Security > Admin
WUI Access.

2. Select the Enable Session Management check box.

23

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

2 The RESTful API Interface

After this check box is selected, you must log in to continue
using the LoadMaster.

3. Configure any other settings as needed.

2.3.1.2 Create a User (If Needed)

It is not possible to use certificate-based authentication with the bal user. However, you can create a
non-bal user and grant it All Permissions, or whatever permissions you want. If you do not already
have another user created, you can add one by following these steps:

1. In the main menu of the LoadMaster WUI, expand System Configuration > System
Administration and click User Management.

2. At the bottom of the screen, enter a username in the User text box.

3. At this point, you can either set a Password for the new user, or select the No Local
Password check box.

For further information on the No Local Password option and
on certificate authentication in general, refer to the User
Management, Feature Description.

4. Click Add User.

2.3.1.3 Enable Client Certificate Authentication on the LoadMaster

A number of different login methods are available to enable. For steps on how to set the Admin
Login Method, along with a description of each of the available methods, refer to the steps below:

1. In the main menu of the LoadMaster WUI, expand Certificates & Security and click
Remote Access.

24

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

2 The RESTful API Interface

2. Select the relevant Admin Login Method.

The Pre-Auth Click Through Banner in the Admin WUI Access
screen must be set for all Admin Login Method options to be
made available.

Using local certificates only works with API authentication.
Because of this, it might be best to select the Password or
Client certificate option. This enables API access using the
client certificate and WUI access using the username/password.

The following login methods are available:

Password Only Access (default): This option provides access using the username and
password only – there is no access using client certificates.

Password or Client certificate: You can log in either using the username/password or using a
valid client certificate. If a valid client certificate is in place, the username and password is not
required.
The LoadMaster asks the client for a certificate. If a client certificate is available, the LoadMaster
checks for a match. The LoadMaster checks if the certificate matchesone of the local certificates,
or checks if the Subject Alternative Name (SAN) or Common Name (CN) of the certificate is a
match. The SAN is used in preference to the CN when performing a match. If there is a match,
you are granted access to the LoadMaster. This works both using the API and user interface.
An invalid certificate will not allow access.
If no client certificate is supplied, the LoadMaster expects that a username and password is
supplied (for the API) or will request a password using the standard WUI login page.

Client certificate required: Access is only allowed with the use of a client certificate. It is not
possible to log in using the username and password. SSH access is not affected by this (only the
bal user can log in using SSH).

25

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

2 The RESTful API Interface

Client certificate required (Verify via OCSP): This is the same as the Client certificate
required option, but the client certificate is verified using an OCSP service. You must configure
the OCSP Server Settings for this to work. For further information on the OCSP Server Settings,
refer to the SSL Accelerated Services, Feature Description.

Some points to note regarding the client certificate methods are below:

The bal user does not have a client certificate. Therefore, it is not possible to log into the
LoadMaster as bal using the Client certificate required methods. However, a non-bal user can
be created and granted All Permissions. This will allow the same functionality as the bal user.

There is no log out option for users that are logged in to the WUI using client certificates, as it is
not possible to log out (if the user did log out the next access would automatically log them
back in again). The session terminates when the page is closed, or when the browser is
restarted.

2.3.1.4 Generate and Download the Client Certificate

To generate a local certificate, follow the steps below:

Users with User Administration permissions are able to
manage local certificates for themselves and other users.

1. In the main menu of the LoadMaster WUI, navigate to System Configuration > System
Administration > User Management.

2. Click Modify on the relevant user.

3. Enter a Passphrase and click Generate.

26

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

2 The RESTful API Interface

Entering a passphrase is optional. If a passphrase is entered, it
is used to encrypt the private key.

4. Click OK to the pop-up message that appears.

5. Click Download.

You can also regenerate from this screen.

2.3.1.5 Specify the Certificate Details in the API

After configuring all of the options as outlined in the above sections, you must specify the details of
the certificate to run the API commands successfully. You must also run the command as a cURL
command, for example:

curl -k -E <PathToCertificateFile>/<CertificateFilename>.pem
https://172.21.59.100/access/get?param=version

2.3.1.6 Create a PFX File (If Running Commands using a Web Browser)

If you are running the RESTful APIs from the command line – you can use the PEM file, as indicated
in the Specify the Certificate Details in the API section. If you want to run RESTful API commands
using a web browser, you need to create a PFX file and import that into the browser.

You can convert the .pem file to .pfx any way you like. For the purposes of this document, we have
provided steps on how to do it using OpenSSL. If you are using Windows, you may need to install
OpenSSL to run these steps.

To create a .pfx file using, follow the steps below:

27

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

2 The RESTful API Interface

1. Open the .pem certificate.

2. Copy from the start of the -----BEGIN CERTIFICATE----- section to the end of the -----END
CERTIFICATE----- section.

3. Paste this text into a new file.

4. Save the file as <CerFileName>.cer.

5. Go to the .pem certificate file again.

6. Copy from the start of the -----BEGIN RSA PRIVATE KEY----- section to the end of the -----
END RSA PRIVATE KEY----- section.

7. Paste this text into a new file.

8. Save the file as <KeyFileName>.key.

9. Use the openssl command to create the .pfx file:

openssl pkcs12 -export -out <NewFileName>.pfx -inkey <KeyFilename>.key -in
<CerFileName>.cer

10. Import the certificate to the web browser.

2.3.2 How to Use API Keys

When running API commands, you can authenticate using an API key. An API key is a unique
identifier used to authenticate a user.

To generate an API key, run the following command:

https://<LoadMasterIPAddress>/access/addapikey

A list of API keys is returned. You can have up to 16 API keys per user - if you try to create more, the
oldest is deleted.

When you have an API key, you can perform any command as normal, but you no longer need the
username or password. For example:

https://<LoadMasterIPAddress>/access/listvs?&apikey=YOUR_API_KEY

You can list the API keys by running the following command:

https://<LoadMasterIPAddress>/access/listapikeys?&apikey=YOUR_API_KEY

2.3.2.1 Delete an API Key

You can delete an API key by running the following command:

28

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

2 The RESTful API Interface

https://<LoadMasterIPAddress>/access/delapikey?&key=Sv3twbV1LJQCH1K85q1gNGQm1
wqMYXrAsIlDMF5pr0kz

You must specify an API key or a username and password to validate the request. The various
options for running this command are detailed below.

curl -k
"https://<LoadMasterIPAddress>/access/delapikey?apikey=<ValidAPIKey>&key=<API
KeyToDelete>"

The above example assumes that the access apikey and the key to delete belong to the same user.

curl -k -u <Username>:<Password>
"https://<LoadMasterIPAddress>/access/delapikey?key=<APIKeyToDelete>"

The above example assumes the user whose username is specified owns the API key to delete.

curl -k -u <Username>:<Password>
"https://<LoadMasterIPAddress>/access/delapikey?key=<APIKeyToDelete>&user=<Ow
nerOfKey>"

The above example is usually performed by the bal user. For example:

curl -k -u bal:<Password>
"https://<LoadMasterIPAddress>/access/delapikey?key=<APIKeyToDelete>&user=<Ow
nerOfKey>"

The following example using an API key to authenticate is also valid:

curl -k
"https://<LoadMasterIPAddress>/access/delapikey?apikey=<ValidAPIKey>&key=<API
KeyToDelete>&user=<OwnerOfKey>"

The user performing the delete command must have the User
Administration permission.

2.4 Enabling the LoadMaster RESTful API Interface

The RESTful API interface is enabled or disabled using the LoadMaster WUI. By default the interface
is disabled.

To enable the RESTful API interface complete the following steps:

1. Select the Certificates & Security > Remote Access menu option.

2. Select the Enable API Interface checkbox.

2.5 Using get and set commands

A large number of LoadMaster parameters can be managed using the set and get commands. These
parameters are described throughout the document. A list of parameters is also provided in List All

29

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

2 The RESTful API Interface

API Commands and get/set Parameters.

Values of parameters can be obtained using the get command using the format

https://<LoadMasterIPAddress>/access/get?param=<ParameterName>

Values of parameters can be set using the set command using the format

https://<LoadMasterIPAddress>/access/set?param=<ParameterName>&value=<Paramet
erValue>

2.6 Error Reports

If an error occurs, for example where a request is missing the param value, an error report is
generated as follows:

----------------------------------------------------------

<?xml version="1.0" encoding="ISO-8859-1"?>

<Response stat="400" code="fail">

<Error>

param: String Value missing

</Error>

</Response>

-----------------------------------------------------------

The HTTP status of the request also reflects the response code.

2.7 Notation

Throughout the document the parameter types are defined as follows:

Type

Abbreviation

Typical Values

Boolean

Integer

String

Address

File

B

I

S

A

F

Y or N; y or n; 1 or 0;

<minint>-<maxint>

"value"

IP-address

Some type of file

30

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

3 RESTful API Commands

3.1 Command Syntax

A request is made up of two parts: the command and the parameters.

https://<LoadMaster IP address>/access/<command>?params

When there is more than one parameter in a request, individual parameters are separated using an
ampersand (&) symbol.

All commands are consistent. For example in all places where a Virtual Service is required, the IP
address of a Virtual Service is specified by using vs=<ipaddr>, for example, to show a Virtual Service,
the command could be:

https://<LoadMasterIPAddress>/access/showvs?vs=10.0.0.10&port=80&prot=tcp

To show a Real Server on a Virtual Service:

https://<LoadMasterIPAddress>/access/showrs?vs=10.0.0.10&port=80&prot=tcp&rs=
99.1.1.1&rsport=80

3.2 List All API Commands and get/set Parameters

To list all available API commands and the currently installed LoadMaster version, run the following
command:

https://<LoadMasterIPAddress>/access/listapi

A number of parameters can be retrieved and configured using the get and set commands.

The getall command returns a list of all parameters that are available (and that are not null):

https://<LoadMasterIPAddress>/access/getall

3.3 Home Screen Information

Some information which is available in the LoadMaster WUI is also available using the API. Refer to
the sub-sections below for further details.

3.3.1 Retrieve the LoadMaster Firmware Version

The LoadMaster firmware version can be obtained using the get command and the version
parameter:

https://<LoadMasterIPAddress>/access/get?param=version

31

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

3.3.2 Retrieve the Boot Time and Active Time

The boot time is the time at which the LoadMaster last booted. The boot time and active time are
the same when a LoadMaster is not running in HA mode. When in HA mode, the active time is the
time at which the LoadMaster last became the active unit. The active time will be zero if the
LoadMaster is in standby mode. To retrieve these values, run the following commands:

https://<LoadMasterIPAddress>/access/get?param=boottime
https://<LoadMasterIPAddress>/access/get?param=activetime

3.3.3 Retrieve the Serial Number

To retrieve the LoadMaster serial number, run the get command for the serialnumber parameter:

https://<LoadMasterIPAddress>/access/get?param=serialnumber

3.3.4 Retrieve the Virtual Service and Real Service Statuses

To retrieve the total numbers of Virtual Services, SubVSs and Real Servers that are up, down and
administratively disabled, run the vstotals command:

https://<LoadMasterIPAddress>/access/vstotals

3.3.5 Retrieve Licensing Information

To retrieve details about the LoadMaster license and subscription, run the licenseinfo command:

https://<LoadMasterIPAddress>/access/licenseinfo

3.4 Initial Configuration

The initial configuration API commands are not valid for pay-
per-use cloud LoadMasters. They are valid for Bring Your Own
License (BYOL) cloud LoadMasters.

A number of steps are involved in initially deploying a LoadMaster, such as accepting the End User
License Agreement (EULA) and licensing the unit. Before the LoadMaster can be fully deployed the
user must display and accept the EULA. These initial configuration steps can either be performed
using the WUI or the API. The API commands relating to initial configuration are listed in the sections
below.

These commands should be run in sequential order

3.4.1 Read the EULA

The ReadEula command displays the EULA and a magic cookie.

32

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

The magic cookie is used for security reasons - it limits the
possibility of remote attacks. If a command requires the magic
cookie (like some of the other ones in the sections below) and
does not get the correct magic cookie from the previous
command, the command will fail.

https://<LoadMasterIPAddress>/access/readeula

The magic string is an automatically generated random string,
for example c0a6fccc-1c53-4a26-8ed3-e0d0bb8e23f3. Please
copy this string because it will be needed in the next command
to set the license type.

3.4.2 Accept the EULA and Set the License Type

Currently there are three license types available from Kemp. These are:

Trial (Unrestricted)

Perpetual

Free (Restricted)

When running the AcceptEULA command, you enter the magic cookie key returned by the readEula
command. The AcceptEULA command accepts the EULA and sets the type of license used, for
example Trial, Perm or Free.

The type parameter must be set when running the accepteula
command. The type set depends on the type of LoadMaster you
are deploying.

https://<LoadMasterIPAddress>/access/accepteula?magic=<CorrectMagicString>&ty
pe=free

Value

Description

Trial

Temporary license for users evaluating the Kemp LoadMaster

Perm

Free

Purchased permanent LoadMaster

Free LoadMaster

33

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

If running this command on a Virtual LoadMaster (VLM) which
has been created in the Multi-Tenant LoadMaster product, the
license type set here is irrelevant because the license type will
be inherited from the Multi-Tenant LoadMaster. However, this
command still needs to be run to get another magic string
which is needed to run the next command (AcceptEula2).

3.4.3 Specify Whether or not to use the Kemp Analytics Feature

The AcceptEULA2 command is used to specify whether or not to enable the Kemp Analytics feature,
which enables statistical and usage data to be sent to Kemp for analysis. This data is strictly about
product usage, enabled capabilities, and statistics. No sensitive user data, or traffic of any kind is
either collected or communicated. For more information, visit https://kemp.ax/KempAnalytics.

https://<LoadMasterIPAddress>/access/accepteula2?magic=<CorrectMagicString>&a
ccept=<yes/no>

3.4.4 Retrieve the Available License Types

To retrieve a list of available license types for a particular Kemp ID, run the alsilicensetypes
command:

https://<LoadMasterIPAddress>/access/alsilicensetypes?kempid=<KempID>&passwor
d=<PasswordForKempID>&orderid=<OrderID>

The orderid parameter is only needed for Virtual LoadMasters.

If successful, the output provides a list of license types and associated IDs. The ID number is used
when licensing using the alsilicense command.

3.4.5 License the LoadMaster

The LoadMaster can be licensed using the license or alsilicense commands. For further information,
please refer to the Licensing section.

3.4.6 Set the Initial Password

The Set_Initial_Passwd command is used to set the password of the default LoadMaster user (bal).

https://<LoadMasterIPAddress>/access/set_initial_passwd?passwd=<password1>

Parameter

Parameter
Type

Description

Mandatory

Passwd

String

This is the password for the default administrator user
(bal). The password should contain at least 8

Yes

34

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

alphanumeric characters.

If you are licensing using Kemp 360 Central, you may need to use the usersetsyspassword
command instead:

https://<LoadMasterIPAddress>/access/usersetsyspassword?currpassword=YOUR_CURRENT_PASSWORD&password=YOUR_NEW_PASSWORD

Refer to the following table to determine what command you should use:

LoadMaster Version

Kemp 360 Central version >= V2.3

Kemp 360 Central version < V2.3

LoadMaster >= V7.2.47

Use usersetsyspassword

Use set_initial_password

LoadMaster < V7.2.47

Use set_initial_password

Use set_initial_password

To future-proof any existing LoadMaster deployment scripts you may have, modify the scripts to first
use set_initial_password to attempt setting the bal password. If that fails, use
usersetsyspassword.

If you are trying to license LoadMaster version 7.2.46 against a version of Kemp 360 Central that is
above V2.3, you will not be able to log into the WUI after setting the password using the API. To work
around this, you must run the following command after running the set_initial_password
command:

https://<LoadMasterIPAddress>/access/set?param=motd&value=

3.5 Licensing using the Activation Server Functionality

You can license locally if using Kemp 360 Central with Activation Server functionality.

To retrieve a list of available license types, use the aslgetlicensetypes command:

https://<LoadMasterIPAddress>/access/aslgetlicensetypes?aslhost=<Kemp360Centr
alHostOrIPAddress>&aslport=<Kemp360CentralPort>

The aslhost parameter was introduced in LoadMaster firmware
version 7.2.43. The parameters previously used were called
aslipaddr and aslname. If you have scripts using these old
parameters, you will need to update them to use the new
aslhost parameter if upgrading.

For example:

https://10.35.47.20/access/aslgetlicensetypes?aslhost=10.35.44.19&aslport=443

35

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

After running the aslgetlicensetypes command, a list of available license types with license IDs is
displayed:

<Response stat="200" code="ok">

<Success>{"categories": [{"description": "Licenses from Kemp 360 ASL Server",
"licenseTypes": [

{"id": "2", "name": "VLM-MAX", "description": "VLM-MAX", "available": 1}

]}]}</Success>

</Response>

To activate the license, use the aslactivate command and specify the license type ID:

https://<LoadMasterIPAddress>/access/aslactivate?lic_type_id=<LicenseTypeID>

For example:

https://10.35.47.20/access/aslactivate?lic_type_id=2

For compatibility across releases, the lic_id_type and the licensetypeid can be used
interchangeably in any command where a license type ID is required. Therefore, the above
command synopsis could also be shown as:

https://<LoadMasterIPAddress>/access/aslactivate?licensetypeid=<LicenseTypeI
D>

For example:

https://10.35.47.20/access/aslactivate?licensetypeid=2

3.6 Virtual Services

3.6.1 Virtual Service Control

The basic forms of the Virtual Services commands are below. Virtual Services can be addressed
either by using the IP address or the index (ID). The index is a numerical value that tracks the Virtual
Service internally.

The index can be displayed by using the showvs or listvs command or, alternatively by checking the
Virtual Service properties screen in the WUI, which displays the Virtual Service ID.

https://<LoadMasterIPAddress>/access/listvs
https://<LoadMasterIPAddress>/access/showvs?vs=<IPaddr>&port=<Port>&prot=<tcp
/udp>
https://<LoadMasterIPAddress>/access/showvs?vs=<index>
https://<LoadMasterIPAddress>/access/addvs?vs=<IPaddr>&port=<Port>&prot=<tcp/
udp>[&...]

36

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

https://<LoadMasterIPAddress>/access/delvs?vs=<IPaddr>&port=<Port>&prot=<tcp/
udp>
https://<LoadMasterIPAddress>/access/delvs?vs=<index>
https://<LoadMasterIPAddress>/access/modvs?vs=<IPaddr>&port=<Port>&prot=<tcp/
udp>[&...]
https://<LoadMasterIPAddress>/access/modvs?vs=<index>[&...]

The delvs command returns an OK status on success; otherwise the commands return the current
settings of the Virtual Service.

The addvs and modvs command both allow the user to modify all the settings of a Virtual Service.
The addvs command will first create the Virtual Service - while modvs will modify an existing Virtual
Service.

Frequently adding or deleting Virtual Services at a high velocity
is not the recommended best practice. If you need to modify
parameters, use the modvs command. If you need to
constantly modify Virtual Service IP addresses, moving to
FQDNs (rather than IP addresses) is the recommended best
practice.

The listvs command lists all Virtual Services on the LoadMaster.

(When creating a new Virtual Service, the default values set are non-transparent and subnet
originating - except for UDP services, which are transparent (force L4).)

When the status of the Virtual Service is returned, the Real Servers associated with the Virtual
Service are also returned.

Some commands depend on other commands as a prerequisite.
If the prerequisites are not met, the command will do nothing.

Not all parameters are applicable on all setups. The parameters
available for use depends on the configured environment

Sub-Virtual Services (SubVSs)

The Virtual Service commands can be used on SubVSs also. However, as SubVSs do not have IP
addresses, the SubVS index must be used. The SubVS index can be found using the listvs command.

37

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

Alternatively, check the ID SubVS properties screen in the WUI by clicking modify on a SubVS. In the
example above, the SubVS ID is 2.

To display details about a particular SubVS, run the following command:

https://<LoadMasterIPAddress>/access/showvs?vs=<SubVSindex>

A new SubVS can be added by running one of the following commands:

https://<LoadMasterIPAddress>/access/modvs?vs=<VSIP>&port=<Port>&prot=<tcp/ud
p>&createsubvs=
https://<LoadMasterIPAddress>/access/modvs?vs=<index>&createsubvs=

A SubVS can be deleted from a Virtual Service by running the following command:

https://<LoadMasterIPAddress>/access/delvs?vs=<VSindex>

A Real Server can be deleted from a SubVS by running the following command:

https://<LoadMasterIPAddress>/access/delrs?vs=<SubVSindex>&rs=%21<RSindex>

To modify SubVS settings, run the following command:

https://<LoadMasterIPAddress>/access/modvs?vs=<SubVSindex> [&...]

SubVS index is an integer value.

Frequently adding or deleting Real Servers or SubVSs at a high
velocity is not the recommended best practice. If you need to
modify parameters, use the modrs command. If you need to
constantly modify Real Server IP addresses, moving to FQDNs
(rather than IP addresses) is the recommended best practice.

The parameters that can be set in the addvs and modvs commands are described in the sections
below. For ease of use, the parameters have been broken into sections based on where the
corresponding field appears in the WUI.

3.6.1.1 Properties

Name

Type

Default

Range

Description

Port

I

<unset>

3-65530,
*

The port for the Virtual Service. A wildcard port can
also be specified by using an asterisk (*).

The port parameter is used to assign a port when
initially creating a Virtual Service. If modifying the port
of an existing Virtual Service, specify the existing port

38

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

as the port parameter and use the vsport parameter
to assign the new port.

The reason why these must be separate parameters is
because you need to specify what the port of the
existing Virtual Service is (because there may be
another Virtual Service with the same IP address but a
different port) and if you want to change the port, a
second port parameter (VSPort) is needed to specify
the new port value.

The port for the Virtual Service.

The port parameter is used to assign a port when
initially creating a Virtual Service. If modifying the port
of an existing Virtual Service, specify the existing port
as the port parameter and use the vsport parameter
to assign the new port.

The reason why these must be separate parameters is
because you need to specify what the port of the
existing Virtual Service is (because there may be
another Virtual Service with the same IP address but a
different port) and if you want to change the port, a
second port parameter (VSPort) is needed to specify
the new port value.

VSPort

I

<unset>

3-65530,
*

Protocol

VSAddress

S

A

<unset>

udp, tcp

The protocol to be used for the Virtual Service.

Address

The IP address of the Virtual Service.

MasterVS

I (Read
Only)

<unset>

0 – Not a
parent
Virtual
Service

1 – Is a
parent
Virtual
Service

Signifies whether or not the Virtual Service is a parent
Virtual Service (that is, if it has one or more SubVSs).

39

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

3.6.1.2 Basic Properties

Name

Type

Default

Range

Description

Enable

B

Y

Activate or deactivate the Virtual Service

gen - Generic

http -
HTTP/HTTPS

http2 -
HTTP/2

VStype

S

<port
dependent>

ts - Remote
Terminal

Specifies the type of service being load
balanced.

tls –
STARTTLS
protocols

log – Log
Insight

Specifies the "friendly" name of the service.

In addition to the usual alphanumeric
characters, the following ‘special’ characters
can be used as part of the Service Name:
. @ - _

You cannot use a special character as the first
character of the Service Name.

NickName

S

<unset>

3.6.1.3 Standard Options

Name

Type

Default

Range

Description

Cookie

S

<unset>

This parameter is only relevant when the
persistence mode is set to cookie, active-
cookie, cookie-src or active-cook-src.
Enter the name of the cookie to be
checked.

40

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

ForceL7

B

Y (if not
UDP)

0 - Disabled

1 - Enabled

Idletime

I

660

0-86400

Enabling ForceL7 means the Virtual
Service runs at Layer 7 and not Layer 4.
This may be needed for various reasons,
including that only Layer 7 services can be
non-transparent.

Specifies the length of time (in seconds)
that a connection may remain idle before
it is closed. The range for this parameter is
0 to 86400.

Setting the Idletime to 0 ensures the
default L7 connection timeout is used. You
can modify the default timeout value by
setting the ConnTimeout parameter.

Persist

S

none

The list of
relevant
persist
values are:

ssl

cookie

active-
cookie

cookie-
src

active-
cook-src

cookie-
hash

cookie-
hash-src

url

query-
hash

Specify the type of persistence (stickiness)
to be used for this Virtual Service.

Note: If setting the persistence mode to an
option that requires a cookie (or query-
hash), the cookie parameter must also be
set.

41

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

host

header

super

super-src

src

rdp

rdp-src

rdp-sb

rdp-sb-src

none

udpsip

SubnetOriginating

B

0

0 – Disabled

1 – Enabled

PersistTimeout

I

0

0-2419200

When transparency is not enabled, the
source IP address of connections to the
Real Servers is that of the Virtual Service.
When transparency is enabled, the source
IP address will be the IP address that is
initiating connection to the Virtual Service.
If the Real Server is on a subnet, and the
Subnet Originating Requests option is
enabled, then the subnet address of the
LoadMaster will be used as the source IP
address.

The length of time (in seconds) after the
last connection that the LoadMaster will
remember the persistence information.

Timeout values are rounded down to an
even number of minutes. Setting a value
that is not a number of whole minutes
results in the excess being ignored. Setting
a value to less than 60 seconds results in a
value of 0 being set, which disables
persistency.

42

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

Refreshpersist

QueryTag

B

S

<unset>

0 – Disabled

1 – Enabled

When this parameter is enabled, it keeps
auto-refereshing persist entries for long
lived connections.

Schedule

S

rr

rr

wrr

lc

wlc

fixed

adaptive

sh

dl

sdn-adaptive

uhash

ServerInit

I

0

0-6

This is the query tag to be matched if the
Persist type is set to query-hash.

Specify the type of scheduling of new
connections to Real Servers that is to be
performed. The value values are spelled
out below:

rr = round robin

wrr = weighted round robin

lc = least connection

wlc = weighted least connection

fixed = fixed weighting

adaptive = resource based (adaptive)

sh = source IP hash

dl = weighted response time

sdn-adaptive = resource based (SDN
adaptive)

uhash = URL hash

By default, the LoadMaster will not initiate
a connection with a Real Server until it has
received some data from a client. This
prohibits certain protocols from working
as they need to communicate with the
Real Server before transmitting data.

If the Virtual Service uses one of these
protocols, specify the protocol using the
ServerInit parameter to enable it to work
correctly.

0 = Normal Protocols

43

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

Transparent

B

Y

0 - Disabled

1 - Enabled

1 = SMTP

2 = SSH

3 = Other Server Initiating

4 = IMAP4

5 = MySQL

6 = POP3

When using Layer 7, when this is enabled -
the connection arriving at the Real Server
appears to come directly from the client.
Alternatively, the connection can be non-
transparent which means that the
connections at the Real Server appear to
come from the LoadMaster.

If a Virtual Service (with or without a
SubVS) has SSL re-encrypt enabled, the
transparency flag of the Virtual Service has
no meaning (re-encryption forces
transparency to be off). The transparency
setting can still be modified by the API,
and is honored when re-encrypt is
disabled on the Virtual Service.

By default, when the LoadMaster is being
used to NAT Real Servers, the source IP
address used on the Internet is that of the
LoadMaster.

UseforSnat

B

N

0 – Disabled

1 – Enabled

Enabling this option allows the Real
Servers configured to use the Virtual
Service as the source IP address instead.

If the Real Servers are configured on more
than one Virtual Service which has this
option set, only connections to destination
port 80 will use this Virtual Service as the
source IP address.

44

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

QoS

S

0 –
Normal
Service

0 - Normal-
Service

1 - Minimize-
Cost

2 - Maximize-
Reliability

4 - Maximize-
Throughput

8 - Minimize-
Delay

16 - Pass
Through

StartTLSMode

I

0-6

The Quality of Service (QoS) parameter
sets a Type of Service (ToS) in the IP
header of packets that leave the Virtual
Service. This means that the next device or
service that deals with the packets will
know how to treat and prioritise this
traffic. Higher priority packets are sent
from the LoadMaster before lower priority
packets.

0 = HTTP/HTTPS (the Service Type needs
to be set to HTTP/HTTPS for this to work)

The Virtual Service Type must be set to
STARTTLS for the remaining values to be
set:

1 = SMTP (STARTTLS if requested)

2 = SMTP (STARTTLS always)

3 = FTP

4 = IMAP

6 = POP3

ExtraPorts

S

<unset>

3-65530

Specify extra ports that the Virtual Service
will listen to. To remove any existing extra
ports, set the ExtraPorts parameter to an
empty string.

When setting the persistence method to cookie, active-cookie,
cookie-src or active-cook-src, the cookie name must also be
set within the command.
For example:

45

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

https://<LoadMasterIPAddress>/access/modvs?vs=10.0.2.19
4&port=80&prot=tcp&persist=cookie&cookie=<cookie
name>&

3.6.1.4 SSL Properties

Name

Typ
e

Default

Range

Description

CertFile

S

<unset>

Ciphers

S

Default
assignme
nt

All
supporte
d ciphers

A list of certificate identifiers, separated by
spaces. When used with the addvs command, all
certificates required for the VS must be specified
in a single space-separated list. Similarly, when
using the modvs command, the entire list of
certificates required for the VS must be
specified.

There is a limit of 8099 characters when
assigning certificates to a Virtual Service using
the API.

Multiple ciphers can be assigned by inserting a
colon between each cipher. When ciphers are
assigned in this way, a Cipher Set called
Custom_<VirtualServiceID> will be
created/updated.

Note: The assigned ciphers list will be
overwritten when ciphers are added in this way.
Ensure to include all ciphers to be assigned.

For the list of ciphers which are assigned by
default, and for a list of supported ciphers, refer
to the SSL Accelerated Services, Feature
Description.

Note: Do not try to set the CipherSet parameter
and the Ciphers parameter at the same time -
use one or the other. Custom cipher sets can be
created using a different command. For more
information, refer to the Modify a Custom
Cipher Set/Create a New Custom Cipher Set

46

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

CipherSet

S

Default

All
available
cipher
sets

section

This parameter can be used to assign a cipher
set to a Virtual Service. System-defined cipher
sets and custom cipher sets can be assigned
using this parameter. The valid values are below:

nDefault

nDefault_NoRc4

nBestPractices

nIntermediate_compatibility

nBackward_compatibility

nWUI

nFIPS

nLegacy

nNull_Ciphers

nECDSA_Default

nECDSA_BestPractices

n<NameOfCustomCipherSet>

Do not try to set the
CipherSet parameter and the
Ciphers parameter at the
same time - use one or the
other. Custom cipher sets can
be created using a different
command. For more
information, refer to the
Modify a Custom Cipher
Set/Create a New Custom
Cipher Set section.

Tls13CipherSet

S

All TLS1.3

This parameter can be used to assign TLS1.3

47

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

available
cipher
sets

ClientCert

I

0

0-6

PassCipher

B

0 -
Disabled

1 -
Enabled

cipher sets to a Virtual Service. Multiple ciphers
can be specified using a space and colon
separated list. You cannot unset this parameter -
at least one cipher set must be specified.

The list of supported TLS1.3 Ciphers (and valid
values) is as follows:

- TLS_AES_256_GCM_SHA384

- TLS_CHACHA20_POLY1305_SHA256

- TLS_AES_128_GCM_SHA256

- TLS_AES_128_CCM_8_SHA256

- TLS_AES_128_CCM_SHA256

0 = No client certificates required

1 = Client certificates required

2 = Client certificates and add headers

3 = Client Certificates and pass DER through as
SSL-CLIENT-CERT

4 = Client Certificates and pass DER through as
X-CLIENT-CERT

5 = Client Certificates and pass DER through as
SSL-CLIENT-CERT

6 = Client Certificates and pass PEM through as
X-CLIENT-CERT

When this parameter is enabled, the LoadMaster
adds X-SSL headers containing client
SSLinformation such as TLS version, TLS cipher,
client certificate serial number, and SNI host.

Note: SSLAcceleration must be enabled to
enable the PassCipher parameter.

SSLReencrypt

B

N

0 -
Disabled

This parameter is only relevant if SSL
Acceleration is enabled.

48

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

PassSNI

B

SSLReverse

B

N

SSLRewrite

S

<unset>

ReverseSNIHostn
ame

S

<unset>

SecurityHeaderOp
tions

I

0 - Don't
add the
Strict
Transport
Security
Header

1 -
Enabled

0 -
Disabled

1 -
Enabled

0 -
Disabled

1 -
Enabled

<unset>,
http,
https

0 - Don't
add the
Strict
Transport
Security
Header

1 - Add
the Strict
Transport
Security
Header -
no
subdomai
ns

When this option is enabled, the SSL data
stream is re-encrypted before sending to the
Real Server.

To enable or disable the PassSNI parameter.

Enabling this parameter means that the data
from the LoadMaster to the Real Server is re-
encrypted.

When the Real Server rejects a request with a
HTTP redirect, the requesting Location URL may
need to be converted to specify HTTPS instead
of HTTP (and vice versa).

Specify the SNI Hostname that should be used
when connecting to the Real Servers. This
parameter relates to the Reencryption SNI
Hostname field in the WUI.

Enable this option to add the Strict-Transport-
Security header to all LoadMaster-generated
messages (ESP and error messages).

Note: You can configure the maximum age for
the message by setting the SecurityHeaderAge
parameter.

To retrieve the current value of the
SecurityHeaderAge parameter, run the following
command:

/access/get?param=securityheaderage

To set the parameter, run the following
command:

2 - Add

/access/set?param=securityheaderage&v
alue=<value>

49

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

SSLAcceleration

B

N

the Strict
Transport
Security
Header -
include
subdomai
ns

4 - Add
the Strict
Transport
Security
Header -
no
subdomai
ns +
preload

6 - Add
the Strict
Transport
Security
Header -
include
subdomai
ns +
preload

0 -
Disabled

1 -
Enabled

0 –
Disabled

1 –
Enabled

Valid values for this parameter range from 86400
(1 day) to 94608000 (2 year).

Enable SSL handling on this Virtual Service.

Verify (using Online Certificate Status Protocol
(OCSP)) that the client certificate is valid.

0 –
Disabled

OCSPVerify

TLSType

B

B

Disabled if
SSL

0 – 30
bitmask

Specify which of the following protocols to
support; SSLv3, TLS1.0, TLS1.1, TLS1.2, or

50

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

Accelerati
on is not
enabled.

TLS1.1,
TLS1.2,
and
TLS1.3 are
enabled
when SSL
Accelerati
on is
enabled.

0 –
Disabled

By default
all
intermedi
ate
certificate
s are
assigned

TLS1.3. The protocols can be enabled and
disabled using a bitmask value. Refer to the
table below to find out what number
corresponds to which settings.

0 -
Disabled

1 -
Enabled

When this parameter is enabled, the hostname is
always required to be sent in the TLS client hello
message. If it is not sent, the connection will be
dropped.

Valid cert
names

Assign intermediate and root certificates to the
specified Virtual Service. This provides the ability
to restrict access. You cannot add a certificate to
an already assigned list of certificates - all
certificates that should be assigned to the Virtual
Service must be specified in the one modvs
command. If you enter more than one certificate
name, separate them using a plus symbol (+).

NeedHostName

B

IntermediateCerts

S

3.6.1.4.1 TLSType Parameter

For the TLSType parameter, the protocols can be enabled and disabled using a bitmask value.

The valid bitmask values vary depending on whether the SSLOldLibraryVersion parameter is
enabled or disabled. Refer to the relevant section below to find out what number corresponds to
which settings.

SSLOldLibraryVersion Disabled

If the SSLOldLibraryVersion parameter is disabled, the bitmask values and settings are as outlined
in the table below:

51

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

Number

SSLv3

TLS1.0

TLS1.1

TLS1.2

TLS1.3

0

1

2

3

4

5

6

7

8

9

10

11

12

13

14

15

16

17

18

19

20

21

22

23

Enabled

Enabled

Enabled

Enabled

Enabled

Disabled

Enabled

Enabled

Enabled

Enabled

Enabled

Disabled

Enabled

Enabled

Enabled

Disabled

Disabled

Enabled

Enabled

Enabled

Enabled

Enabled

Disabled

Enabled

Enabled

Disabled

Enabled

Disabled

Enabled

Enabled

Enabled

Disabled

Disabled

Enabled

Enabled

Disabled

Disabled

Disabled

Enabled

Enabled

Enabled

Enabled

Enabled

Disabled

Enabled

Disabled

Enabled

Enabled

Disabled

Enabled

Enabled

Disabled

Enabled

Disabled

Enabled

Disabled

Disabled

Enabled

Disabled

Enabled

Enabled

Enabled

Disabled

Disabled

Enabled

Disabled

Enabled

Disabled

Disabled

Enabled

Enabled

Disabled

Disabled

Disabled

Enabled

Disabled

Disabled

Disabled

Disabled

Enabled

Enabled

Enabled

Enabled

Enabled

Disabled

Disabled

Enabled

Enabled

Enabled

Disabled

Enabled

Disabled

Enabled

Enabled

Disabled

Disabled

Disabled

Enabled

Enabled

Disabled

Enabled

Enabled

Disabled

Enabled

Disabled

Disabled

Enabled

Disabled

Enabled

Disabled

Enabled

Disabled

Disabled

Enabled

Disabled

Disabled

Disabled

Disabled

Enabled

Disabled

52

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

24

25

26

27

28

29

30

Enabled

Enabled

Enabled

Disabled

Disabled

Disabled

Enabled

Enabled

Disabled

Disabled

Enabled

Disabled

Enabled

Disabled

Disabled

Disabled

Disabled

Enabled

Disabled

Disabled

Enabled

Enabled

Disabled

Disabled

Disabled

Disabled

Enabled

Disabled

Disabled

Disabled

Enabled

Disabled

Disabled

Disabled

Disabled

SSLOldLibraryVersion Enabled

If the SSLOldLibraryVersion parameter is enabled, TLS1.3 is not available and the range of the
bitmask value is 0-14, as outlined in the table below.

Number

SSLv3

TLS1.0

TLS1.1

TLS1.2

0

1

2

3

4

5

6

7

8

9

10

11

12

13

14

Enabled

Enabled

Enabled

Enabled

Disabled

Enabled

Enabled

Enabled

Enabled

Disabled

Enabled

Enabled

Disabled

Disabled

Enabled

Enabled

Enabled

Enabled

Disabled

Enabled

Disabled

Enabled

Disabled

Enabled

Enabled

Disabled

Disabled

Enabled

Disabled

Disabled

Disabled

Enabled

Enabled

Enabled

Enabled

Disabled

Disabled

Enabled

Enabled

Disabled

Enabled

Disabled

Enabled

Disabled

Disabled

Disabled

Enabled

Disabled

Enabled

Enabled

Disabled

Disabled

Disabled

Enabled

Disabled

Disabled

Enabled

Disabled

Disabled

Disabled

53

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

Another way of determining the correct bitmask value to set for the TLSType parameter is outlined
in the partial table and explanation below.

Dec Bit
Values

16

8

4

2

1

Values Set

TLS1.3

TLS1.2

TLS1.1

TLS1.0

SSLv3

0

3

23

15

off

off

on

off

off

off

off

off

off

off

on

on

on

on

on

off

on

on

on

on

All TLS
types
enabled

1.1,1.2,1.3
enabled

Only
TLS1.2
enabled

Only
TLS1.3
enabled

Here are some notes about the above table:

l For all TLS types that you want to enable, you leave the bit off and turn on the rest

l A value of 31 is not possible (all bits on) because you would be disabling all TLS types so valid

values are 0 - 30

l When TLS1.3 is not available (if the SSLOldLibraryVersion is enabled) then the range

becomes 0 - 15. However, 15 is not a valid value so the valid range is 0 - 14

Another way of thinking about this is by adding 16+8+4+2+1=31 and then whatever TLS type you
want on, you subtract from 31.

If TLS 1.3 is not available, then you leave out the TLS 1.3 column above and add 8+4+2+1.

3.6.1.5 Advanced Properties

Name

Type Default

Range

Description

CopyHdrFrom

S

<unset>

This is the name of the
source header field to
copy into the new header

54

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

CopyHdrTo

S

<unset>

AddVia

I

AllowHTTP2

B

0 –
Disabled

field before the request is
sent to the Real Servers.

Used in conjunction with
the CopyHdrFrom
parameter.

The name of the header
field into which the
source header is to be
copied.

This corresponds to the
Add HTTP Headers field
in the WUI. Select which
headers are to be added
to HTTP requests. X-
ClientSide and X-
Forwarded-For are only
added to non-transparent
connections.

Enable HTTP2 for this
Virtual Service. SSL
Acceleration must be
enabled before HTTP2

0 = Legacy
Operation
(X-
Forwarded-
For)

1 = X-
Forwarded-
For (+ Via)

2 = None

3 = X-
ClientSide
(+ Via)

4 = X-
ClientSide
(No Via)

5 = X-
Forwarded-
For (No
Via)

6 = Via Only

0 –
Disabled

1 – Enabled

55

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

Cache

Compress

B

B

N

N

0 - Caching
Disabled

1 – Caching
Enabled

0 –
Disabled

1 - Enabled

CachePercent

I

0

0-100

DefaultGW

A

<unset>

ErrorCode

I

0

200-505

can be enabled. The Best
Practices cipher set
should be used when
HTTP2 is enabled.

Enable or disable the
caching of URLs.

When enabled, files sent
from the LoadMaster are
compressed with Gzip.

This parameter is only
relevant if caching is
enabled. Specify the
maximum percentage of
cache space permitted for
this Virtual Service.

Specify the Virtual
Service-specific default
gateway to be used and
to send responses back to
clients. If not set, the
global default gateway
will be used.

If no Real Servers are
available, the LoadMaster
can terminate the
connection with a HTTP
error code. Specify the
error code number in this
parameter. To unset the
error code, set the
parameter to an empty
string.

56

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

In LoadMaster firmware
version 7.2.52 it is
possible to upload an
error file using the API to
add to the error response.
To retrieve the Virtual
Service ID, run the listvs
command. For further
details refer to the
heading Upload Error File.

When no Real Servers are
available and an error
response is sent back to
the client, a redirect URL
can also be specified.

This parameter was
depreciated as of 7.1-24.
For LoadMasters with
version 7.1-24 or higher,
use the FollowVSID
parameter to set port
following.

Specify the ID of the
Virtual Service to follow.
Setting this value to 0
disables port following. 1
and 2 are not valid values
so ensure that the Virtual
Service that you want to
follow has a value
between 3 and 65530.

Specify the ID of the
Virtual Service to follow.

ErrorUrl

S

<unset>

PortFollow

I

<unset>

0 and 3-
65530

FollowVSID

I

<unset>

LocalBindAddrs

A

<unset>

A space
separated
list of IP

This corresponds to the
Alternate Source
Address in the Advanced

57

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

addresses

Properties section of the
WUI. Allow connections
scaling over 64K
Connections needs to be
enabled in L7
Configuration for this
feature to work.

This displays the number
of HTTP Header
Modification request
rules.

This displays the number
of HTTP Header
Modification response
rules.

The list of request rules
that are assigned to the
Virtual Service.

The list of response rules
that are assigned to the
Virtual Service.

Specify the IP address of
the “Sorry” server that is
to be used when no other
Real Servers are available.
This server will not be
health checked and is
assumed to be always
available.

Specify the port of the
“Sorry” server.

0 -
Disabled

1 - Enabled

Set this parameter to 1
(enabled) if you are
adding a non-local sorry
server using the

NRequestRules

NResponseRules

RequestRules

ResponseRules

<unset>

<unset>

I
(Read
only)

I
(Read
only)

List
(Read
only)

List
(Read
only)

StandbyAddr

A

<unset>

StandbyPort

I

<unset>

NonLocalSorryServer

B

<unset>

58

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

Verify

0

I

0-7
(bitmask)

AltAddress

A

<unset>

IP address

AddVia

I

0-6

PreProcPrecedence

S

<unset>

StandByAddr and
StandByPort parameters.

Refer to the Verify
Parameter section for
further information on
the Verify parameter.

Specify the alternate
address for this Virtual
Service.

Specify which headers to
be added to HTTP
requests. X-ClientSide
and X-Forwarded-For are
only added to non-
transparent connections.

0 = Legacy Operation(X-
Forwarded-For)

1 = X-Forwarded-For (+
Via)

2 = None

3 = X-ClientSide (+ Via)

4 = X-ClientSide (No Via)

5 = X-Forwarded-For (No
Via)

6 = Via Only

This parameter should be
used in conjunction with
PreProcPrecedencePos.
This parameter is used to
specify the name of the
existing rule whose
position you wish to
change.

59

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

PreProcPrecedencePos

Int16

<unset>

RequestPrecedence

String

<unset>

RequestPrecedencePos

Int16

<unset>

This parameter relates to
Content Matching Rules
only.

This parameter, in
conjunction with the
PreProcPrecedence
parameter, is used to
change the position of
the rule in a sequence of
rules. For example a
position of 2 means the
rule will be checked
second.

This parameter relates to
the Content Matching
Rules only.

This parameter should be
used in conjunction with
RequestPrecedencePos.
This parameter is used to
specify the name of the
existing request rule
whose position you wish
to change.

This parameter relates to
the following rule types:
Content MatchingAdd
HeaderDelete
HeaderReplace
HeaderModify URL

This parameter, in
conjunction with the
RequestPrecedence
parameter, is used to
change the position of
the rule in a sequence of

60

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

ResponsePrecedence

String

<unset>

ResponsePrecedencePos

Int16

<unset>

MatchBodyPrecedence

String

<unset>

rules. For example a
position of 2 means the
rule will be checked
second.

This parameter should be
used in conjunction with
ResponsePrecedencePos
. This parameter is used
to specify the name of the
existing response rule
whose position you wish
to change.

This parameter relates to
the following rule types:
Content MatchingAdd
HeaderDelete
HeaderReplace Header

This parameter, in
conjunction with the
ResponsePrecedence
parameter, is used to
change the position of
the rule in a sequence of
rules. For example, a
position of 2 means the
rule will be checked
second.

This parameter should be
used in conjunction with
MatchBodyPrecedenceP
os. Use this parameter to
specify the name of the
existing body
modification rule that you
want to change the
position of.

61

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

MatchBodyPrecedenceP
os

Int16

<unset>

This parameter relates to
Body Modification rules
only.

Use this parameter, in
conjunction with the
MatchBodyPrecedence
parameter, to change the
position of the rule in a
sequence of rules. For
example, a position of 2
means the rule is checked
second.

3.6.1.5.1 Upload Error File

As of LoadMaster firmware version 7.2.52, it is also possible to upload the error file. To upload an
error file using the RESTful API, run the following command:

curl -u "<Username>:<Password>" -k -X POST --data-binary "@<PathToFile>"
"https://<LoadMasterIPAddress>/access/uploadvserrfile?vs=<VirtualServiceID>"

3.6.1.5.2 Verify Parameter

Verify is a bitmask. The valid values of the Verify parameter are as follows:

Bit 0: set this to 1 to enable detection intrusion

Bit 0 must be set to 1 to use the other two bits.

Bit 1 determines whether to reject or drop a connection. Setting it to 1 will drop the connection.

Bit 2 determines whether to give just warnings on bad requests or also on malicious (but not
invalid) requests

Bits 3 to 7 cannot be set – an error message displays if you try
to do this.

The following table lists the valid integers and the values they set the fields to when used:

Integer Detect Malicious Requests Intrusion Handling Warnings Checkbox

0

Disabled

N/A

N/A

62

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

1

2

3

4

5

6

7

Enabled

Enabled

Enabled

Enabled

Enabled

Enabled

Enabled

Drop Connection

Unchecked

Send Reject

Unchecked

Send Reject

Unchecked

Drop Connection

Drop Connection

Send Reject

Send Reject

Checked

Checked

Checked

Checked

You cannot set the Verify parameter to a value above 7 – 7 is
the maximum value.

3.6.1.6 WAF Settings

Name

Type Default

Range

Description

Intercept

B

0

0 –
Disabled

1 –
Enabled

InterceptOpts

S

<unset>

InterceptPOSTOtherContentTyp
es

S

<unset>

Enable/disable the Web
Application Firewall (WAF) for this
Virtual Service.

Most of the fields in the WAF
Options section of the Virtual
Service modify screen in the
LoadMaster WUI can be set using
this parameter. For more
information, refer to the WAF
InterceptOpts Parameter section.

When the otherctypesenable
parameter is enabled, use the
InterceptPOSTOtherContentTyp
es parameter to enter a comma-
separated list of POST content
types allowed for WAF analysis, for
example text/plain,text/css. By
default, all types (other than
XML/JSON) are enabled. To set

63

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

this to any other content types, set
the value to any.

Enabling the
inspection of any
other content types
may increase system
resource utilization
(CPU and memory). A
specific list of
content types should
be considered.

AlertThreshold

I

0 -
disabled

0 -
100000

This is the threshold of incidents
per hour before sending an alert.
Setting this to 0 disables alerting.

3.6.1.6.1 WAF InterceptOpts Parameter

The WAF InterceptOpts parameter is a special parameter – it can be used to set the value for
multiple fields, rather than just one field as with most other parameters. The InterceptOpts
parameter allows the specification of most of the fields in the WAF Options section of the Virtual
Service modify screen in the LoadMaster WUI.

To enable WAF, set the Intercept parameter to 1.

The names of the specific WUI fields that the InterceptOpts parameter is related to, are listed in the
table below.

One or more field values can be set in one command. Multiple values can be set in the one
command by separating the values with a semi-colon, for example:

https://<LoadMasterIPAddress>/access/modvs?vs=<VirtualServiceIPAddress>&port=
<Port>&prot=<tcp/udp>&InterceptOpts=opnormal;auditnone;reqdataenable;resdatae
nable;jsondisable;xmldisable

The table below outlines what each of the values mean.

64

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

The values that are related to the same WUI option are
mutually exclusive. For example, you cannot set Basic
Operation to both opnormal and opblock.

Value

opnormal

opblock

Related
WUI Option

Default

Default
Operation

Default
Operation

Audit
Only

Audit
Only

Meaning

Set the Basic Operation to Audit Only

Set the Basic Operation to Block Mode

auditnone

Audit mode No Audit

Set the Audit mode to No Audit. No data is
logged.

auditrelevant

Audit mode No Audit

auditall

Audit mode No Audit

Set the Audit mode to Audit Relevant. Logs data
which is of a warning level and higher.

Set the Audit mode to Audit All. Logs all data
through the Virtual Service.

The Audit All option is not recommended for use
in normal operation. Audit All should only be used
when troubleshooting a specific problem.

reqdataenable

reqdatadisable

resdataenable

resdatadisable

Inspect
HTML POST
Request
Content

Inspect
HTML POST
Request
Content

Process
Response
Data

Process
Response
Data

Disabled

Enable the Inspect HTML POST Request Content
option

Disabled

Disable the Inspect HTML POST Request Content
option

Disabled

Enable the Process Response Data option

Disabled

Disable the Process Response Data option

65

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

jsondisable

jsonenable

Enable
JSON
Parser

Enable
JSON
Parser

Enabled

Enabled

xmldisable

Enable XML
Parser

Enabled

xmlenable

Enable XML
Parser

Enabled

Disable the JSON parser.

This option is only relevant if the Inspect HTML
POST Request Content option is enabled.

Enable the JSON parser.

This option is only relevant if the Inspect HTML
POST Request Content option is enabled.

Disable the XML parser.

This option is only relevant if the Inspect HTML
POST Request Content option is enabled.

Enable the XML parser.

This option is only relevant if the Inspect HTML
POST Request Content option is enabled.

otherctypesdisable

Enable
Other
Content
Types

Disabled

Disable verification of POST content types (other
than XML/JSON).

Enable verification of POST content types (other
than XML/JSON).

otherctypesenable

Enable
Other
Content
Types

Disabled

Enabling the inspection of any
other content types may
increase system resource
utilization (CPU and memory). A
specific list of content types
should be considered.

When this option is enabled, the
InterceptPOSTOtherContentTypes parameter can
be used to enter a comma-separated list of POST
content types allowed for WAF analysis. By default,
all types (other than XML/JSON) are enabled.

66

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

3.6.1.6.2 Assign an WAF Rule to a Virtual Service

All rules for a particular WAF ruleset can be assigned to a Virtual Service by running the following
command.

https://<LoadMasterIPAddress>/access/vsaddwafrule?vs=<VSIPAddress>&port=<Port
>&prot=<tcp/udp>&rule=<Prefix>/<RuleName>

For example:

https://10.11.0.30/access/vsaddwafrule?vs=10.11.0.35&port=80&prot=tcp&rule=C/
modsecurity_crs_13_xml_enabler

The <RuleName> must be preceded with the relevant letter or word and a forward slash. The
letter/word used depends on the type of rule being added:

This is case sensitive. The letter/word needs to be in in the
correct case (as per the case used in this document below) for
the command to work.

C or Custom

Z  or ApplicationGeneric

A or ApplicationSpecific

G or Generic

All parameters listed in the example command above are
required for the vsaddwafrule command. If any of the
parameters is omitted, a String value missing error will be
displayed.

Multiple rules can be assigned in the same command by separating them with a space (or %20). For
example:

https://10.11.0.30/access/vsaddwafrule?vs=10.11.0.35&port=80&prot=tcp&rule=C/
modsecurity_crs_13_xml_enabler%20C/modsecurity_crs_10_ignore_static

View a list of rules and rule IDs for an active ruleset by running the vslistwafruleids command, for
example:

https://10.11.0.30/access/vslistwafruleids?
vs=10.11.0.35&port=80&prot=tcp&rule=G/ip_reputation

A list of rules and their IDs will be displayed for the specified ruleset, for example:

<Response stat="200" code="ok">

<Success>

67

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

<Data>

<ip_reputation>

<InactiveRule1>

2200000:REPUTATION/MALICIOUS:SLR: Client IP in Blocklist.

</InactiveRule1>

<InactiveRule2>

2200002:REPUTATION/ANONYMIZER:SLR: Client IP in TOR Exit Nodes Blocklist.

</InactiveRule2>

</ip_reputation>

</Data>

</Success>

</Response>

The ID is the number displayed before the rule name.

When adding a ruleset, you can specify the specific rules to not enable within the ruleset by
specifying the rule IDs to not enable, for example:

https://10.154.11.100/access/vsaddwafrule?vs=10.154.11.141&port=8443&prot=tcp
&rule=G/ip_reputation&disablerules=2200000

To disable a specific rule (or rules) (and not an entire ruleset), run the vsaddwafrule command with
a blank rule parameter, for example:

https://10.154.11.100/access/vsaddwafrule?vs=10.154.11.102&port=443&prot=tcp&
rule=&disablerules=960020,958291
Related WUI item

Virtual Services > View/Modify Services > Modify > WAF Options > Manage Rules

3.6.1.6.3 Unassign an WAF Rule from a Virtual Service

An WAF rule can be unassigned from a Virtual Service by running the following command. This
command related to the Available Rules and Assigned Rules fields in the Modify Virtual Service
screen in the WUI.

https://<LoadMasterIPAddress>/access/vsremovewafrule?vs=<VSIPAddress>&port=<P
ort>&prot=<tcp/udp>&rule=C/<RuleName>

For example:

https://10.11.0.30/access/vsremovewafrule?vs=10.11.0.35&port=80&prot=tcp&rule
=C/modsecurity_crs_13_xml_enabler

The <RuleName> must be preceded with the relevant letter/word and a forward slash. The
letter/word used depends on the type of rule being removed:

68

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

C or Custom

Z  or ApplicationGeneric

A or ApplicationSpecific

G or Generic

All of the parameters listed in the example command above are
required for the vsremovewafrule command. If any of them
are omitted, a String value missing error will be displayed.

Related WUI item

Virtual Services > View/Modify Services > Modify > WAF Options > Assign Rules

3.6.1.7 ESP Options

Name

Type

Default

Range

Description

AllowedHosts

S

<unset>

AllowedDirectories

S

<unset>

You can specify up to
254 characters for this
parameter.

Domain

S

<unset>

This parameter is
only relevant when
ESP is enabled.
Specify all the
virtual hosts that
can be accessed
using this Virtual
Service.

This parameter is
only relevant when
ESP is enabled.
Specify all the
virtual directories
that can be
accessed using this
Virtual Service.

The Single Sign On
(SSO) domain in
which this Virtual
Service will
operate.

69

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

This parameter is
only relevant when
ESP is enabled and
when the Client
Authentication
Mode is set to
Form Based.
Specify the string
that the
LoadMaster should
use to detect a
logout event.
Multiple logoff
strings can be
specified by using
a space-separated
list.

If the URL to be
matched contains
sub-directories
before the
specified string,
the Logoff String
will not be
matched.
Therefore, the
LoadMaster will
not log the user off.

This option is only
available if SAML is
selected as the
InputAuthMode.
Specify the name
of the HTTP
header. This
header is added to

Logoff

S

<unset>

You can specify up to
255 characters for this
parameter.

AddAuthHeader

S

<unset>

You can specify up to
255 characters for this
parameter.

70

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

the HTTP request
from the
LoadMaster to the
Real Server and its
value is set to the
user ID for the
authenticated
session. You can
unset the value of
this parameter by
running the modvs
command with the
addauthheader
parameter set to
an empty string,
for example:
addauthheader=

Display the
public/private
option on the login
page. Based on the
option the user
selects on the login
form, the session
timeout value will
be set to the value
specified for either
the public or
private timeout.

Enabling this
option removes the
password field
from the login
page. This may be
needed when
password
validation is not
required, for

DisplayPubPriv

B

1 – Enabled

0 – Disabled

1 – Enabled

DisablePasswordFor
m

B

0 – Disabled

0 – Disabled

1 – Enabled

71

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

Captcha

B

0 – Disabled

0 – Disabled

1 – Enabled

example if using
RSA SecurID
authentication in a
singular fashion.

Enable this
parameter to allow
CAPTCHA
verification on the
login page.

The
LoadMaster
only
supports
CAPTCHA
v2. The
InputAuthM
ode must
be set to 2
(Form
Based) for
the
CAPTCHA
parameters
to be
relevant

All
CAPTCHA
parameters
must be set
before it
can be
used.

72

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

CaptchaPublicKey

S

<unset>

Both the
LoadMaster
and the
client
machine
must be
able to
access
Google for
this to
work.

Before the
CAPTCHA has been
correctly
answered, the
submit button on
the login form is
disabled. If the
user does not
submit the form
within two minutes
of answering the
CAPTCHA, the
CAPTCHA times out
(Google-specified
timeout), and the
user must verify a
new CAPTCHA (the
submit button is
disabled until the
new CAPTCHA has
been verified).

The key that was
provided as the
public key when
you signed up for

73

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

CaptchaPrivateKey

S

<unset>

CaptchaAccessUrl

S

www.google.com/r
ecap tcha/api.js

CaptchaVerifyUrl

S

www.google.com/r
ecap
tcha/api/siteverify

the CAPTCHA
service.

The key that was
provided as the
private key when
you signed up for
the CAPTCHA
service.

The URL of the
service that
provides the
CAPTCHA
challenge.

Do not start
this URL
with https.

Only
CAPTCHA
V2 is
currently
supported.

The URL of the
service that verifies
the response to the
CAPTCHA
challenge.

Do not start
this URL
with https.

74

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

Only
CAPTCHA
V2 is
currently
supported.

Enable ESP
logging. Valid
values are below:

0 = Logging off

1 = User Access

2 = Security

3 = User Access
and Security

4 = Connection

5 = User Access
and Connection

6 = Security and
connection

7 = User Access,
Security and
Connection

Note: The only
valid values for
SMTP services are
0 and 4. For SMTP
services, security
issues are always
logged. Nothing is
logged for user
access because
there are no logins.

Specify all the

ESPLogs

I

7

Integer 0-7

SMTPAllowedDomai

S

<unset>

75

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

ns

ExcludedDirectories

S

<unset>

EspEnabled

B

N

0 – Disabled

1 - Enabled

InputAuthMode

I

0

0-8

permitted domains
that are allowed to
be received by this
Virtual Service.

This parameter is
only relevant when
ESP is enabled. Any
virtual directories
specified within
this field will not
be pre-authorized
on this Virtual
Service and are
passed directly to
the relevant Real
Servers.

Enable or disable
the Edge Security
Pack (ESP)
features.

Specify the client
authentication
method to be used:

0 = Delegate to
Server

1 = Basic
Authentication

2 = Form Based

4 = Client
Certificate

5 = NTLM

6 = SAML

7 = Pass Post

76

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

OutputAuthMode

I

Dependent on
InputAuthMode
value

0-4

TokenServerFQDN

S

<unset>

You can specify up to
127 characters for this
parameter.

8 = OIDC / OAUTH

Specify the server
authentication
mode to be used:

0 = None

1 = Basic
Authentication

2 = Form Based

3 = KCD

4 = Server Token

This parameter is
only relevant when
using SAML as the
Client
Authentication
Mode
(InputAuthMode)
and Server Token
as the Server
Authentication
Mode
(OutputAuthMode).
When set, the
LoadMaster
contacts the token
server at the given
FQDN during sign-
on and obtains a
permanent access
token from that
token server. If this
parameter is unset,
then the
LoadMaster
obtains the token

77

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

ServerFbaPath

S

<unset>

ServerFBAPost

S

<unset>

from the Real
Server.

Only relevant when
using form-based
authentication as
the Server
Authentication
Mode
(
OutputAuthMode).
Set the
authentication
path for server-side
Form Based
Authentication
(FBA). When used
in Exchange
environments, this
does not need to
be set.

Only relevant when
using form-based
authentication as
the Server
Authentication
Mode
(
OutputAuthMode).
Set the format
string used to
generate POST
body for server
side FBA. The value
must be base64-
encoded.

When used in
Exchange

78

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

environments, this
does not need to
be set.

This option is only
relevant if the
InputAuthMode is
set to 2 (Form
Based), the
OutputAuthMode
is set to 2 (Form
Based), and the
ServerFbaPath
has been entered.
Enable this option
to send the
username only
(without the
domain part) in the
server-side form
based
authentication
POST request.

Enter the name of
the outbound SSO
domain.

This parameter
relates to the SSO
Image Set drop-
down in the ESP
Options section of
the modify Virtual
Service screen.
Specify the name
of the image set to
be used for the
login screen. If no
image set is

ServerFbaUsername
Only

B

0 – Disabled

0 – Disabled

1 - Enabled

OutConf

S

<unset>

SingleSignOnDir

S

<unset>

- Blank

- Dual Factor
Authentication

- Exchange

- Français%20Canadien
%20-%20Blank

- Français%20Canadien
%20-%20Exchange

- Português%20do
%20Brasil%20-%20Blan

79

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

k

- Português%20do
%20Brasil%20-%20Exch
ange

SingleSignOnMessag
e

S

<unset>

You can specify up to
255 characters for this
parameter.

specified, the
default Exchange
image set will be
used.

Specifies the SSO
message that is
displayed. The
SingleSignOnMess
age parameter
accepts HTML
code, so you can
insert an image if
required.

There are
several
characters
that are not
supported.
These are
the grave
accent
character (
` ) and the
single
quote ('). If
a grave
accent
character is
used in the
SingleSign
OnMessage
, the
character
will not

80

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

AllowedGroups

S

<unset>

You can specify up to
2048 characters for this
parameter.

display in
the output,
for example
a`b`c
becomes
abc. If a
single
quote is
used, users
will not be
able to log
in.

Specify the groups
that are allowed to
access this Virtual
Service.

If the
parameter
value is
longer than
the
maximum
length of a
HTTP GET
query (1024
characters),
you must
set the
HTTP
Method to
POST.

GroupSIDs

S

<unset>

This parameter allows a
list of group SIDs of up
to 64 bytes and 2048

Specify the group
security identifiers
(SIDs) that are

81

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

characters in length.

allowed to access
this Virtual Service.

Each group is
separated by a
semi-colon. Spaces
are used to
separate bytes in
certain group SIDs.
Here is an
example:

S-1-5-21-
703902271-
2531649136-
2593404273-1606

SIDs can be found
by using the get-
adgroup-Identity
GroupName
command.

If the
parameter
value is
longer than
the
maximum
length of
HTTP GET
query (1024
characters),
you must
set the
HTTP
Method to

82

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

IncludeNestedGroup
s

B

0 - Disabled

0 – Disabled

1 - Enabled

SteeringGroups

String

<unset>

You can specify up to
2048 characters for this
parameter.

POST.

This parameter
relates to the
AllowedGroups
parameter. Enable
this option to
include nested
groups in the
authentication
attempt. If this
option is disabled,
only users in the
top-level group will
be granted access.
If this option is
enabled, users in
both the top-level
and first sub-level
group will be
granted access.

Enter the Active
Directory group
names that will be
used for steering
traffic. Use a semi-
colon to separate
multiple group
names. The
steering group
index number
corresponds to the
location of the
group in this list.

If the
parameter
value is

83

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

longer than
the
maximum
length of a
HTTP GET
query (1024
characters),
you must
set the
HTTP
Method to
POST.

Enable this option
to verify if the
authentication
header contains a
bearer record. This
is used when doing
JSON web token
validation.

This option is only
visible if the
VerifyBearer
parameter is
enabled.

Specify the name
of the relevant
certificate (this
must be first
uploaded to the
LoadMaster using
the addcert
command)
containing a Public
Key used to

VerifyBearer

Boolea
n

0 - Disabled

0 - Disabled

1 - Enabled

BearerCertificateNa
me

String

<unset>

A valid name of an
uploaded certificate.

84

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

BearerText

String

<unset>

ExcludedDomains

String

<unset>

AltDomains

String

<unset>

validate the
authenticity of the
JSON Web Token
Signature. This is
used when doing
JSON web token
validation.

This option is only
visible if the
VerifyBearer
parameter is
enabled.

You can enter up to
five bearer header
validation strings
(comma-separated
list). This is used
when doing JSON
web token
validation.

Any virtual
directories
specified within
this field will not
be pre-authorized
on this Virtual
Service and will be
passed directly to
the relevant Real
Servers. Multiple
excluded domains
can be specified by
using a space-
separated list.

Specify alternative
domains to be

85

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

SameSite

I

0 – System Default
1 – SameSite=None
2 - SameSite=LAX
3 - SameSite=Strict
4 - SameSite Option Not
Added

UserPwdChangeURL

String

<unset>

assigned to a
Virtual Service
when configuring
multi-domain
authentication. To
specify multiple
alternative
domains, use a
space separated
list.

Allows the
SameSite attribute
to be explicitly
specified for
cookies used by
LoadMaster Edge
Security Pack. This
influences the way
browsers will use
cookies across
sites.

This is relevant
when using form-
based LDAP
authentication.
Specify the URL
that users can use
to change their
password. If a
user’s password
has expired, or if
they must reset
their password,
this URL and the
UserPwdChangeM
sg is displayed on
the login form.

86

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

UserPwdChangeMsg

String

<unset>

UserPwdExpiryWarn

Boolea
n

0 - Disabled

0 - Disabled

1 - Enabled

This URL must be
put into the
exception list for
authentication, if
required.

This parameter is
only relevant if the
UserPwdChangeU
RL parameter is
set. Specify the
text to be
displayed on the
login form when
the user must reset
their password.

By default, SSO
users are notified
about the number
of days before they
must change their
password. If you
disable this option,
the password
expiry notification
will not appear on
the login forms.
This parameter is
only relevant if the
InputAuthMode is
set to Form Based
(2) and the
UserPwdChangeU
RL is set.

The language of
the warning text is
based on the
SSO Image Set

87

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

UserPwdExpiryWarn
Days

Integer

15

1 - 30

that is selected
(English, French, or
Portuguese).

Specify the number
of days to show the
warning before the
password is
expired. This
parameter is only
relevant if the
InputAuthMode is
set to Form Based
(2) and the
UserPwdChangeU
RL is set.

3.6.1.8 Real Servers

Name

Type

Default

Range

Description

CheckType

S

<tcp>

The default
value is
dependent
on the
Virtual
Service
port. The
list of values
is:

icmp

https

http

tcp

smtp

nntp

Specify which protocol is to be
used to check the health of the
Real Server.

88

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

ftp

telnet

pop3

imap

rdp

bdata

ldap

none

LdapEndpoint

S

<unset>

An existing
endpoint
name

CheckHost

A

<unset>

CheckPattern

S

<unset>

Specify the name of an LDAP
endpoint to use for the health
checks. If LDAP is selected as the
CheckType, the server IP address
(or addresses) and ports from the
LDAP endpoint configuration are
used instead of the Real Server IP
address and port. For further
information on LDAP endpoints,
refer to the LDAP Configuration
section.

The CheckUse1.1 parameter must
be enabled to set the CheckHost
value. When using HTTP/1.1
checking, the Real Servers require
a Hostname be supplied in each
request. If no value is set then this
value is the IP address of the
Virtual Service.

When the CheckType is set to http
or https - this corresponds to the
Reply 200 Pattern in the WUI. This
parameter only applies when the
HTTP Method is set to GET or
POST. When the CheckType is set

89

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

to bdata: Specify the hexadecimal
string which will be searched for in
the response. Specify an empty
value to unset CheckPattern.

When the CheckType is set to http
or https - by default, the health
checker tries to access the URL / to
determine if the machine is
available. A different URL can be
set in the CheckUrl parameter.

When the CheckType is set to
bdata: Specify a hexadecimal
string to send to the Real Server.

The maximum character length for
the CheckUrl parameter value is
126 characters.

A space-separated list of HTTP
status codes that should be
treated as successful when
received from the Real Server.

Specify up to four additional
headers/fields which will be sent
with each health check request.
Separate the pairs with a pipe, for
example; Host:xyc|UserAgent:prq.

This parameter is only relevant
when the CheckType is set to
bdata. Specify the number of
bytes to find the CheckPattern
within.

By default, the health checker uses
HTTP/1.0 when checking the Real
Server status. Enabling
CheckUse1.1 means HTTP/1.1 is
used (which is more efficient).

CheckUrl

S

<unset>

CheckCodes

S

<unset>

300-599

CheckHeaders

S

<unset>

MatchLen

CheckUse1.1

S

B

0

0-8000

N

0 – Disabled

1 - Enabled

90

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

CheckPort

I

<unset>

3-65530

NumberOfRSs

NRules

RuleList

CheckUseGet

ExtraHdrKey

ExtraHdrValue

I (Read
only)

I (Read
only)

List(Read
only)

I

S

S

<unset>

<unset>

N

<unset>

<unset>

CreateSubVS

<unset>

0 - HEAD

1 - GET

2 - POST

3 - OPTIONS

Optimization only
works on HTTP (not
HTTPS) connections.

The port to be checked. If a port is
not specified, the Real Server port
is used. Specify 0 to unset
CheckPort.

This displays the number of Real
Servers that are assigned to the
Virtual Service.

This displays the number of rules
assigned to a Real Server when
content switching is enabled.

A list of content rules assigned to
the Real Servers.

When accessing the health check
URL - the system can use the
HEAD, the GET, the POST or the
OPTIONS method.

Specify the key for the extra
header to be inserted into every
request sent to the Real Servers.

Specify the value for the extra
header to be inserted into every
request sent to the Real Servers.

This parameter can be used to
create a SubVS within a Virtual
Service. This parameter has no
value (entering createsubvs= will
create a SubVS).

SubVS

I (Read
Only)

0 – Disabled

This parameter displays details of
any SubVSes which exist in the

91

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

1 – Enabled

Virtual Service.

CheckPostData

S

<unset>

Supports up
to 2047
characters

RSRulePrecedence

String

<unset>

RSRulePrecedencePos

Int16

<unset>

EnhancedHealthchecks

Boolean

0 –
Disabled

0 – Disabled

1 – Enabled

RsMinimum

Integer

1

1 to the

This parameter is only relevant if
the HTTP Method is set to POST.
When using the POST method, up
to 2047 characters of POST data
can be sent to the server.

This parameter should be used in
conjunction with
RSRulePrecedencePos. This
parameter is used to specify the
name of the existing rule whose
position you wish to change.

This parameter, in conjunction
with the RSRulePrecedence
parameter, is used to change the
position of the rule in a sequence
of rules. For example, a position of
2 means the rule will be checked
second.

Enabling the
EnhancedHealthchecks
parameter provides an additional
health check parameter –
RsMinimum. If the
EnhancedHealthchecks
parameter is disabled, the Virtual
Service will be considered
available if at least one Real Server
is available. If the
EnhancedHealthchecks
parameter is enabled, you can
specify the minimum number of
Real Servers which should be
available to consider the Virtual
Service to be available.

This parameter can only be set

92

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

number of
Real Servers
configured

using the modvs command if the
EnhancedHealthchecks
parameter is enabled. Specify the
minimum number of Real Servers
required to be available for the
Virtual Service to be considered
up. If less than the minimum
amount of Real Servers are
available, a critical log is
generated. If some Real Servers are
down but it has not reached the
minimum amount specified, a
warning is logged. If the email
options are configured, an email
will be sent to the relevant
recipients.

When retrieving the value of this
parameter – 0 is the default value
if there are no Real Servers or 1
Real Server in the Virtual Service.
However, 1 is always the minimum
in reality.

3.6.1.9 Miscellaneous

Name

Type

Default

Range

Description

Adaptive

S
(Read
only)

<unset>

MultiConnect

B

0

This parameter is read only and will only be
displayed when the Scheduling Method is set to
resource based (adaptive).

Enabling this option permits the LoadMaster to
manage connection handling between the
LoadMaster and the Real Servers. Requests from
multiple clients will be sent over the same TCP
connection.

Multiplexing only works for simple HTTP GET
operations. This parameter cannot be enabled in
certain situations, for example if WAF, ESP or SSL

0 -
Disabled

1 -
Enabled

93

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

non_local

B

0 -
Disabled

Acceleration is enabled.

0 –
Disabled

1 –
Enabled

By default, only Real Servers on local networks
can be assigned to a Virtual Service. Enabling this
option will allow a non-local Real Server to be
assigned to the Virtual Service.

This option will only be available if NonLocalRS
has been enabled and the Transparent option
has been disabled on the relevant Virtual Service.

3.6.2 Adding a Virtual Service Using a Template

To add a Virtual Service and automatically configure it with a template, run the following command:

https://<LoadMasterIPAddress>/access/addvs?vs=<VSIPAddress>&port=<port>&prot=
<tcp/udp>&template=<TemplateName>

The port and protocol parameters are required, but if the template sets the ports then the values
entered in the command will be ignored.

For commands on adding, removing and listing templates, refer to the Manage Templates section.

3.6.3 Manage Templates

3.6.3.1 Export a Virtual Service as a Template

An existing Virtual Service can be exported as a template by running the following command:

https://<LoadMasterIPAddress>/access/exportvstmplt?vs=<VirtualServiceIPAddres
s>&port=<VirtualServicePort>&prot=<tcp/udp>

The Virtual Service index can also be entered for the vs parameter (and the other parameters are
then not needed). To retrieve the Virtual Service ID, run the listvs command. For further
information, refer to the Virtual Service Control section.

3.6.3.2 Upload a Template

Templates can be uploaded by running the following cURL command:

curl –X POST --data-binary “@<TemplateFileName.tmpl>” –k
https://bal:<password>@<LoadMasterIPAddress>/access/uploadtemplate

3.6.3.3 Display a List of Installed Templates

To display a list of the templates that exist on the LoadMaster, run the following command:

https://<LoadMasterIPAddress>/access/listtemplates

94

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

3.6.3.4 Delete a Template

To delete a template from the LoadMaster, run the following command:

https://<LoadMasterIPAddress>/access/deltemplate?name=<TemplateName>

3.6.4 Manage SSO

3.6.4.1 SSO Domains

Single-Sign On Domains can be managed by the following commands.

When the kcdciphersha1 parameter is enabled, the AES256 SHA1 KCD cipher is used (by default the
RC4 cipher is used).

To retrieve the value of the kcdciphersha1 parameter, run the following command:

https://<LoadMasterIPAddress>/access/get?param=kcdciphersha1

To enable or disable the kcdciphersha1 parameter, run the following command:

https://<LoadMasterIPAddress>/access/set?param=kcdciphersha1&value=1

0 - Disabled

1 - Enabled

To add a domain:

https://<LoadMasterIPAddress>/access/adddomain?domain=<DomainName>

You can specify up to 64 characters in the domain parameter.
The maximum number of SSO domains that are allowed is 128.

To delete a domain:

https://<LoadMasterIPAddress>/access/deldomain?domain=<DomainName>

To show details of all domains:

https://<LoadMasterIPAddress>/access/showdomain

To show details of a specific domain:

https://<LoadMasterIPAddress>/access/showdomain?domain=<DomainName>

To modify a specific domain:

https://<LoadMasterIPAddress>/access/moddomain?domain=<DomainName>
[&paramname=value...]

moddomain accepts the following additional (optional) parameters:

95

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

Name

Type

Default

Range

Additional Information

auth_type

S

LDAP-StartTLS

LDAP-Unencrypted

LDAP-StartTLS

LDAP-LDAPS

RADIUS

RSA-SECURID

KCD

Certificates

RADIUS and LDAP-
Unencrypted

RADIUS%20and%20LDAP-
StartTLS

RADIUS%20and%20LDAP-
LDAPS

RSA-
SECURID%20and%20LDAP-
Unencrypted

RSA-
SECURID%20and%20LDAP-
StartTLS

RSA-
SECURID%20and%20LDAP-
LDAPS

OIDC-OAUTH

Specify the transport
protocol used to
communicate with the
authentication server.

ldap_
endpoint

S

None

The name of an existing
LDAP endpoint

Specify the LDAP
endpoint to use. For
further information on
LDAP endpoints, refer to
the LDAP Configuration
section.

96

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

radius_
shared_
secret

S
(masked)

<unset>

radius_
send_nas_
id

B

0 - Disabled

0 - Disabled

1 - Enabled

radius_
nas_id

S

The hostname

The shared secret to be
used between the
RADIUS server and the
LoadMaster.

If this parameter is
disabled (default), a NAS
identifier is not sent to
the RADIUS server. If it is
enabled, a Network
Access Server (NAS)
identifier string is sent to
the RADIUS server. By
default, this is the
hostname. Alternatively,
if a value is specified in
the radius_nas_id
parameter, this value is
used as the NAS
identifier. If the NAS
identifier cannot be
added, the RADIUS
access request is still
processed. This field is
only available if the
auth_type is set to a
RADIUS option.

If the radius_send_nas_
id parameter is enabled,
the radius_nas_id
parameter is relevant.
When specified, this
value is used as the
NAS identifier. Otherwise,
the hostname is used as
the NAS identifier. If the
NAS identifier cannot be
added, the RADIUS

97

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

access request is still
processed.

This parameter is only
relevant if the auth_type
is set to a RADIUS option
and the radius_send_
nas_id parameter is
enabled.

Specify the logon string
format used to
authenticate to the
LDAP/RADIUS server.

The Username%20only
value is only available if
the auth_type is set to a
RADIUS or RSA-SecurID
protocol. The Username
value is not available if
the auth_type is set to
RADIUS or a RADIUS and
LDAP protocol.

Specify the logon string
format used to
authenticate to the
server.

This parameter
corresponds with the
Domain/Realm field in
the WUI. The login
domain to be used. This
is also used with logon
format to construct the
normalized user name,
for example:

Principalname:
<username>@<domain>

logon_fmt

S

Principalname

not%20specified

Principalname

Username

Username%20only

Not%20specified

logon_fmt2

S

Principalname

Principalname

Username

logon_
domain

S

<unset>

98

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

logon_
transcode

B

0

0 - Disabled

1 - Enabled

user_acc_
control

max_
failed_
auths

sess_tout_
idle_pub

I

I

I

0

0

0-300

0-999

900

60-604800

Username:

<domain>\<username>

Enable or disable the
transcode of logon
credentials from ISO-
8859-1 to UTF-8, when
required.

Specify the range in
which periodic User
Access Control (UAC)
checks are performed.
When an interval value is
specified in the range of 1
to 300 minutes, the
periodic UAC check is
performed per user for
the requests received
after the interval expiry.

If the interval
value is set to 0
minutes, then
the UAC check
is not
performed.

The maximum number of
failed login attempts
before the user is locked
out.

0 – Never lock out.

The session idle timeout
value in seconds. This
value is used in a public
environment.

99

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

sess_tout_
duration_
pub

sess_tout_
idle_priv

sess_tout_
duration_
priv

sess_tout_
type

testuser

I

I

I

S

S

1800

60-604800

900

60-604800

2800

60-604800

idle time

max duration

idle time

<unset>

testpass

S
(masked)

<unset>

reset_fail_
tout

I

60

60-86400

The maximum duration
timeout value for the
session in seconds. This
value is used in a public
environment.

The session idle timeout
value in seconds. This
value is used in a private
environment.

The maximum duration
timeout value for the
session in seconds. This
value is used in a private
environment.

Specify the type of
session timeout to be
used.

The username that will
be used to check the
authentication server(s),
if you are not using an
LDAP endpoint.

The password of the user
that is used to check the
authentication server(s),
if you are not using an
LDAP endpoint.

The number of seconds
that must elapse before
the Failed Login
Attempts counter is
reset to 0. This value
must be less than the
unblock_tout.

100

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

unblock_
tout

I

1800

60-86400

server

S

<unset>

server2

A

<unset>

Valid IP address

kerberos_
domain

kerberos_
kdc

kcd_
username

kcd_
password

S

S

S

S

<unset>

<unset>

<unset>

<unset>

The timeout value (in
seconds) before a
blocked account is
automatically unblocked.
This must be greater than
the reset_fail_tout
value.

The address(s) of the
server(s) that are to be
used to validate this
domain.

IPv6 is not
supported for
RADIUS
authentication.

When using dual factor
authentication, use the
server parameter to set
the address of the
RADIUS server(s) and use
the server2 parameter to
set the address of the
LDAP server(s).

The Kerberos Realm

The Kerberos Key
Distribution Center

The kcd_username
should not contain
double or single quotes.

The kcd_password
should not contain
double or single quotes.

101

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

ldap_
admin

ldap_
password

S

S

<unset>

<unset>

cert_
check_asi

B

0 - Disabled

0 - Disabled

1 - Enabled

cert_
check_cn

B

0 - Disabled

0 - Disabled

1 - Disabled

server_side

B

Y – Outbound
KCD SSO
domain

Y = Outbound KCD SSO
domain

N = Inbound configuration

idp_entity_
id

S

<unset>

This, along with the
ldap_password, is used
to log in to the database
to check if the user from
the certificate exists.

This, along with the
ldap_admin, is used to
log in to the database to
check if the user from the
certificate exists.

This option is only
available when the
Authentication Protocol
is set to Certificates.
When this option is
enabled - in addition to
checking the validity of
the client certificate, the
client certificate will also
be checked against the
altSecurityIdentities (ASI)
attribute of the user on
the Active Directory.

Enabling this parameter
allows a fallback to check
the Common Name (CN)
in the certificate when
the SAN is not available.

Specify whether the
configuration is inbound
or outbound.

Specify the Identity
Service Provider (IdP)
Entity ID. This is relevant
when using SAML. The

102

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

idp_sso_url

S

<unset>

Idp_logoff_
url

idp_cert

idp_
match_cert

S

S

B

<unset>

<unset>

0 - Disabled

0 - Disabled

1 - Enabled

sp_entity_
id

S

<unset>

maximum number of
characters permitted in
this field is 255.

Specify the IdP Single
Sign On (SSO) URL. This
is relevant when using
SAML. The maximum
number of characters
permitted in this field is
255.

Specify the IdP Logoff
URL. This is relevant
when using SAML. The
maximum number of
characters permitted in
this field is 255.

Specify the IdP certificate
to use for verification
processing.

If this option is enabled,
the IdP certificate
assigned must match the
certificate in the IdP
SAML response.

Relevant when using
SAML - the Service
Provider (SP) entity ID is
an identifier that is
shared to enable the IdP
to understand, accept
and have knowledge of
the entity when request
messages are sent from
the LoadMaster. This
must correlate to the
identifier of the relying

103

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

sp_cert

S

<unset>

party on the AD FS
server. The maximum
number of characters
permitted in this field is
255.

It is optional to sign
requests that are sent in
the context of logon.
Currently, the
LoadMaster does not sign
those requests.

In the context of log off
requests – it is
mandatory and these
requests must be signed.
This is to avoid any
spoofing and to provide
extra security in relation
to log off functionality.
This ensures that users
are not being hacked and
not being logged off
unnecessarily.

In the sp_cert parameter,
you can choose to use a
self-signed certificate or
third party certificate to
perform the signing.

To specify a self-signed
certificate, set sp_cert to
useselfsigned. To use a
third party certificate,
specify the name of the
certificate to use (this
certificate must be
uploaded to the
intermediate certificate

104

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

ldapephc

B

1 - Enabled

0 - Disabled

1 - Enabled

oidc_app_
id

S

<unset>

oidc_
redirect_
uri

S

<unset>

oidc_auth_
ep_url

oidc_

S

S

<unset>

<unset>

section of the
LoadMaster before it can
be selected).

Enable this parameter to
use the LDAP endpoint
admin username and
password for the health
check.

Add the Application
(client) ID of the
application. The
maximum number of
characters permitted in
this field is 255.

Specify the redirect
Uniform Resource
Identifier (URI) or URIs
(reply URLs). You can
enter multiple URIs
separated by a space. A
maximum of 255
characters can be
specified for the oidc_
redirect_uri parameter.
Once a value is set for
this parameter, you
cannot unset it.

Specify the authorization
end point URL of the
application. Ensure to
use the correct URL
format. The maximum
number of characters
permitted in this field is
255.

Specify the token end

105

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

token_ep_
url

oidc_
logoff_url

S

<unset>

oidc_secret

S

<unset>

point URL of the
application. Ensure to
use the correct URL
format. The maximum
number of characters
permitted in this field is
255.

Specify the logoff URL of
the application. Ensure to
use the correct URL
format. The maximum
number of characters
permitted in this field is
255.

Specify the OIDC
application secret of the
application.

To show the locked users, run the following command:

https://<LoadMasterIPAddress>/access/showdomainlockedusers?

To unlock specified users, run the following command:

https://<LoadMasterIPAddress>/access/unlockdomainusers?domain=<DomainName>&us
ers=<exampleuser>

3.6.4.1.1 Upload RSA Files

If using RSA-SecurID as the Authentication Protocol, files need to be uploaded to the LoadMaster
for the authentication to work.

To upload the RSA Authentication Manager Config File, run the following command:

curl –X POST -–data-binary “@<RSAConfigFileName.zip>” –k
https://<username>:<password>@<LoadMasterIPAddress>/access/setrsaconfig

To upload the RSA Node Secret File, run the following command:

curl –X POST -–data-binary “@<NodeSecretFileName.zip>” –k
https://<username>:<password>@<LoadMasterIPAddress>/access/setrsanodesecret?r
sanspwd=<RSANodeSecretPassword>

106

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

3.6.4.1.2 Upload an Identity Provider (IdP) Metadata File (if using SAML)

The uploadsamlidpmd command is used to upload an IdP metadata file. This simplifies the
configuration of the IdP attributes, including the IdP Entity ID, IdP SSO URL and IdP Logoff URL.
The metadata file can be downloaded from the IdP. To upload an IdP metadata file, run the
following command:

https://<LoadMasterIPAddress>/access/uploadsamlidpmd?domain=<DomainName>

3.6.4.1.3 Download the Service Provider Certificate (if using SAML)

If using a self-signed certificate, the downloadsamlspcert command is used to download the
certificate from the LoadMaster. This certificate must be installed on the IdP server (for example AD
FS) to be added to the relying party signature.

The AD FS server will require this certificate for use of the public key to verify the signatures that the
LoadMaster generates.

To download the certificate, run the following command:

https://<LoadMasterIPAddress>/access/downloadsamlspcert?domain=<DomainName>

3.6.4.1.4 Sessions

The commands in this section relate to the open SSO sessions.

To filter the list of open sessions by user, run the search command and specify the user, for
example:

https://<LoadMasterIPAddress>/access/ssodomain/search?domain=<DomainName>&use
r=<Username>

The match is based on a substring of the username and is not
exact.

The user parameter is not case sensitive.

To retrieve a list of all open sessions for a specific SSO domain, run the following command:

https://<LoadMasterIPAddress>/access/ssodomain/queryall?domain=<DomainName>

This returns the number of active user and cookie sessions.

To return sessions within a particular range, run the querysessions command, for example:

https://<LoadMasterIPAddress>/access/ssodomain/querysessions?domain=<DomainNa
me>&startsession=1&endsession=1000

This returns sessions in sequence, as they appear in the cache.

107

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

If you do not specify the startsession and endsession parameters, the first 1000 sessions display.

The maximum number of SSO sessions that can be returned in
a single querysessions API call is limited to 1000. If the
maximum number of SSO sessions exceeds 1000, you must use
multiple querysessions API calls.

To kill a particular session, run the following command:

https://<LoadMasterIPAddress>/access/ssodomain/killsession?domain=<DomainName
>&key=<<Cookie>/<Username>,<SourceIPAddress>>

For the key parameter, you can either specify the Cookie or <Username>,<SourceIPAddress>.

For example, if using a cookie:

https://10.154.11.180/access/ssodomain/killsession?domain=qasp.com&key=b6bfa6
6e23ee2d9c3267704bfd20f053

Or if using <Username>,<SourceIPAddress>:

https://10.154.11.180/access/ssodomain/killsession?domain=kempqaesp.net&key="
esptest1@kempqaesp.net,172.21.135.241"

To kill all open sessions for a particular domain, run the following command:

https://<LoadMasterIPAddress>/access/ssodomain/killallsessions?domain=<Domain
Name>

3.6.4.2 SSO Image Sets

Custom SSO image sets can be managed by using the following commands:

https://<LoadMasterIPAddress>/access/listssoimages
https://<LoadMasterIPAddress>/access/delssoimage?name=<Imagesetname>

To upload an SSO image set, use the below command:

curl –X POST -–data-binary "@<pathToImageSet>" –k
https://<LoadMasterIPAddress>/access/ssoimages?

The custom SSO image set must be in the format of a .tar file. A template tar file is available from
the Kemp Support site: Single Sign-On Custom Images. This can then be modified to gain the desired
look and feel. For further information, please refer to the Custom Authentication Form, Technical
Note.

3.6.5 Cache Configuration

File extensions can be added or deleted from the list of file extensions that should not be cached by
using the following commands:

https://<LoadMasterIPAddress>/access/addnocache?param=<FileExtension>

108

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

https://<LoadMasterIPAddress>/access/delnocache?param=<FileExtension>

The <FileExtension> string must begin with a “.”, for example:

https://<LoadMasterIPAddress>/access/addnocache?param=.jpg

Related parameters that can be managed using get and set commands are detailed in the following
table. Refer to the Using get and set commands section for the get and set commands.

Name

Type

Range

Description

cachesize

hostcache

I

B

1-409

Specifies the cache size.

0 - Disabled

1 – Enabled

Enable or disable using the host cache.

3.6.6 Compression Options

File extensions can be added or deleted from the list of file extensions that should not be
compressed by using the following commands:

https://<LoadMasterIPAddress>/access/addnocompress?param=<.FileExtension>
https://<LoadMasterIPAddress>/access/delnocompress?param=<.FileExtension>

The <FileExtension> string must begin with a “.”

3.6.7 Kubernetes Settings

This section provides details about the LoadMaster RESTful API commands you can use to configure
the Kubernetes Ingress Controller functionality.

3.6.7.1 Upload a Kube Config File

To upload a Kube config file to the LoadMaster, run the addlmingressk8sconf as a cURL command.
For example:

curl -X POST --data-binary "@<KubeConfigFilename>" -k
https://<Username>:<Password>@<LoadMasterIPAddress>/access/addlmingressk8scon
f

3.6.7.2 Delete the Kube Config File

To delete the existing Kube config file from the LoadMaster, run the dellmingressk8sconf
command. For example:

/access/dellmingressk8sconf

109

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

3.6.7.3 List the Contexts in the Kube Config File

To list the contexts in the Kube config file that is installed on the LoadMaster, run the
showlmingressk8sconf command. For example:

/access/showlmingressk8sconf

3.6.7.4 Check the Operations Mode

To check what Operations Mode is currently selected, run the getlmingressmode command. For
example:

/access/getlmingressmode

3.6.7.5 Set the Operations Mode

To set the Operations Mode, run the setlmingressmode command. For example:

/access/setlmingressmode?mode=<Service/Ingress>

3.6.7.6 Check the Namespace being Watched

To check what namespace is currently being watched, run the getlmingressnamespace command.
For example:

/access/getlmingressnamespace

3.6.7.7 Set the Namespace to Watch

To set the Namespace to Watch, run the setlmingressnamespace command. For example:

/access/setlmingressnamespace?namespace=<Namespace>

3.6.7.8 Check the Watch Timeout

To check the current LMingress Watch Timeout (in seconds), run the getlmingresswatchtimeout
command. For example:

/access/getlmingresswatchtimeout

3.6.7.9 Set the Watch Timeout

To set the LMingress Watch Timeout (in seconds), run the setlmingresswatchtimeout command.
For example:

/access/setlmingresswatchtimeout?watchtimeout=<TimeoutInSeconds>

3.6.7.10 Restart the Ingress Controller

To restart the LoadMaster Ingress Controller, run the restartlmingress command. For example:

/access/restartlmingress

110

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

3.6.8 Legacy WAF Settings

The following commands only work on a LoadMaster with an
WAF-enabled license.

If you have an WAF license and WAF Support, Kemp provides a number of commercial rules, such as
ip_reputation, which can be set to automatically download and update on a daily basis. These
commercial rules are targeted to protect against specific threats. The Kemp-provided commercial
rules are available when signed up to WAF Support.

You can also upload other rules such as the ModSecurity core rule set which contains generic attack
detection rules that provide a base level of protection for any web application.

You can also write and upload your own custom rules if desired.

With the WAF-enabled LoadMaster, you can choose whether to use Kemp-provided rules, custom
rules which can be uploaded or a combination of both. The sections below provide details about
commands that are specific to commercial rules, custom rules and a command which relates to both
types of rule.

3.6.8.1 Commands Relating to Commercial Rule Files

The commands in this section are all related to commercial rule files.

3.6.8.1.1 Display the Commercial WAF Rule Settings

The getwafsettings command displays the values of the WAF options relating to commercial rules
that appear in the WAF Settings screen on the LoadMaster WUI.

https://<LoadMasterIPAddress>/access/getwafsettings

Related WUI Item

Virtual Services > WAF Settings

3.6.8.1.2 Enable Automatic Commercial Rule File Updates

The setwafautoupdate command allows you to enable the automatic downloading of updates to
commercial WAF rule files. When this option is enabled, updated rules are downloaded on a daily
basis from Kemp. The default installation time for these rule updates is 4am. The time at which the
installation of these rule file updates can be set by running the SetWafInstallTime command. For
more information, refer to the Set the Time of the Automatic Commercial Rule File Installation
section.

111

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

You can see what this is currently set to by running the GetWafSettings command. For more
information, refer to the section.

https://<LoadMasterIPAddress>/access/setwafautoupdate?enable=<yes/no>

Related WUI Item

Virtual Services > WAF Settings > Enable Automatic Rule Updates

3.6.8.1.3 Enable/Disable Automatic Installation of Commercial Rule File Updates

Automatic installation of updated commercial rule files can be enabled/disabled by running the
following command.

https://<LoadMasterIPAddress>/access/setwafautoinstall?enable=<yes/no>

Related WUI Item

Virtual Services > WAF Settings > Enable Automated Installs

3.6.8.1.4 Set the Time of the Automatic Commercial Rule File Installation

The time of day of the automatic commercial rule file installation can be set by running the following
command. This relates to the When to Install drop-down menu in the WAF Settings screen in the
WUI.

https://<LoadMasterIPAddress>/access/setwafinstalltime?hour=<hour>

The hour is the hour value from the 24-hour clock (0-23), for example 13 is 1pm:

https://10.11.0.31/access/setwafinstalltime?hour=13

The range is 0-23. Minutes cannot be specified.

Related WUI Item

Virtual Services > WAF Settings > When to Install

3.6.8.1.5 Download WAF Commercial Rule File Updates Now

The WAF commercial rule file updates can be manually downloaded to the LoadMaster by running
the following command. This relates to the Download Now button in the WAF Settings screen in
the WUI.

https://<LoadMasterIPAddress>/access/downloadwafrules

Related WUI Item

Virtual Services > WAF Settings > Download Now

112

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

If there are no updates because the latest rules have already
been downloaded, a message will be displayed which says No
updates available.

3.6.8.1.6 Display the WAF Rule Change Log

A log of the changes which have been made to the Kemp WAF rule set can be downloaded by
running the following command.

https://<LoadMasterIPAddress>/access/getwafchangelog

3.6.8.1.7 Manually Install Commercial Rule Files

The commercial rule files can be manually installed by running the following command. This relates
to the Install Now button in the WAF Settings screen in the WUI.

https://<LoadMasterIPAddress>/access/maninstallwafrules

Related WUI Item

Virtual Services > WAF Settings > Install Now

An error message will be displayed if any problems occur while
installing the rules.

3.6.8.2 Commands Relating to Custom Rule Files

The commands in this section are all related to custom rules.

3.6.8.2.1 Upload a Custom Rule File or Rule Set

An WAF custom rule file can be uploaded by running a cURL command with the addwafcustomrule
command and the filename parameter (required), for example:

curl –X POST --data-binary “@<FileName.conf>” –k
https://bal:<BalPassword>@<LoadMasterIPAddress>/access/addwafcustomrule?filen
ame=<FileName.conf>

In addition to uploading individual custom rule files, you can also upload custom rule sets (.tar.gz
files). An example of uploading the OWASP core rule set is below:

curl –X POST --data-binary “@owasp-modsecurity-crs-master.tar.gz” –k
https://bal:<BalPassword>@<LoadMasterIPAddress>/access/addwafcustomrule?filen
ame= SpiderLabs-owasp-modsecurity-crs-2.2.9-5-gebe8790.tar.gz

This relates to the Custom Rules section in the WAF Settings screen in the LoadMaster WUI.

Related WUI Item

113

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

Virtual Services > WAF Settings > Custom Rules

3.6.8.2.2 Delete a Custom Rule File

A custom rule file can be deleted by running the following command:

https://<LoadMasterIPAddress>/access/delwafcustomrule?filename=<filename>

For example:

https://10.11.0.30/access/delwafcustomrule?filename= modsecurity_crs_10_
ignore_static

This does not delete the associated data file.

Related WUI Item

Virtual Services > WAF Settings > Custom Rules > Delete

3.6.8.2.3 Download a Custom Rule File

A custom rule file can be downloaded to your local machine by running the following command:

https://<LoadMasterIPAddress>/access/downloadwafcustomrule?filename=<filenam
e>

For example:

https://10.11.0.30/access/downloadwafcustomrule?filename=modsecurity_crs_55_
response_profiling

If you run this command using cURL the file will be downloaded to your working directory in Linux.

Related WUI Item

Virtual Services > WAF Settings > Custom Rule Data > Download

3.6.8.2.4 Upload a Custom Rule Data File

A custom rule data file can be uploaded by running a cURL command with the addwafcustomdata
command and the filename parameter (required), for example:

curl –X POST --data-binary “@<FileName.data>” –k
https://bal:<BalPassword>@<LoadMasterIPAddress>/access/addwafcustomdata?filen
ame=<filename.data>
Related WUI Item

Virtual Services > WAF Settings > Custom Rule Data > Add Data File

114

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

3.6.8.2.5 Delete a Custom Rule Data File

A custom rule data file can be deleted by running the following command:

https://<LoadMasterIPAddress>/access/delwafcustomdata?filename=<filename.dat
a>

Related WUI Item

Virtual Services > WAF Settings > Custom Rule Data > Delete

3.6.8.2.6 Download a Custom Rule Data File

A custom rule data file can be downloaded by running the following command:

https://<LoadMasterIPAddress>/access/downloadwafcustomdata?filename=<filenam
e>

For example:

https://10.11.0.30/access/downloadwafcustomdata?filename=modsecurity_35_bad_
robots

Related WUI Item

Virtual Services > WAF Settings > Custom Rule Data > Download

3.6.8.3 Command Relating to Custom and Commercial Rules

The command in this section is related to both commercial and custom rules.

3.6.8.3.1 List WAF Rules

The listwafrules command displays a list of all installed rules (commercial and custom rules).

It also shows if the rules are active or not by displaying either Active or Inactive in the tag name.
Active rules are ones that have been assigned to one or more Virtual Services.

https://<LoadMasterIPAddress>/access/listwafrules

Related WUI Item

Virtual Services > WAF Settings > Custom Rules

Virtual Services > View/Modify Services > Modify > WAF Options > Available Rules

3.6.8.4 Commands Relating to Remote Logging

The commands in this section relates to the WAF remote logging feature which allows the WAF audit
logs to be sent to a central log repository.

115

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

3.6.8.4.1 Set the WAF Logging Format

Set the WAF logging format by using the following command:

https://<LoadMasterIPAddress>/access/setwaflogformat?logformat=<json/native>

3.6.8.4.2 Disable Remote Logging

WAF remote logging can be disabled by running the following command:

https://<LoadMasterIPAddress>/access/disablewafremotelogging

3.6.8.4.3 Enable Remote Logging

WAF remote logging can be enabled by running the following command:

https://<LoadMasterIPAddress>/access/enablewafremotelogging?remoteuri=<Remote
ServerConsoleURI>&username=<RemoteUsername>&passwd=<RemotePassword>

3.6.8.4.4 Save Temporary WAF Remote Log Data

Temporary WAF remote log data can be saved to your local machine by running the following
command:

https://<LoadMasterIPAddress>/access/logging/savemlogcdata

3.6.8.4.5 Clear Temporary WAF Remote Log Data

Temporary WAF remote log data can be cleared by running the following command:

https://<LoadMasterIPAddress>/access/logging/clearmlogcdata

This removes all of the temporary WAF remote log data. This data is created when WAF remote
logging is enabled on the LoadMaster and the remote log server is down or too slow to process the
amount of logs generated. These log files are temporary and get automatically deleted/cleared once
the data/logs have been sent to the remote log server.

3.6.9 WAF Settings

The following commands only work on a LoadMaster with an
WAF-enabled license.

Enable legacy WAF

access/modvs?vs=1&InterceptMode=1

Enable OWASP WAF

access/modvs?vs=1&InterceptMode=2

116

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

The following WAF parameters can be retrieved or configured using the get or set commands:

Name

Type

Default

Range

Description

Intercept

B

0

0 –
Disabled

1 –
Enabled

0 –
Disabled

InterceptMode

B

0

1 – Legacy

2 –
OWASP

InterceptOpts

S

<unset>

OwaspOpts

S

<unset>

Enable/disable the Web
Application Firewall (WAF) for
this Virtual Service.

Enable (in Legacy or OWASP
mode) or disable the Web
Application Firewall (WAF) for
this Virtual Service.

Most of the fields in the WAF
Options (Legacy) section of the
Virtual Service modify screen in
the LoadMaster WUI can be set
using this parameter.

Most of the fields in the WAF
section of the Virtual Service
modify screen in the LoadMaster
WUI can be set using this
parameter.

The paranoia level at which the
OWASP engine blocks the
request coming from the server.

The paranoia level at which the
OWASP engine logs requests
that are coming from the server.
This value should not be lower
than the BlockingParanoia level

BlockingParanoia

ExecutingParanoia

AnomalyScoringThreshold

I

I

i

1

1

1 - 4

1 - 4

100

1 - 10000

Set the Anomaly Scoring
Threshold value. Every detection

117

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

pcrelimit

I

3000

1000 -
99999

JSONDLimit

AlertThreshold

I

I

10000

1000 -
99999

0 -
disabled

0 - 100000

InterceptPOSTOtherContentType
s

S

<unset>

BodyLimit

I

1024 –
52428800

rule in the CRS raises the
anomaly score. If the cumulative
anomaly score per request hits
the configured limit, the request
will be blocked

This setting sets the maximum
iterations that the internal PCRE
engine will use to resolve a
regular expression before failing
a match.

This value sets the maximum
depth that will be accepted
during JSON parsing. Lower
values may cause a valid match
to fail. Higher values may cause
the WAF engine to run slower.

This is the threshold of incidents
per hour before sending an
alert. Setting this to 0 disables
alerting.

When the otherctypesenable
parameter is enabled, use the
InterceptPOSTOtherContentTyp
e s parameter to enter a comma
separated list of POST content
types allowed for WAF analysis,
for example text/plain,text/css.
By default, all types (other than
XML/JSON) are enabled. To set
this to any other content types,
set the value to any.

Set the maximum size of POST
request bodies (in bytes) that
the WAF engine will allow
through. Higher values require
more memory resources and

118

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

may impact WAF engine
performance. The default value
is 1048576 bytes.

When the otherctypesenable
parameter is enabled, use the
POSTOtherContentTypes
parameter to enter a comma
separated list of POST content
types allowed for WAF analysis,
for example text/plain,text/css.
By default, all types (other than
XML/JSON) are enabled. To set
this to any other content types,
set the value to any.

Enables the checking of client
addresses against the IP
reputation database.

In OWASP CRS rulesets are
described by three digit
numbers. Specify the three digit
number of the rulesets you wish
to enable. For example:
RuleSets=911, 913, 920….

Specify a list of workloads that
the customer is running. By
default, some workloads cause a
lot of false positives, if someone
is running one of workloads
(drupal, wordpress, nextcloud,
dokuwiki, cpanel, xenforo), add
its name to the list will stop
certain checks that are known to
cause problems.

Enter the two letter country
codes that are to be blocked.

PostOtherContentTypes

S

IPReputationBlocking

B

0

0 –
Disabled

1 –
Enabled

RuleSets

ExcludedWorkLoads

BlockedCountries

S

S

S

119

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

AuditParts

S

ABEFHKZ

CustomRules

DisabledRules

Enter a valid string which
contains the sections that are to
be put in the wafaudit log for
each request. Currently, only
four values B, E, F, H are
enabled.

Specify a list of custom rules
that are to be configured for the
Virtual Service.

Specify a list of disabled rules.

3.6.9.1 OWASP Custom Rulesets

To add a new custom rule file, run the addowaspcustomrule command. For example:

/access/addowaspcustomrule?filename=owasp-cus.conf

To delete an existing rule file, run the delowaspcustomrule command. For example:

/access/delowaspcustomrule?filename=owasp-cus

To download a custom rule file, run the downloadowaspcustomrule command. For example:

/access/downloadowaspcustomrule?filename=<filename>

The filename parameter is mandatory. Specify the name of the OWASP custom rule file to download
in the filename parameter. You can get the filename by going to Web Application Firewall >
Custom Rules in the WUI. If you run the command using a web browser, the file will download to
the location specified in your browser settings.

3.6.9.2 OWASP Custom Data File

To add a custom data file, run the addowaspcustomdata command. For example:

/access/addowaspcustomdata?filename=owasp-cust.data

To delete an existing data file, run the delowaspcustomdata command. For example:

/access/delowaspcustomdata?filename=owasp-cust

To download a custom data file, run the downloadowaspcustomdata command. For example:

/access/downloadowaspcustomdata?filename=<filename>

120

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

The filename parameter is mandatory. Specify the name and extension (either .txt or .data) of the
OWASP custom data file to download in the filename parameter. You can get the filename by going
to Web Application Firewall > Custom Rules in the WUI. If you run the command using a web
browser, the file will download to the location specified in your browser settings.

3.6.9.3 OWASP Rules

To list all available OWASP rules, run the owasprules command. For example:

/access/owasprules

To show all OWASP rules and their enablement state for a Virtual Service, run the
owasprules?vs=<VSIndex> command. For example:

/access/owasprules?vs=1

To show an OWASP rule and its enablement state for a Virtual Service, run the
owasprules?vs=<VSIndex>&rule=<RuleId> command. For example:

/access/owasprules?vs=1&rule=911100

To get the rule ID of a OWASP rule, check the user interface
(Virtual Services > View/Modify Services > Modify > WAF >
Manage Rules and expand the relevant rule section to see the
associated rule ids) or run the owasprules command. You can
also specify a prefix, such as 913 for the scanner-detection
rules, to enable/disable/view all rules that contain that prefix in
their ID. For more information on the OWASP rules including a
list of IDs for each ruleset and rule, refer to the OWASP
Standard Rules Technical Note.

To turn off all OWASP rules for a particular ruleset of a Virtual Service, run the
owasprules?vs=<VSIndex>&rule=<RuleId>&enable=<yes/no> command. For example:

/access/owasprules?vs=1&rule=911100&enable=no

To filter the list of rules, run the owasprules?vs=<VSIndex>&filter=<term>&enable=<yes/no>
command. For example, to filter the list of OWASP rules that contain the value SQL:

/access/owasprules?vs=1&filter=sql&enable=yes

To enable/disable all rules for a Virtual Service, run the
owasprules?vs=<VSIndex>&enable=<yes/no> command. For example:

/access/owasprules?vs=1&enable=yes

121

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

3.7 Global Balancing

3.7.1 Manage Fully Qualified Domain Names (FQDNs)

3.7.1.1 Add FQDN

An FQDN can be added by running the following command:

https://<LoadMasterIPAddress>/access/addfqdn?fqdn=<FQDNName>

fqdn is a required parameter for this command.

3.7.1.2 Delete FQDN

An FQDN can be deleted by running the following command:

https://<LoadMasterIPAddress>/access/delfqdn?fqdn=<FQDNName>

fqdn is a required parameter for this command.

3.7.1.3 List FQDNs

The existing FQDNs can be listed by running the following command:

https://<LoadMasterIPAddress>/access/listfqdns

Example output for the listfqdns command is provided below:

<Response stat="200" code="ok">

<Success><Data><fqdn><FullyQualifiedDomainName>www.example.com.</FullyQualifiedDomainN
ame>

<SelectionCriteria>rr</SelectionCriteria>

<FailTime>0</FailTime>

<SiteRecoveryMode>auto</SiteRecoveryMode>

<Mapping>1</Mapping>

<failover>N</failover>

<publicRequestValue>3</publicRequestValue>

<privateRequestValue>3</privateRequestValue>

<LocalSettings>0</LocalSettings>

<UnanimousChecks>N</UnanimousChecks>

<Map><Status>Up</Status>

<Index>1</Index>

<IPAddress>172.16.193.50</IPAddress>

<Cluster>LocalLM</Cluster>

122

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

<Checker>clust</Checker>

<CheckerPort>0</CheckerPort>

<Weight>1000</Weight>

<MappedAddress>172.16.193.50</MappedAddress>

<MappedPort>80</MappedPort>

<MappedName>HTTP VS</MappedName>

<Enable>Y</Enable>

</Map></fqdn><fqdn><FullyQualifiedDomainName>www.example.com.</FullyQualifiedDomainNam
e>

<SelectionCriteria>rr</SelectionCriteria>

<FailTime>0</FailTime>

<SiteRecoveryMode>auto</SiteRecoveryMode>

<Mapping>3</Mapping>

<failover>N</failover>

<publicRequestValue>0</publicRequestValue>

<privateRequestValue>0</privateRequestValue>

<LocalSettings>0</LocalSettings>

<UnanimousChecks>N</UnanimousChecks>

<Map><Status>Down</Status>

<Index>3</Index>

<IPAddress>1.1.1.1</IPAddress>

<Cluster>RemoteLM</Cluster>

<Checker>clust</Checker>

<CheckerPort>0</CheckerPort>

<Weight>1000</Weight>

<MappedAddress>172.16.193.254</MappedAddress>

<MappedPort>80</MappedPort>

<MappedName>HTTP VS</MappedName>

<Enable>Y</Enable>

</Map></fqdn></Data>

</Success>

</Response>

3.7.1.4 Show FQDN

The showfqdn command displays various details relating to the specified FQDN:

https://<LoadMasterIPAddress>/access/showfqdn?fqdn=<FQDNName>

Example output for the showfqdn command is provided below:

123

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

<Response stat="200" code="ok">

<Success>

<Data>

<fqdn>

<Status>Up</Status>

<FullyQualifiedDomainName>www.example.com.</FullyQualifiedDomainName>

<SelectionCriteria>rr</SelectionCriteria>

<FailTime>0</FailTime>

<SiteRecoveryMode>auto</SiteRecoveryMode>

<Mapping>1</Mapping>

<failover>N</failover>

<publicRequestValue>3</publicRequestValue>

<privateRequestValue>3</privateRequestValue>

<LocalSettings>0</LocalSettings>

<UnanimousChecks>N</UnanimousChecks>

<Map><Status>Up</Status>

<Index>1</Index>

<IPAddress>172.16.193.50</IPAddress>

<Cluster>LocalLM</Cluster>

<Checker>clust</Checker>

<CheckerPort>0</CheckerPort>

<Weight>1000</Weight>

<MappedAddress>172.16.193.50</MappedAddress>

<MappedPort>80</MappedPort>

<MappedName>HTTP VS</MappedName>

<Enable>Y</Enable>

</Map></fqdn></Data>

</Success>

</Response>

3.7.1.5 Modify FQDN

An existing FQDN can be modified by running the following command:

https://<LoadMasterIPAddress>/access/modfqdn?fqdn=<FQDNName>

The modfqdn command accepts the following optional parameters:

124

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

Name

Type

Default

Range

Additional Information

rr = round
robin

wrr =
weighted
round robin

fw = fixed
weighting

rsr = real
server load

prx =
proximity

lb =
location
based

all = all
available

0-1440
(minutes)

auto –
automatic

manual -
manual

The selection criteria for addresses
associated with the FQDN. For a
description of each of these options,
refer to the GEO, Feature Description
on the Kemp Documentation Page.

If a failure delay is not set, normal
health checking is performed. If set,
this parameter defines the number of
minutes to wait after a failure before
finally disabling it. Once it is disabled,
it will not normally be brought back
into operation.

This parameter defines the Site
Recovery Mode.

If this is set to automatic, upon site
recovery the site is brought back into
operation immediately.

If this is set to manual, once the site
has failed, the site is disabled. Manual
intervention is required to restore

SelectionCriteria

S

rr

FailTime

I

0

siterecoverymode

S

auto

125

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

failover

B

0 – disabled

publicRequestValue

I

0 – Public
Sites Only

privateRequestValue

I

0 – Private
Sites Only

LocalSettings

B

0 – Disabled

localttl

I

Defaults to
the value of
the global
ttl value
when an
FQDN is
created.

0 –
Disabled

1 – Enabled

0 – Public
Sites Only

1 – Prefer
Public Sites

2 – Prefer
Private
Sites

3- Any Sites

0 – Private
Sites Only

1 – Prefer
Private
Sites

2 – Prefer
Public Sites

3 – Any
Sites

0 –
Disabled

1 – Enabled

1 to 86400

normal operation.

This parameter is only relevant if the
SelectionCriteria is set to lb (Location
Based).

Enable/disable FQDN failover.

Restrict responses to clients from
public IP addresses to specific classes
of site. For an explanation of the
different settings and their values
please see the section Public Requests
& Private Requests below including
the table

Restrict responses to clients from
private IP addresses to specific classes
of site. For an explanation of the
different settings and their values
please see the section Public Requests
& Private Requests below including
the table

Enabling this parameter provides two
additional parameters for the FQDN –
localttl and localsticky.

The Time To Live (TTL) value dictates
how long the reply from the GEO
LoadMaster can be cached by other
DNS servers or client devices. The time
interval is defined in seconds. This
value should be as practically low as
possible. The default value for this field

126

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

localsticky

I

is 10.

Defaults to
the value of
the global
persist
value when
an FQDN is
created.

0 to 86400

Stickiness, also known as persistence,
is the property that enables all name
resolution requests from an individual
client to be sent to the same resources
until a specified period of time has
elapsed.

unanimouschecks

B

0 – Disabled

0 –
Disabled

1 – Enabled

When this parameter is enabled, if any
IP addresses fail health checking - the
other FQDN IP addresses which belong
to the same cluster will be forced
down.

Public Requests & Private Requests

The Public Requests & Private Requests options replace the old Isolate Public/Private Sites option
which was available on LoadMasters with firmware up to and including 7.1-28. The new settings offer
administrators greater flexibility when configuring an FQDN.

These new settings allow administrators to selectively respond with public or private sites based on
whether the client is from a public or private IP. For example, administrators may wish to allow only
private clients to be sent to private sites.

The following table outlines settings and their configurable values:

Setting

Value

Client Type

Site Types Allowed

Public Only

Public

Public

PublicRequests

Prefer Public

Public

Public, Private if no public

Prefer Private

Public

Private, Public if no private

All Sites

Public

Private and Public

Private Only

Private

Private

Private Requests

Prefer Private

Private

Private, Public if no private

Prefer Public

Private

Public, Private if no public

All Sites

Private

Private and Public

127

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

3.7.1.6 Add Map

A map can be added to the FQDN by running the following command:

https://<LoadMasterIPAddress>/access/addmap?fqdn=<FQDNName>&ip=<IPAddressToAd
d>&clust=<ClusterName>

The clust parameter is optional.

In LoadMaster firmware versions prior to 7.2.577.2.50, there is
an entry limit of 6416 IP addresses per FQDN. If you attempt to
add more than this, you get an error message saying Too many
IP addresses already specified.

The entry limit was increased to 256 IP addresses in LoadMaster
firmware version 7.2.57. It is recommended that the LoadMaster
should have 8GB memory space to configure the 256 IP
addresses per FQDN.

3.7.1.7 Modify a Map

To modify a map, run the following command:

https://<LoadMasterIPAddress>/access/modmap?fqdn=<FQDNName>&ip=<IPAddressToMo
dify>

The modmap command accepts the following optional parameters:

Name

Type

Default

Range

Additional Information

Checker

S

icmp

none

icmp

tcp

clust

http

https

Specify the type of checking to be done on
this IP address

checkerurl

S

/

Maximum
of 127
characters

By default, the health checker tries to
access the URL forward slash (/) to
determine if the machine is available. You
can specify a different URL using the

128

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

300-599

checkercodes

checkerhost

S

S

checkerurl parameter. The URL must
begin with a forward slash (/). The URL
cannot contain http: or https:. The URL
can be a maximum of 127 characters.

A space-separated list of HTTP status
codes that should be treated as successful
when received from the server. There is a
maximum of 32 codes. There is a limit of
127 characters.

A hostname can be supplied in the request
to the server. If this is not set, the server
address is sent as the host. There is a limit
of 127 characters. Allowed characters:
alphanumerics and -._:

checkerhttpmethod

S

get

1 - GET

2 - POST

When accessing the health check URL, the
system can use either the GET or the
POST method. If POST is selected, the
checkerpostdata parameter is also valid.

checkerpostdata

S

Weight

I

1000

1-65535

Up to 2047 characters of POST data can be
passed to the server. This parameter is
only relevant if the checkerhttpmethod
parameter is set to 2 (POST).

Specify the weight associated with the IP
address. The address with the highest
weight is returned. This is only relevant if
the Selection Criteria for the FQDN is set
to Weighted Round Robin or Fixed
Weighting.

Enable

Cluster

MapAddress

B

I

A

1 –
Enabled

1 – Enable

0 – Disable

Enable or disable the IP address.

<unset>

<unset>

Specify the ID number of the cluster to
associate with the IP address.

This is only relevant when the Selection
Criteria is set to Real Server Load, the

129

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

MapPort

I

<unset>

Checker is set to Cluster Checks and the
cluster is of type Remote LM or Local LM.

Enter a Virtual Service IP address to be
mapped from the relevant LoadMaster.

This is only relevant when the Selection
Criteria is set to Real Server Load, the
Checker is set to Cluster Checks and the
cluster is of type Remote LM or Local LM.

This parameter is used in conjunction with
the MapAddress parameter to specify an
IP address and port combination to be
mapped.

If this parameter is not set, the health
check will check all Virtual Services with
the same IP address as the one selected. If
one of them is in an “Up” status, the FQDN
will show as “Up”. If a port is specified, the
health check will only check against the
health of that Virtual Service when
checking the health of the FQDN.

The maximum length of an API call is 1024 characters. If you
want to make a larger call, use the POST method.

To delete a health check, set the checker parameter to none. For example:

/access/modmap?fqdn=<FQDN>&ip=<IPAddress>&checker=none

3.7.1.8 Delete a Map

To delete a map, run the following command:

https://<LoadMasterIPAddress>/access/delmap?fqdn=<FQDNName>&ip=<IPAddressToDe
lete>

3.7.1.9 Change the Location of a Map

To change the location of a map, run the following command:

https://<LoadMasterIPAddress>/access/changemaploc?fqdn=<FQDNName>&ip=<IPaddre
ss>&lat=<LatitudeSeconds>&long=<LongituteSeconds>

130

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

This command is only relevant when the Selection Criteria for
the FQDN is set to Proximity.

The lat and long values should be entered as an integer containing the total seconds. This total
seconds value is converted to degrees, minutes and seconds when displayed in the WUI.

There are 60 seconds in a minute and 60 minutes in a degree.

Degrees = º

Minutes = ‘

Seconds = “

60” = 1’

3600” = 1º

3660 = 1º1’

3661 = 1º1’1”

You can also represent this as a decimal value for degrees where the minutes and seconds are
divided by 3600 to get the decimal value.

3.7.1.10 Add a Location

To add a country or continent, run the following command:

https://<LoadMasterIPAddress>/access/addcountry?fqdn=<FQDNName>&ip=<IPAddress
>&countrycode=<TwoCharacterCountry/ContinentCode>&iscontinent=<yes/no>

This command is only relevant when the Selection Criteria for
the FQDN is set to Location Based. Refer to the Modify FQDN
section for details on how to modify the Selection Criteria.

The FQDN name is case sensitive.

The country code and continent codes used are the standard
ISO codes.

When adding a country - the iscontinent parameter must be set
to no.

131

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

When adding a continent - the iscontinent parameter must be
set to yes.

The value for countrycode should be in uppercase.

To specify everywhere as the country, type ALL as the country
code and set the iscontinent parameter to yes.

To add a custom location, run the following command:

https://<LoadMasterIPAddress>/access/addcountry?fqdn=<FQDNName>&ip=<IPAddress
>&customlocation=<CustomLocationName>

It is also possible to add a country/continent and a custom location in the one command – simply
include all of the parameters, for example:

https://<LoadMasterIPAddress>/access/addcountry?fqdn=<FQDNName>&ip=<IPAddress
>&countrycode=<TwoCharacterCountry/ContinentCode>&iscontinent=<yes/no>&custom
location=<CustomLocationName>

3.7.1.11 Remove a Location

To remove a country, run the following command:

https://<LoadMasterIPAddress>/access/removecountry?fqdn=<FQDNName>&ip=<IPAddr
ess>&countrycode=<TwoCharacterCountry/ContinentCode>&iscontinent=<yes/no>

This command is only relevant when the Selection Criteria for
the FQDN is set to Location Based.

The FQDN name is case sensitive.

When removing a country - the iscontinent parameter must be
set to no.

When removing a continent - the iscontinent parameter must
be set to yes.

The value for countrycode should be in uppercase.

To specify everywhere as the country, type ALL as the country
code and set the iscontinent parameter to yes.

To remove a custom location, run the following command:

132

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

https://<LoadMasterIPAddress>/access/removecountry?fqdn=<FQDNName>&ip=<IPAddr
ess>&customlocation=<CustomLocationName>

It is also possible to remove a country/continent and a custom location in the one command –
simply include all of the parameters, for example:

https://<LoadMasterIPAddress>/access/removecountry?fqdn=<FQDNName>&ip=<IPAddr
ess>&countrycode=<TwoCharacterCountry/ContinentCode>&iscontinent=<yes/no>&cus
tomlocation=<CustomLocationName>

3.7.1.12 Change Checker Address

To change the address of a checker, run the following command:

https://<LoadMasterIPAddress>/access/changecheckeraddr?fqdn=<FQDNName>&ip=<Ma
pIPAddress>&checkerip=<CheckerIPAddress>&port=<CheckPort>

The changecheckeraddr command requires the following parameters:

Name

Type

Default

Range

Additional Information

checkerip

port

S

I

<unset>

Specify the address used to health check the IP address.

80

1-65530

Specify the port used to health check the IP address.

Specifying an empty value for the the checkerip or port parameters sets them to their default
values (blank for the checkerip and 80 for the port).

3.7.1.13 Additional Records

You can add a new TXT, CNAME and MX record to an FQDN by running the addrr command. For
example:

/access/addrr?fqdn=<FQDNName>&type=txt&rdata=<ResourceRecordData>

/access/addrr?fqdn=<FQDNName>&type=cname&name=<Name>

/access/addrr?fqdn=<FQDNName>&type=mx&rdata=<ResourceRecordData>

You can modify an existing TXT, CNAME and MX record by running the modrr command. For
example:

/access/modrr?fqdn=<FQDNName>&type=txt&param=rdata&value=<UpdatedResourceRecordD
ata>&id=<IndexOfRecord>

/access/modrr?fqdn=<FQDNName>&type=cname&param=name&value=<UpdatedName>&id=<I
ndexOfRecord>

133

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

/access/modrr?fqdn=Example.com&type=mx&id=<IndexOfRecord>&param=<rdata/priority>&v
alue=<Value>

When modifying an MX record, you can specify either the rdata
or priority as the param, depending on what parameter you
want to modify the value for.

You can delete an existing TXT, CNAME and MX record by running the dellrr command. For example:

/access/delrr?fqdn=<FQDNName>&id=<Index>

To retrieve the Index number of an existing record, run the
showfqdn command.

3.7.2 Manage Clusters

3.7.2.1 List Clusters

Existing clusters can be listed by running the following command:

https://<LoadMasterIPAddress>/access/listclusters

3.7.2.2 Show Cluster

Details about a specific cluster can be displayed by running the following command:

https://<LoadMasterIPAddress>/access/showcluster?id=<ClusterID>

id is a required parameter for this command.

The Address entry is deprecated.

3.7.2.3 Add Cluster

A cluster can be added by running the following command:

https://<LoadMasterIPAddress>/access/addcluster?ip=<ClusterIPAddress>&name=<C
lusterName>

The ip and name parameters are required for this command.

3.7.2.4 Delete Cluster

A cluster can be deleted by running the following command:

https://<LoadMasterIPAddress>/access/delcluster?ip=<ClusterIPAddress>

134

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

The ip parameter is required for this command.

3.7.2.5 Modify Cluster

A cluster can be modified by running the following command:

https://<LoadMasterIPAddress>/access/modcluster?id=<ClusterID>

The modcluster commands accepts the following optional parameters:

Name

Type

Default

Range

Additional Information

default

Default

remoteLM

Change the type of the cluster

type

name

checker

S

S

S

localLM

none

tcp

icmp

none

checkerport

I

0

1-65530

enable

B

1 –
Enabled

1 = Enabled

0 =
Disabled

Specify a name for the cluster

Specify the method used to check the status of the
cluster

Set the port used for checking the cluster. This
parameter is only relevant if the checker is set to
tcp.

Enable/disable the cluster

3.7.2.6 Change Cluster Location

To change a cluster location, run the following command:

https://<LoadMasterIPAddress>/access/clustchangeloc?ip=<ClusterIPAddress>&lat
secs=<LatitudeSeconds>&longsecs=<LongitudeSeconds>

The latsecs and longsecs values should be entered as an integer containing the total seconds. This
total seconds value is converted to degrees, minutes and seconds when displayed in the WUI.

There are 60 seconds in a minute and 60 minutes in a degree.

Degrees = º

Minutes = ‘

135

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

Seconds = “

60” = 1’

3600” = 1º

3660 = 1º1’

3661 = 1º1’1”

You can also represent this as a decimal value for degrees where the minutes and seconds are
divided by 3600 to get the decimal value.

3.7.3 Miscellaneous Params

3.7.3.1 List the Miscellaneous Parameters

To list the GEO miscellaneous parameters, run the following command:

https://<LoadMasterIPAddress>/access/listparams

3.7.3.2 Modify Miscellaneous Parameters

The GEO miscellaneous parameters can be modified by running the following command:

https://<LoadMasterIPAddress>/access/modparams

The modparams command accepts the following optional parameters:

Name

zone

Type

Default

Range

Additional Information

S

<unset>

Specify the zone name.

PerZoneSOA

B

0 -
Disabled

SourceOfAuthority

namesrv

SOAEmail

S

S

S

<unset>

<unset>

<unset>

0 -
Disabled

1 -
Enabled

If this option is enabled, the Source of
Authority (SOA) parameters are applied only
to the zone. If it is disabled, the SOA
parameters apply to all Fully Qualified
Domain Names (FQDNs). The Apply to Zone
Only option is disabled by default.

Set the response set for Source of Authority
requests.

Set the response sent for Name Server
requests.

Email address of the person responsible for
the zone and to which email may be sent to

136

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

report errors or problems. This is the email
address of a suitable DNS administrator but
more commonly the technical contact for the
domain.

By convention (in RFC 2142) it is suggested
that the reserved mailbox hostmaster is used
for this purpose but any valid email address
will work.

The format is
<MailboxName>.<Domain>.com, for
example, hostmaster.example.com (uses a
full stop (.) rather than the usual @ symbol
because the @ symbol has other uses in the
zone file) but mail is sent to
hostmaster@example.com.

dclustunavail

B

glueip

TTL

Txt

EDNSECS

S

I

S

B

0 -
Disabled

1 -
Enabled

This option is disabled by default. When this
option is enabled, requests to the cluster are
dropped if a GEO cluster is disabled.

This option allows you to set the IP address
of the name server to return in additional
records in a DNS response. To unset the Glue
Record IP so that 0.0.0.0 is returned, set the
glueip parameter to an empty string.

<unset>

1-86400

Set the Time To Live (TTL) (in seconds) of the
responses returned by the LoadMaster.

This option allows you to modify the TXT
record.

0 -
Disabled

1 -
Enabled

The EDNS Client Subnet (ECS) option is
enabled by default on new installations but if
you are upgrading a LoadMaster that
previously used GEO functionality then the
option is disabled. When enabled, the ECS

137

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

persist

CheckInterval

ConnTimeout

RetryAttempts

I

I

I

I

0

0-86400

120

9-3600

20

2

4-60

2-10

field (if included in the request) is used to
determine the client location. When disabled,
this field is ignored.

This corresponds with the Stickiness WUI
field. This determines how long (in seconds)
a specific response will be returned to a host.

Set how often (in seconds) that devices will
be checked.

Note: The interval value must be greater
than the ConnTimeout value multiplied by
the RetryAttempts value (Interval > Timeout
* Retry + 1). This is to ensure that the next
health check does not start before the
previous one completes. If the timeout or
retry values are increased to a value that
breaks this rule, the interval value will be
automatically increased.

Set the timeout (in seconds) for the check
request.

Set the number of times the check will be
retried before the device is marked as failed.

The timeline diagram below illustrates what happens from the time a resource IP is added or
enabled, to when it goes down and then comes back up again:

When a resource IP is enabled/created, an ICMP request is sent by the LoadMaster to the resource IP.
Assuming it responds, the resource is marked UP.

After 120 seconds has elapsed (the default Check Interval), an ICMP request is sent to the resource
IP. If 20 seconds (the default Connection Timeout) elapses and the IP fails to respond, the
LoadMaster will send up to two additional requests (the default Retry Attempts) and wait for 20
seconds between each. If all three of these requests receive no response, then the resource is
marked down, and the Check Interval timer is reset.

After 120 seconds elapses, the LoadMaster attempts to send an ICMP request to the resource IP. If
the resource has now come back up and responds before the Connection Timeout elapses, the
LoadMaster marks it UP and resets the Check Interval timer.

138

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

3.7.3.3 Upload a Location Data Patch File

A location data update file can be uploaded. To do this, run a cURL command:

curl –X POST --data-binary “@<GEOPatchFileName>” -k
https://<username>:<password>@<LoadMasterIPAddress>/access/locdataupdate

3.7.4 IP Range Selection Criteria

3.7.4.1 List the IP Addresses

To list the IP addresses set for the IP range selection criteria, run the following command:

https://<LoadMasterIPAddress>/access/listips

3.7.4.2 Show IP Address Details

To show details of a specific IP address which is set for the IP range selection criteria, run the
following command:

https://<LoadMasterIPAddress>/access/showip?ip=<IPAddress>

3.7.4.3 Add IP Address

To add an IP address to the IP range selection criteria, run the following command:

https://<LoadMasterIPAddress>/access/addip?ip=<IPAddress>

3.7.4.4 Delete IP Address

To delete an IP address from the IP range selection criteria, run the following command:

https://<LoadMasterIPAddress>/access/delip?ip=<IPAddress>

139

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

3.7.4.5 Change the Location for an IP Address

To change the location for an IP address, run the following command:

https://<LoadMasterIPAddress>/access/modiploc?ip=<IPAddress>&lat=<LatitudeMin
utes>&long=<LongitudeMinutes>

The lat and long values should be entered as an integer containing the total seconds. This total
seconds value is converted to degrees, minutes and seconds when displayed in the WUI.

There are 60 seconds in a minute and 60 minutes in a degree.

Degrees = º

Minutes = ‘

Seconds = “

60” = 1’

3600” = 1º

3660 = 1º1’

3661 = 1º1’1”

You can also represent this as a decimal value for degrees where the minutes and seconds are
divided by 3600 to get the decimal value.

3.7.4.6 Delete IP Location

To delete the location for an IP address, run the following command:

https://<LoadMasterIPAddress>/access/deliploc?ip=<IPAddress>

3.7.4.7 Add IP Country

To add a country association to an existing IP address, run the following command:

https://<LoadMasterIPAddress>/access/addipcountry?ip=<IPAddress>&<param>=<val
ue>

Name

Mandatory

Type

Default

Range

Additional Information

countrycode

No

customloc

No

S

S

<unset>

Valid country
code

A valid, uppercase, two-digit
country code must be used.

<unset>

Existing
custom
location

The name of an existing custom
location.

140

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

Either the countrycode or customloc parameter must be
entered when running the command.

3.7.4.8 Remove IP Country

To remove the country association from an IP address, run the following command:

https://<LoadMasterIPAddress>/access/removeipcountry?ip=<IPAddress>

3.7.4.9 List the Custom Locations

To list the existing custom locations, run the following command:

https://<LoadMasterIPAddress>/access/listcustomlocation

3.7.4.10 Add a Custom Location

A custom location can be added by running the following command:

https://<LoadMasterIPAddress>/access/addcustomlocation?location=<CustomLocati
onName>

The location parameter is required.

3.7.4.11 Edit a Custom Location

To rename an existing custom location, run the following command:

https://<LoadMasterIPAddress>/access/editcustomlocation?cloldname=<OldCustomL
ocationName>&clnewname=<NewCustomLocationName>

3.7.4.12 Delete a Custom Location

To remove an existing custom location, run the deletecustomlocation command, using the
following format:

https://<LoadMasterIPAddress>/access/deletecustomlocation?clName=<CustomLocat
ionName>

3.7.5 IP Access List Settings

Refer to the subsections below for details on the RESTful API commands relating to the IP access-list
settings.

3.7.5.1 Retrieve the IP Access List Settings

To retrieve the IP access-list settings, run the following command:

https://<LoadMasterIPAddress>/access/geoacl/getsettings

141

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

3.7.5.2 Enable/Disable Automatic IP Access List Updates

To enable/disable automatic updates, run the following command:

https://<LoadMasterIPAddress>/access/geoacl/setautoupdate?enable=<1/0>

3.7.5.3 Enable/Disable Automatic Installation of the IP Access List Updates

To enable/disable automatic installation of the updates, run the following command:

https://<LoadMasterIPAddress>/access/geoacl/setautoinstall?enable=<1/0>

3.7.5.4 Set the Time of the Automatic Installation

To set the time of the automatic installation, run the following command:

https://<LoadMasterIPAddress>/access/geoacl/setinstalltime?hour=<hour>

The hour is the hour value from the 24-hour clock (0-23), for example 13 is 1pm:

https://10.11.0.31/access/geoacl/setinstalltime?hour=13

The range is 0-23. Minutes cannot be specified. It is not possible to set the install time if automatic
installation is disabled.

3.7.5.5 Download the Updates Now

To download the updates now, run the following command:

https://<LoadMasterIPAddress>/access/geoacl/updatenow

3.7.5.6 Install the Updates Now

To install any downloaded updates now, run the following command:

https://<LoadMasterIPAddress>/access/geoacl/installnow

3.7.5.7 View the Access List

To retrieve the access-list, run the following command:

https://<LoadMasterIPAddress>/access/geoacl/downloadlist

3.7.5.8 View Changes to the Access List

To retrieve a list of changes which were made to the access-list, run the following command:

https://<LoadMasterIPAddress>/access/geoacl/downloadchanges

3.7.5.9 View the User-Defined Allow List

To retrieve the contents of the user-defined allow list (which overrides the access-list), run the
following command:

https://<LoadMasterIPAddress>/access/geoacl/listcustom

142

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

3.7.5.10 Add an Address to the Allow List

To add an IP address or network (in CIDR format) to the allow list, run the following command:

https://<LoadMasterIPAddress>/access/geoacl/addcustom?addr=<Address>

3.7.5.11 Remove an IP Address or Network from the Allow List

To remove an IP address or network from the allow list, run the following command:

https://<LoadMasterIPAddress>/access/geoacl/removecustom?addr=<Address>

3.7.6 Configure DNSSEC

To configure DNSSEC using the API, use the commands outlined in the below sections.

3.7.6.1 Generate the Key Signing Keys (KSKs)

To generate the KSKs, run the following command:

https://<LoadMasterIPAddress>/access/geogenerateksk?algorithm=<Algorithm>&key
size=<KeySize>

Name

Type

Default

Range

Description

algorithm

S

RSASHA256

RSASHA256,
NSEC3RSASHA1,
NSEC3RSASHA1

Specify the cryptographic algorithm to
use. If this parameter is omitted, the
default value is used.

keysize

I

2048

1024, 2048, 4096

Specify the key size (in bits). If this
parameter is omitted, the default value is
used.

3.7.6.2 Import the KSKs

To import the KSKs, run the following cURL command:

curl -F "publickey=@/tmp/example.com.+008+62284.key" -F
"privatekey=@/tmp/example.com.+008+62284.private" -k
https://<Username>:<Password>@<LoadMasterIPAddress>/access/geoimportksk

This command uploads both KSK files at the same time.

3.7.6.3 Delete the KSK Files

To delete the KSK files, run the following command:

https://<LoadMasterIPAddress>/access/geodeleteksk

3.7.6.4 Enable/Disable DNSSEC

To enable/disable DNSSEC, run the following command:

143

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

https://<LoadMasterIPAddress>/access/geosetdnssec?enable=<yes/no>

3.7.6.5 Retrieve the DNSSEC Configuration Settings

To retrieve the DNSSEC settings, run the following command:

https://<LoadMasterIPAddress>/access/geoshowdnssec

3.7.7 GSLB Statistics

To retrieve the Global Server Load Balancing (GSLB) statistics, run the following command:

https://<LoadMasterIPAddress>/access/geostats

3.7.8 Enable/Disable GEO

3.7.8.1 Check if GEO is Enabled

To check if GEO is enabled, run the following command:

https://<LoadMasterIPAddress>/access/isgeoenabled

3.7.8.2 Enable GEO

GEO can be enabled by running the following command:

https://<LoadMasterIPAddress>/access/enablegeo

3.7.8.3 Disable GEO

GEO can be disabled by running the following command:

https://<LoadMasterIPAddress>/access/disablegeo

3.8 Statistics

Statistics for all the Virtual Services and Real Servers can be obtained by using the stats command.

If you run the stats command on the admin node when using
LoadMaster clustering – the output will show the combined
totals of all machines.

https://<LoadMasterIPAddress>/access/stats

If the command executes without error, the statistics for all the Virtual Services and Real Servers are
returned in the following format.

The Real Server statistics are returned on a per Virtual Service
basis.

<Response stat="200" code="ok">

144

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

<Success>

<Data>

<CPU>

<total>

<User>0</User>

<System>1</System>

<Idle>99</Idle>

<IOWaiting>0</IOWaiting>

</total>

<cpu0>

<User>0</User>

<System>0</System>

<HWInterrupts>0</HWInterrupts>

<SWInterrupts>0</SWInterrupts>

<Idle>99</Idle>

<IOWaiting>0</IOWaiting>

</cpu0>

<cpu1>

<User>1</User>

<System>0</System>

<HWInterrupts>0</HWInterrupts>

<SWInterrupts>0</SWInterrupts>

<Idle>99</Idle>

<IOWaiting>0</IOWaiting>

</cpu1>

</CPU>

<Memory>

<MBtotal>2003</MBtotal>

<memused>312140</memused>

<MBused>304</MBused>

<percentmemused>15</percentmemused>

<memfree>1739060</memfree>

<MBfree>1698</MBfree>

<percentmemfree>85</percentmemfree>

</Memory>

<Network>

<eth0>

145

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

<ifaceID>0</ifaceID>

<speed>10000</speed>

<in>0.0</in>

<inbytes>149</inbytes>

<inbytesTotal>1511851</inbytesTotal>

<out>0.0</out>

<outbytes>122</outbytes>

<outbytesTotal>5702883</outbytesTotal>

</eth0>

<bnd2>

<ifaceID>2</ifaceID>

<speed>1000</speed>

<in>0.0</in>

<inbytes>0</inbytes>

<inbytesTotal>3960</inbytesTotal>

<out>0.0</out>

<outbytes>0</outbytes>

<outbytesTotal>38396</outbytesTotal>

</bnd2>

</Network>

<DiskUsage>

<partition>

<name>/var/log</name>

<GBtotal>7.19</GBtotal>

<GBused>0.02</GBused>

<percentused>0</percentused>

<GBfree>7.17</GBfree>

<percentfree>100</percentfree>

</partition>

<partition>

<name>/var/log/userlog</name>

<GBtotal>7.68</GBtotal>

<GBused>0.02</GBused>

<percentused>0</percentused>

<GBfree>7.67</GBfree>

<percentfree>100</percentfree>

</partition>

146

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

</DiskUsage>

<ClientLimits>

<Totals>

<CurrentConnections>0</CurrentConnections>

<CurrentConnectionsBlocked>0</CurrentConnectionsBlocked>

<SuccessfulConnectionAttempts>0</SuccessfulConnectionAttempts>

<SuccessfulRequestAttempts>0</SuccessfulRequestAttempts>

<SuccessfulMatchedRuleAttempts>0</SuccessfulMatchedRuleAttempts>

<ConnectionAttemptsBlocked>0</ConnectionAttemptsBlocked>

<RequestAttemptsBlocked>0</RequestAttemptsBlocked>

<MatchedRulesBlocked>0</MatchedRulesBlocked>

</Totals>

<glbcps> </glbcps>

<glbrps> </glbrps>

</ClientLimits>

<CountryCounts>

<DifferentCountries>0</DifferentCountries>

<Total> </Total>

<LastHour> </LastHour>

<LastDay> </LastDay>

</CountryCounts>

<VStotals>

<ConnsPerSec>0</ConnsPerSec>

<TotalConns>0</TotalConns>

<BitsPerSec>0</BitsPerSec>

<TotalBits>0</TotalBits>

<BytesPerSec>0</BytesPerSec>

<TotalBytes>0</TotalBytes>

<PktsPerSec>0</PktsPerSec>

<TotalPackets>0</TotalPackets>

</VStotals>

<Vs>

<VSAddress>10.35.48.17</VSAddress>

<VSPort>80</VSPort>

<VSProt>tcp</VSProt>

<Index>3</Index>

<Status>down</Status>

147

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

<ErrorCode>0</ErrorCode>

<Enable>1</Enable>

<TotalConns>0</TotalConns>

<TotalPkts>0</TotalPkts>

<TotalBytes>0</TotalBytes>

<TotalBits>0</TotalBits>

<ActiveConns>0</ActiveConns>

<BytesRead>0</BytesRead>

<BytesWritten>0</BytesWritten>

<ConnsPerSec>0</ConnsPerSec>

<ConnsRateBlocked>0</ConnsRateBlocked>

<RequestsRateBlocked>0</RequestsRateBlocked>

<MaxConnsBlocked>0</MaxConnsBlocked>

<WafEnable>0</WafEnable>

<InterceptMode>0</InterceptMode>

</Vs>

<Vs>

<VSAddress>10.35.48.24</VSAddress>

<VSPort>80</VSPort>

<VSProt>tcp</VSProt>

<Index>1</Index>

<Status>down</Status>

<ErrorCode>0</ErrorCode>

<Enable>1</Enable>

<TotalConns>0</TotalConns>

<TotalPkts>0</TotalPkts>

<TotalBytes>0</TotalBytes>

<TotalBits>0</TotalBits>

<ActiveConns>0</ActiveConns>

<BytesRead>0</BytesRead>

<BytesWritten>0</BytesWritten>

<ConnsPerSec>0</ConnsPerSec>

<ConnsRateBlocked>0</ConnsRateBlocked>

<RequestsRateBlocked>0</RequestsRateBlocked>

<MaxConnsBlocked>0</MaxConnsBlocked>

<WafEnable>0</WafEnable>

<InterceptMode>2</InterceptMode>

148

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

<Requests>0</Requests>

<Incidents>0</Incidents>

<Incidents_Hour>0</Incidents_Hour>

<Incidents_Day>0</Incidents_Day>

<Incidents_Dayover>0</Incidents_Dayover>

</Vs>

<TPS>

<Total>0</Total>

<SSL>0</SSL>

</TPS>

<Timestamp>

<Sec>1637849344</Sec>

<Usec>682846</Usec>

<Period>5006303</Period>

</Timestamp>

<ChangeTime>1637849309</ChangeTime>

</Data>

</Success>

</Response>

The statistics are explained in the table below.

Section

CPU

Name

User

System

Idle

IOWaiting

HWInterrupts

SWInterrupts

Additional Information

The percentage of the CPU spent processing in
user mode

The percentage of the CPU spent processing in
system mode

The percentage of CPU which is idle

The percentage of the CPU spent waiting for
I/O to complete

The percentage of hardware interrupts

The percentage of software interrupts

149

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

MBtotal

Memused

MBused

The total memory available in Mb

The amount of memory in use

The amount of memory in use in Mb

Percentmemused

The percentage of memory used

Memory

Memfree

MBfree

The amount of memory free

The amount of free memory in Mb

Percentmemfree

The percentage of free memory

DiskUsage

Name

GBtotal

GBused

Percentused

GBfree

Percentfree

The name of the partition

The total disk usage in Gb

The amount of disk space usage in Gb

The percentage of disk space in use

The amount of disk space free

The percentage of disk space free

150

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

CurrentConnections

The total number of current connections

CurrentConnectionsBlocked

The number of connections currently blocked

SuccessfulConnectionAttempts

The number of successful connection attempts

SuccessfulRequestAttempts

The number of successful request attempts

SuccessfulMatchedRuleAttempts

The number of rules that were successfully
matched

ConnectionAttemptsBlocked

The number of connection attempts that were
blocked

RequestAttemptsBlocked

The number of request attempts that were
blocked

MatchedRulesBlocked

The number of connections that were blocked
due to a matching rule limit

glbcps

glbrps

Global connections per second

Global requests per second

DifferentCountries

The number of different countries that
connections were made from

LastHour

LastDay

ifaceID

Speed

In

Out

Total (TPS)

SSL (TPS)

The number of different countries that
connections were made from in the last hour

The number of different countries that
connections were made from in the last day

The ID number of the interface

The speed of the link

Inbound

Outbound

The total number of Transactions Per Second
(TPS)

The total number of SSL Transactions Per
Second (TPS)

ClientLimits

Network

151

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

VStotals

ConnsPerSec

The number of connections per second

TotalConns

BitsPerSec

BytesPerSec

PktsPerSec

TotalPackets

The total number of Virtual Service connections

The number of bits per second

The number of bytes per second

The number of packets per second

The total number of packets transferred

152

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

Vs

VSAddress

The IP address of the Virtual Service

153

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

VSPort

The port of the Virtual Service

154

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

VSProt

Index

ErrorCode

Enable

TotalConns

TotalPkts

TotalBytes

TotalBits

ActiveConns

BytesRead

BytesWritten

ConnsPerSec

The protocol of the Virtual Service. This will
either be tcp or udp.

The index (ID) number of the Virtual Service

The error code

Displays whether the Virtual Service is enabled
(1) or disabled (0)

The total number of connections made

The total number of packets

The total number of bytes

The total number of bits

The total number of connections that are
currently active. When using ESP, all
connections going through the login process
are counted as active connections for the
Virtual Service. They are not counted as active
connections for the Real Server because they
are not actual connections to the Real Server.
The WUI page displays the number of active
connections associated with the Real Servers,
while SNMP displays the number of active
connections for the Virtual Service. Without
ESP, these values are identical. When using
ESP, the Virtual Service counts can be much
higher than the final counts going to the Real
Servers, due to the above reason.

The total number of bytes read

The total number of bytes written

The total number of Virtual Service connections
per second

ConnsRateBlocked

The rate at which connections were blocked

RequestsRateBlocked

The rate at which requested were blocked

155

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

MaxConnsBlocked

The maximum number of connections blocked

WafEnable

Requests

Incidents

Incidents_Hour

Incidents_Day

Incidents_Dayover

ChangeTime

ChangeTime

Displays whether WAF is enabled (1) or
disabled (0). The WAF statistics below will only
be displayed if WAF is enabled on the Virtual
Service.

The total number of requests handled by the
WAF (shows all requests, whether they were
blocked or not). Two requests will be recorded
for each connection – one incoming and one
outgoing request.

The total number of events handled by the WAF
(requests that were blocked).

The number of events that have happened in
the current hour (since xx.00.00).

The number of events that have happened
since midnight (local time).

The number of times the event counter has
gone over the configured warning threshold
today. For example, if the threshold is set to 10
and there has been 20 events, this counter will
be set to 2. The warning threshold is set on a
per-Virtual Service basis by setting the
AlertThreshold parameter. For further
information, refer to the Virtual Service
Control section.

The time of the last configuration change on
the LoadMaster. The configuration has not
changed if this value has not changed. This
only works if session management is enabled.
The time is represented in “Unix time or epoch
time” (also known as Portable Operating
System Interface (POSIX) time) format. This is a
system for describing instants in time, defined
as the number of seconds that have elapsed
since 00:00:00 Coordinated Universal Time

156

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

(UTC), Thursday 1st January 1970, not counting
leap seconds. For example, 1484150723 is the
equivalent of GMT: Wed, 11th January 2017
16:05:23 GMT. There are conversion tools are
available online to convert the value to an
easily readable format.

3.9 SDN Statistics

The device information for the specified SDN controller can be retrieved by running the following
command:

https://<LoadMasterIPAddress>/access/sdndeviceinfo?cid=<ControllerID>

Example output for the sdndeviceinfo command is provided below:

<Response stat="200" code="ok">
<Success>
<Data>
<controller id="62">
<deviceinfo>
<uid>openflow:151936205333838</uid>
<name>br3</name>
<type/>
<vendor>Nicira, Inc.</vendor>
<product>Open vSwitch</product>
<firmware>2.3.1</firmware>
<serial>None</serial>
<ip>10.35.8.47</ip>
<ifcount>3</ifcount>
<status/>
<portinfo>
<port>
<id>1</id>
<name>prt3</name>
<state/>
<mac>52:34:63:89:05:17</mac>
<curspeed>current_speed=0</curspeed>
<maxspeed>max_speed=0</maxspeed>
</port>
<port>
<id>2</id>
<name>vnet5</name>

157

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

<state/>
<mac>fe:54:00:79:04:75</mac>
<curspeed>current_speed=10000</curspeed>
<maxspeed>max_speed=0</maxspeed>
</port>
<port>
<id>local</id>
<name>br3</name>
<state/>
<mac>8a:2f:67:8c:25:4e</mac>
<curspeed/>
<maxspeed/>
</port>
</portinfo>
</deviceinfo>
<deviceinfo>
<uid>openflow:60003129350209</uid>
<name>br1</name>
<type/>
<vendor>Nicira, Inc.</vendor>
<product>Open vSwitch</product>
<firmware>2.3.1</firmware>
<serial>None</serial>
<ip>10.35.8.47</ip>
<ifcount>4</ifcount>
<status/>
<portinfo>
<port>
<id>3</id>
<name>vnet6</name>
<state/>
<mac>fe:54:00:ed:2d:aa</mac>
<curspeed>current_speed=10000</curspeed>
<maxspeed>max_speed=0</maxspeed>
</port>
<port>
<id>2</id>
<name>prt11</name>
<state/>
<mac>de:8f:f3:cc:58:7a</mac>
<curspeed>current_speed=0</curspeed>
<maxspeed>max_speed=0</maxspeed>
</port>

158

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

<port>
<id>1</id>
<name>prt1</name>
<state/>
<mac>5e:b2:61:21:c8:20</mac>
<curspeed>current_speed=0</curspeed>
<maxspeed>max_speed=0</maxspeed>
</port>
<port>
<id>local</id>
<name>br1</name>
<state/>
<mac>36:92:91:35:d8:41</mac>
<curspeed/>
<maxspeed/>
</port>
</portinfo>
</deviceinfo>
<deviceinfo>
<uid>openflow:130736296040257</uid>
<name>br2</name>
<type/>
<vendor>Nicira, Inc.</vendor>
<product>Open vSwitch</product>
<firmware>2.3.1</firmware>
<serial>None</serial>
<ip>10.35.8.47</ip>
<ifcount>4</ifcount>
<status/>
<portinfo>
<port>
<id>2</id>
<name>vnet7</name>
<state/>
<mac>fe:54:00:85:ca:9f</mac>
<curspeed>current_speed=10000</curspeed>
<maxspeed>max_speed=0</maxspeed>
</port>
<port>
<id>1</id>
<name>prt2</name>
<state/>
<mac>8a:8d:81:78:10:8b</mac>

159

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

<curspeed>current_speed=0</curspeed>
<maxspeed>max_speed=0</maxspeed>
</port>
<port>
<id>3</id>
<name>prt22</name>
<state/>
<mac>d2:10:88:e8:98:f6</mac>
<curspeed>current_speed=0</curspeed>
<maxspeed>max_speed=0</maxspeed>
</port>
<port>
<id>local</id>
<name>br2</name>
<state/>
<mac>76:e7:6a:7c:17:41</mac>
<curspeed/>
<maxspeed/>
</port>
</portinfo>
</deviceinfo>
<deviceinfo>
<uid>openflow:217995646047043</uid>
<name>br4</name>
<type/>
<vendor>Nicira, Inc.</vendor>
<product>Open vSwitch</product>
<firmware>2.3.1</firmware>
<serial>None</serial>
<ip>10.35.8.47</ip>
<ifcount>4</ifcount>
<status/>
<portinfo>
<port>
<id>2</id>
<name>vnet4</name>
<state/>
<mac>fe:54:00:ab:30:91</mac>
<curspeed>current_speed=10000</curspeed>
<maxspeed>max_speed=0</maxspeed>
</port>
<port>
<id>1</id>

160

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

<name>prt4</name>
<state/>
<mac>f2:fc:c5:31:1e:a0</mac>
<curspeed>current_speed=0</curspeed>
<maxspeed>max_speed=0</maxspeed>
</port>
<port>
<id>3</id>
<name>vnet8</name>
<state/>
<mac>fe:54:00:6a:f8:4e</mac>
<curspeed>current_speed=10000</curspeed>
<maxspeed>max_speed=0</maxspeed>
</port>
<port>
<id>local</id>
<name>br4</name>
<state/>
<mac>c6:44:11:0b:93:43</mac>
<curspeed/>
<maxspeed/>
</port>
</portinfo>
</deviceinfo>
</controller>
</Data>
</Success>

</Response>

The output is described in the table below.

Section

Name

Additional Information

161

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

Device Information

uid

The Unique Identifier (UID) for the device.

name

vendor

product

The name of the device.

The device vendor.

The type of device.

firmware

The firmware version of the device.

serial

ip

The serial number of the device.

The IP address of the device.

ifcount

The number of interfaces on the device.

status

id

name

The status of the device.

The ID number of the port.

The name of the port.

Port Information

mac

The MAC address of the port.

curspeed

The current speed of the port.

maxspeed

The maximum speed of the port.

The path information for the specified SDN controller (and corresponding Virtual Service
configuration on the LoadMaster) can be retrieved by running the following command:

https://<LoadMasterIPAddress>/access/sdnpathinfo?cid=<ControllerID>

Example output for the sdnpathinfo command is provided below:

<Response stat="200" code="ok">

<Success>

<Data>

<pathinfo>

<path>

<dir>fwd</dir>
<source>10.35.8.49</source>
<dest>10.35.8.89</dest>
<pathelem>

<switch>

<idx>0</idx>
<name>baloo</name>
<dpid>00:08:a0:1d:48:92:4f:80</dpid>

162

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

</switch>
<inport>

<idx>25</idx>
<name>25</name>
<byte>3397596</byte>

</inport>
<outport>

<idx>14</idx>
<name>14</name>
<byte>3395099</byte>

</outport>

</pathelem>
<pathelem>

<switch>

<idx>1</idx>
<name>bagheera</name>
<dpid>00:08:40:a8:f0:87:04:80</dpid>

</switch>
<inport>

<idx>15</idx>
<name>15</name>
<byte>3388430</byte>

</inport>
<outport>

<idx>6</idx>
<name>6</name>
<byte>1566302</byte>

</outport>

</pathelem>

</path>
<path>

<dir>rev</dir>
<source>10.35.8.89</source>
<dest>10.35.8.49</dest>
<pathelem>

<switch>

<idx>0</idx>
<name>baloo</name>
<dpid>00:08:a0:1d:48:92:4f:80</dpid>

</switch>
<inport>

<idx>25</idx>
<name>25</name>

163

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

<byte>3397596</byte>

</inport>
<outport>

<idx>14</idx>
<name>14</name>
<byte>3395099</byte>

</outport>

</pathelem>
<pathelem>

<switch>

<idx>1</idx>
<name>bagheera</name>
<dpid>00:08:40:a8:f0:87:04:80</dpid>

</switch>
<inport>

<idx>15</idx>
<name>15</name>
<byte>3388430</byte>

</inport>
<outport>

<idx>6</idx>
<name>6</name>
<byte>1566302</byte>

</outport>

</pathelem>

</path>

</pathinfo>

</Data>

</Success>

</Response>

The output is described in the table below.

Section

Name

Additional Information

dir

The direction of the path.

path

source

The source IP address.

dest

The destination IP address.

164

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

idx

The index number of the switch along the path.

switch

name

The name of the switch.

inport

dpid

The Data Path ID (DPID) of the switch.

idx

The switch port number of the inbound traffic.

name

The name of the inbound port.

byte

The number of bytes transferred on the port.

outport

idx

The switch port number of the outbound traffic.

name

The name of the outbound port.

byte

The number of bytes transferred on the port.

3.10 Real Servers

A Real Server can be managed by using one of the commands below.

https://<LoadMasterIPAddress>/access/showrs?vs=<IPaddr>&port=<Port>&prot=<tcp
/udp>&rs=<RS IPaddr>&rsport=<RS-Port>
https://<LoadMasterIPAddress>/access/delrs?vs=<IPaddr>&port=<Port>&prot=<tcp/
udp>&rs=<RS IPaddr>&rsport=<RS-Port>
https://<LoadMasterIPAddress>/access/delrs?vs=<IPaddr>&port=<Port>&prot=<tcp/
udp>&rs=!<RSIndex>
https://<LoadMasterIPAddress>/access/addrs?vs=<IPaddr>&port=<Port>&prot=<tcp/
udp>&rs=<RS IPaddr>&rsport=<RS-Port>
https://<LoadMasterIPAddress>/access/modrs?vs=<IPaddr>&port=<Port>&prot=<tcp/
udp>&rs=<RS IPaddr>&rsport=<RS-Port>

The rs parameter accepts integers (ID), service names (for SubVSs) and IP addresses. The ID can be
found in the <RSIndex> element when doing a showvs command, for example:

…

<Rs>

<Status>Up</Status>

<VSIndex>1</VSIndex>

<RsIndex>3</RsIndex>

<Addr>10.154.201.3</Addr>

<Port>80</Port>

<Forward>nat</Forward>

<Weight>1000</Weight>

<Limit>0</Limit>

<Enable>Y</Enable>

165

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

<Critical>N</Critical>

</Rs>

…

Alternatively, check the Modify Virtual Service screen in the WUI, which lists Real Server ID in the Id
column in the Real Servers section.

For the rs parameter, when using <RSIndex>, always precede it with an exclamation mark (‘!’).

For example:

https://<LoadMasterIPAddress>/access/showrs?vs=<IPaddr>&port=<Port>&prot=<tcp
/udp>&rs=!<RSIndex>

The Real Server IP address (that the rs parameter can be set to) can be in either IPv4 or IPv6
formats:

Example IPv4 address:10.11.0.24

Example IPv6 address: fdce:9b36:e54f:110::40:14

Some SubVS parameters, such as critical, need to be modified using the RsIndex of the SubVS, for
example:

https://<LoadMasterIPAddress>/access/modrs?vs=<ParentVSIndex>&rs=!<RsIndexOfT
heSubVS>&critical=<0/1>

To modify the settings of a Real Server which has been added to a SubVS, use the VS Index of the
SubVS and the RsIndex of the Real Server, for example:

https://<LoadMasterIPAddress>/access/modrs?vs=<SubVSIndex>&rs=!<RsIndex>&crit
ical=<0/1>

addrs and modrs accept the following additional (optional) parameters.

Name

Type

Default

Range

Description

addtoallsubvs

B

0

0 -
Disabled
1 -
Enabled

Enable this option when adding a Real Server to
all SubVSs of a Virtual Service.

When using this parameter, ensure you set the vs
parameter to the ID of the SubVS rather than the
parent Virtual Service.

Run the listvs command to retrieve the VSIndex
of the SubVS.

166

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

When using weighted round robin scheduling, the
weight of a Real Server is used to indicate what
relative proportion of traffic should be sent to the
server. Servers with higher values will receive
more traffic.

The weight of a SubVS can also be updated using
the modrs command - set the rs to the number
that appears in the Id column for the relevant
SubVS in the parent Virtual Service modify screen.

The port on the Real Server to be used.

weight

I

1000

1-65535

newport

I

<unset>

3-65535
(change
the Port
of the
Real
Server)

nat

nat, route

The type of forwarding method used. The default
method is NAT. Direct server return can only be
used with Layer 4 services.

forward

enable

limit

S

B

I

non_local

B

1

0

0

critical

B

0

Enable or disable the Real Server.

0-100000

The maximum number of open connections that
can be sent to a Real Server before it is taken out
of rotation.

0 -
Disabled

1 -
Enabled

By default only Real Servers on local networks can
be assigned to a Virtual Service. Enabling this
option will allow a non-local Real Server to be
assigned to the Virtual Service.

This option will only be available if nonlocalrs has
been enabled and the Transparent option has
been disabled on the relevant Virtual Service.

0 -
Disabled

1 -
Enabled

Enabling this parameter indicates that the Real
Server is required for the Virtual Service to be
considered available. The Virtual Service will be
marked as down if the Real Server has failed or is
disabled.

167

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

follow

I

<unset>

RsIndex
of Real
Server to
follow

Specify what Real Server the health check is based
on by setting this parameter to the RsIndex of the
Real Server to be followed. This can either be set
to the RsIndex of the same Real Server to health
check based on that particular Real Server status,
or another Real Server can be specified. For
example – if Real Server 1 is down, any Real
Servers which have their health check based on
Real Server 1 will also be marked as down,
regardless of their actual Real Server status.

If the service is a Layer 7 service then setting the ‘forward’
parameter to ‘route’ will have no effect

3.10.1 Enabling/Disabling Real Servers

3.10.1.1 Globally Enable/Disable a Real Server

A Real Server can be enabled/disabled globally, that is, for all Virtual Services by using the following
commands:

https://<LoadMasterIPAddress>/access/enablers?rs=<IPaddr>

or

https://<LoadMasterIPAddress>/access/disablers?rs=<IPaddr>

The Real Server IP address (that the rs parameter can be set to) can be in either IPv4 or IPv6 formats:

Example IPv4 address:10.11.0.24

Example IPv6 address: fdce:9b36:e54f:110::40:14

3.10.1.2 Locally Enable/Disable a Real Server

A Real Server can be disabled/enabled locally, that is, for one specific Virtual Service, by using the
following commands:

https://<LoadMasterIPAddress>/access/modrs?vs=<VirtualServiceIPAddress>&port=
<Port>&prot=<tcp/udp>&rs=<RealServerIPAddress>&rsport=<port>&enable=n

or

https://<LoadMasterIPAddress>/access/modrs?vs=<VirtualServiceIPAddress>&port=
<Port>&prot=<tcp/udp>&rs=<RealServerIPAddress>&rsport=<port>&enable=y
The Real Server IP address (that the rs parameter can be set to) can be in
either IPv4 or IPv6 format.

168

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

Example IPv4 address: 10.11.0.24

Example IPv6 address: fdce:9b36:e54f:110::40:14

3.11 Rules & Checking

Content Rules can be managed using the RESTful API.

3.11.1 Show Rules

The rules which are in use within the system can be displayed by using the showrule command.

https://<LoadMasterIPAddress>/access/showrule?[name=<Rule Name>]&[type=<0-5>]

Running the showrule command with no parameters will list all of the existing rules. The list can be
reduced by either specifying the name of a rule or the type of the rules to be displayed.

The type is one of the following:

Value

Type

Description

0

1

2

3

4

5

MatchContentRule

The original rules.

AddHeaderRule

Rule to Add header field

DeleteHeaderRule

Rule to Delete a header field.

ReplaceHeaderRule Rule to modify a header field.

ModifyURLRule

URL rewrite rule.

ReplaceBodyRule

Rule to replace a body string.

3.11.2 Delete a Rule from the System

A rule can be deleted by using the delrule command.

https://<LoadMasterIPAddress>/access/delrule?name=<Rule Name>

3.11.3 Add/Modify a Rule on the System

Rules can be added or modified by using the addrule and modrule commands.

https://<LoadMasterIPAddress>/access/addrule?name=<Rule Name>
https://<LoadMasterIPAddress>/access/modrule?name=<Rule Name>

169

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

The following parameters can be set (dependent on the type of rule). When creating a Rule - if the
"type" is not specified, it will default to zero, that is, a MatchContentRule. If "type" is not specified
when performing a modify operation, the type will not be changed.

Unless modifying/adding an AddHeaderRule, the pattern parameter must be supplied.
Type 0 (MatchContentRule)

Name

Type

Default

Range

lregex

lprefix

lpostfix

matchtype

inchost

nocase

negate

incquery

S

B

B

B

B

regex

N

N

N

N

header

S

<unset>

See below

Additional
Information

The type of
matching to be
performed by the
rule.

Prepend the
hostname to
request URI
before
performing the
match.

Ignore case when
comparing the
strings.

Invert the sense
of the match.

Append the
query string to
the URI before
performing a
match.

The header field
name that should
be matched. If no
header field is
set, the default is
to match in the
URL. Set this to
body to match

170

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

pattern

setonmatch

S

I

<unset>

<unset>

0-9

onlyonflag

I

<unset>

0-9

onlyonnoflag

I

<unset>

0-9

on the body of a
request.

The pattern to be
matched.

If the rule is
successfully
matched, set the
specified flag.

Only try to
execute this rule
if the specified
flag is set.

Using the
onlyonflag,
onlyonnoflag,
and setonmatch
parameters, it is
possible to make
rules dependent
on each other,
that is, only
execute a
particular rule if
another rule has
been successfully
matched. For
more detailed
instructions on
‘chaining’ rules,
refer to the
Content Rules,
Feature
Description
document.

Only try to
execute this rule

171

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

mustfail

B

0 - Disabled

0 – Disabled

1 - Enabled

The header parameter is optional and is the header in which
the match is to be performed.

Type 1 (AddHeaderRule)

if the specified
flag is not set.

If this rule is
matched, then
always fail to
connect.

Name

Type

Default

Additional Information

header

replacement

onlyonflag

onlyonnoflag

S

S

I

I

<unset>

<unset>

<unset>

<unset>

Name of the header field to be added.

The replacement string. You can enter a maximum of 255
characters in this parameter.

Range: 1-9

Only try to execute this rule if the specified flag is set.

Using the onlyonflag, onlyonnoflag, and setonmatch
parameters, it is possible to make rules dependent on each
other, that is, only execute a particular rule if another rule has
been successfully matched. For more detailed instructions on
‘chaining’ rules, refer to the Content Rules, Feature Description
document.

Range: 1-9

Only try to execute this rule if the specified flag is not set.

Type 2 (DeleteHeaderRule)

Name

Type

Default

Additional Information

pattern

onlyonflag

S

I

<unset>

<unset>

The pattern to be matched.

Range: 1-9

172

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

Only try to execute this rule if the specified flag is set.

Using the onlyonflag, onlyonnoflag, and setonmatch
parameters, it is possible to make rules dependent on each
other, that is, only execute a particular rule if another rule has
been successfully matched. For more detailed instructions on
‘chaining’ rules, refer to the Content Rules, Feature Description
document.

onlyonnoflag

I

<unset>

Range: 1-9

Only try to execute this rule if the specified flag is not set.

Type 3 (ReplaceHeaderRule)

Name

header

replacement

pattern

onlyonflag

onlyonnoflag

Type 4 (ModifyURLRule)

Type

Default

Additional Information

S

S

S

I

I

<unset>

<unset>

<unset>

<unset>

The header field name where the
substitution should be performed.

The replacement string.

The pattern to be matched.

Range: 1-9

Only try to execute this rule if the specified
flag is set.

Using the onlyonflag, onlyonnoflag, and
setonmatch parameters, it is possible to
make rules dependent on each other, that
is, only execute a particular rule if another
rule has been successfully matched. For
more detailed instructions on ‘chaining’
rules, please refer to the Content Rules,
Feature Description document.

Range: 1-9

<unset>

Only try to execute this rule if the specified
flag is not set.

173

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

Name

Type

replacement

pattern

onlyonflag

onlyonnoflag

S

S

I

I

Type 5 (ReplaceBodyRule)

Name

Type

replacement

pattern

onlyonflag

S

S

I

Default

<unset>

<unset>

<unset>

Additional Information

How the URL is to be modified.

The pattern to be matched.

Range: 1-9

Only try to execute this rule if the specified
flag is set.

Using the onlyonflag, onlyonnoflag, and
setonmatch parameters, it is possible to
make rules dependent on each other, that
is, only execute a particular rule if another
rule has been successfully matched. For
more detailed instructions on ‘chaining’
rules, please refer to the Content Rules,
Feature Description document.

Range: 1-9

<unset>

Only try to execute this rule if the specified
flag is not set.

Default

<unset>

<unset>

<unset>

Additional Information

The replacement string.

The pattern to be matched.

Range: 1-9

Only try to execute this rule if the
specified flag is set.

Using the onlyonflag,
onlyonnoflag, and setonmatch
parameters, it is possible to make
rules dependent on each other,
that is, only execute a particular
rule if another rule has been

174

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

successfully matched. For more
detailed instructions on ‘chaining’
rules, please refer to the Content
Rules, Feature Description
document.

Enable this parameter to ignore
the case of the strings when
comparing.

0 – Disabled

1 - Enabled

Range: 1-9

0 – Disabled

<unset>

Only try to execute this rule if the
specified flag is not set.

caseindependent

onlyonnoflag

B

I

3.11.4 Add/Delete Real Server Rule

Rules can be added or deleted from Real Servers by using the addrsrule and delrsrule commands:

https://<LoadMasterIPAddress>/access/addrsrule?vs=<IPaddr>&port=<Port>&prot=<
tcp/udp>&rs=<RS IPaddr>&rsport=<RS-Port>&rule=<RuleName>
https://<LoadMasterIPAddress>/access/delrsrule?vs=<IPaddr>&port=<Port>&prot=<
tcp/udp>&rs=<RS IPaddr>&rsport=<RS-Port>&rule=<RuleName>

The rs parameter also accepts integers (ID). The ID (Real Server index) can be found in the
<RSIndex> element when doing a showvs command, for example:

…

<Rs>

<Status>Up</Status>

<VSIndex>1</VSIndex>

<RsIndex>3</RsIndex>

<Addr>10.154.201.3</Addr>

<Port>80</Port>

<Forward>nat</Forward>

<Weight>1000</Weight>

<Limit>0</Limit>

<Enable>Y</Enable>

<Critical>N</Critical>

</Rs>

175

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

…

3.11.5 Add/Delete SubVS Rule

Content rules can be added or deleted from SubVSs by using the addrsrule and delrsrule
commands:

https://<LoadMasterIPAddress>/access/addrsrule?vs=<IPaddr>&port=<Port>&prot=<
tcp/udp>&rs=!<RsIndexOfSubVS>&rule=<RuleName>
https://<LoadMasterIPAddress>/access/delrsrule?vs=<IPaddr>&port=<Port>&prot=<
tcp/udp>&rs=!<RsIndexOfSubVS>&rule=<RuleName>

To get the RsIndex or VsIndex, run the listvs command. For further information, refer to the Virtual
Service Control section.

To add a content rule to a Real Server which is assigned to a SubVS, run the following command:

https://<LoadMasterIPAddress>/access/addrsrule?vs=<VSIndexOfSubVS>&rs=<RealSe
rverIPAddress>&rsport=<RealServerPort>&rule=<RuleName>

Content rules can be added to a SubVS, by using the addprerule, addresponserule and
addrequestrule commands, depending on the type of rule being added:

https://<LoadMasterIPAddress>/access/addprerule?vs=<VSIndexOfSubVS>&rule=<Rul
eName>
https://<LoadMasterIPAddress>/access/addresponserule?vs=<VSIndexOfSubVS>&rule
=<RuleName>
https://<LoadMasterIPAddress>/access/addrequestrule?vs=<VSIndexOfSubVS>&rule=
<RuleName>

Content rules can be deleted from a SubVS, by using the delprerule, delresponserule and
delrequestrule commands, depending on the type of rule being deleted:

https://<LoadMasterIPAddress>/access/delprerule?vs=<VSIndexOfSubVS>&rule=<Rul
eName>
https://<LoadMasterIPAddress>/access/delresponserule?vs=<VSIndexOfSubVS>&rule
=<RuleName>
https://<LoadMasterIPAddress>/access/delrequestrule?vs=<VSIndexOfSubVS>&rule=
<RuleName>

Virtual Services and SubVSs share the same attributes. If you
want to apply a content rule to a SubVS, you must know the
RsIndex (ID) of the SubVS. To find the RsIndex, run the listvs
command and scroll down to find the RsIndex parameter you
want to edit.

3.11.6 Add Virtual Service Rules

Rules can be added to Virtual Services by using the addprerule, addresponserule, addrequestrule
and addresponsebodyrule commands:

176

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

https://<LoadMasterIPAddress>/access/addprerule?vs=<IPaddr>&port=<Port>&prot=
<tcp/udp>&rule=<RuleName>
https://<LoadMasterIPAddress>/access/addresponserule?vs=<IPaddr>&port=<Port>&
prot=<tcp/udp>&rule=<RuleName>
https://<LoadMasterIPAddress>/access/addrequestrule?vs=<IPaddr>&port=<Port>&p
rot=<tcp/udp>&rule=<RuleName>
https://<LoadMasterIPAddress>/access/addresponsebodyrule?vs=<IPaddr>&port=<Po
rt>&prot=<tcp/udp>&rule=<RuleName>

If Kerberos Constrained Delegation (KCD) is enabled on the
Virtual Service, it is not possible to add a response body rule.

3.11.7 Delete Virtual Service Rules

Rules can be deleted from Virtual Services by using the delprerule, delresponserule,
delrequestrule and delresponsebodyrule commands:

https://<LoadMasterIPAddress>/access/delprerule?vs=<IPaddr>&port=<Port>&prot=
<tcp/udp>&rule=<RuleName>
https://<LoadMasterIPAddress>/access/delresponserule?vs=<IPaddr>&port=<Port>&
prot=<tcp/udp>&rule=<RuleName>
https://<LoadMasterIPAddress>/access/delrequestrule?vs=<IPaddr>&port=<Port>&p
rot=<tcp/udp>&rule=<RuleName>
https://<LoadMasterIPAddress>/access/delresponsebodyrule?vs=<IPaddr>&port=<Po
rt>&prot=<tcp/udp>&rule=<RuleName>

3.11.8 Check Parameters

The Service Check Parameters can be obtained by using the following command:

https://<LoadMasterIPAddress>/access/showhealth?

The output of the showhealth command will display the RetryInterval, Timeout and RetryCount
values.

The Service Check Parameters can be modified by using modhealth command.

Name

Type

Range

Default

Additional Information

Mandatory

Defined in seconds, this is the delay
between health checks. This includes
clusters and FQDNs.

RetryInterval

I

9-120
(901)

9

Recommended and default value:
9 seconds

N

Valid values range from the
<mininterval> (9) to the <maxinterval>
(901).

177

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

The <mininterval> is RetryCount *
Timeout + 1, that is, a value of 9 by
default.

The <maxinterval> is 901 [because that
is what 60 (maximum Timeout) * 15
(maximum RetryCount) + 1 is].

You can manually set the
RetryInterval to up to 120 seconds.
The RetryInterval value may go above
120 if the Timeout and RetryCount
parameters are configured with high
enough values.

If the RetryInterval is above 120
seconds, you must adjust the Timeout
and RetryCount values to modify the
RetryInterval.

Defined in seconds, this is the allowed
maximum wait time for a reply to a
health check.

This is the consecutive number of
times in which a health check must fail
before it is marked down and removed
from the load balancing pool.

N

N

Timeout

RetryCount

I

I

4-60

2-15

4

2

To configure all three parameters, you must first set the Timeout and/or RetryCount in one request.
Then, set the RetryInterval in the second request. For example:

https://<LoadMasterIPAddress>/access/modhealth?Timeout=<TimeoutValue>&RetryCo
unt=<CountValue>

https://<LoadMasterIPAddress>/access/modhealth?RetryInterval=<IntervalValue>

The Adaptive Check parameters can be obtained by using the following command:

https://<LoadMasterIPAddress>/access/showadaptive?

The Adaptive Check parameters can be modified by using the following command:

https://<LoadMasterIPAddress>/access/modadaptive?AdaptiveURL=<URL>&AdaptivePo
rt=<Port>&<AdaptiveInterval=<Interval>&MinPercent=%Value>

178

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

3.12 Certificates & Security

3.12.1 Certificate Management

Certificates can be managed using the following commands.

To list the currently installed certificates and their fingerprints, run the following command:

https://<LoadMasterIPAddress/access/listcert

Example output for the listcert command is provided below:

<Response stat="200" code="ok">

<Success><Data><cert>

<name>ecccert</name>

<type>ECC</type>

<publickey>MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAExIIYNDHXTHHOGxWcQlNjXMwnBlZNvaEp4V4o+0y
UBILnf7+hEZjbTKxfAPTiBechmEe6LNapZH6M0HK8lAsG+g==</publickey>

</cert>

<cert>

<name>rsacertificate</name>

<type>RSA</type>

<modulus>EBABCF2255B7E3A784E0122057E75E5902DAD385868A405775BE6641E343E1FED9B484FD3EA0A
CA6C7EBA301EDD4AAC2BA32E1F5646611B95640B0DE311B498A153E5784C742BB4617D0C5D26A37DE893BC
F56D7D6A0E2D0A70BE8FFD2AC048151F698A006AF8AB27A7FFFA4359ABF1553347E762FA6913DAEAE17E8D
24A649D9925041267083A8A422E3EB30E93F25F9AF764E1314FB8A19943B82063F4FB0429D1428098E0F1D
B5E1197DC71159F46BE6D82E79012249377C179DC2D0704EB0CFAD904C048CC6915F457F603DD5E7D9131C
EF799E86EB761836051AE411B330D3C39087BB9F7ABB0DDF33354AE89B29CD3943C73B99777A3D8D67E36A
056A3</modulus>

</cert>

</Data>

</Success>

</Response>

To list the currently installed intermediate certificates, run the following command:

https://<LoadMasterIPAddress/access/listintermediate

To return an existing certificate as a BLOB, run the following command:

https://<LoadMasterIPAddress/access/readcert?cert=<CertName>

To return an existing intermediate certificate as a BLOB, run the following command:

https://<LoadMasterIPAddress/access/readintermediate?cert=<CertName>

179

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

By fault, for the readcert and reasintermediate commands, the BLOB is in PEM format. There is an
optional parameter called outform that can be used to specify the format – either PEM or DER, for
example:

https://<LoadMasterIPAddress/access/readcert?cert=<CertName>&outform=<PEM/DE
R>

DER is Base64-encoded because it is a binary format.

To upload a certificate, run the following cURL command:

curl –X POST --data-binary “@<Filename>.<Exension>” –k
https://<LoadMasterIPAddress/access/addcert?cert=<CertName>&password=<Passwor
d>&replace=<0/1>

If you are uploading a certificate and key file, insert both the
certificate and key in the same file.

Name

Type

Default

Additional Information

Mandatory

cert

password

S

S

The identifier that the certificate is known as on the
LoadMaster.

<unset>

<unset>

The (optional) passphrase that was used to protect
the certificate when it was created.

0 - Not replacing

1 - Replacing

replace

B

<unset>

If you are replacing a certificate which already exists
in the LoadMaster, set the replace parameter to 1.
If you are uploading a new certificate, set replace
to 0.

https://<LoadMasterIPAddress>/access/delcert?cert=<CertName>

It is not possible to delete a certificate assigned to a Virtual
Service. Remove the certificate from any Virtual Services before
deleting.

Y

N

N

https://<LoadMasterIPAddress>/access/addintermediate?cert=<CertName>
https://<LoadMasterIPAddress>/access/delintermediate?cert=<CertName>
https://<LoadMasterIPAddress>/access/backupcert?password=<Password>
https://<LoadMasterIPAddress>/access/restorecert?password=<Password>&Type=<ty
pe>

180

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

The password (passphrase) must be alpha numeric and is case sensitive. The minimum number of
characters is 7 with a maximum of 64.

The type parameter has three possible values:

full - All Virtual Service and intermediate certificates

third - Intermediate certificates only

vs - Virtual Service certificates only

The values for the type parameter are case sensitive. Ensure to
use lowercase when setting this parameter.

Replace is a boolean value which tells the LoadMaster whether to replace an existing certificate with
the same name or not.

Parameters relating to Certificates that can be managed using get and set commands are detailed in
the following table:

Name

Type

Additional Information

admincert

localcert

S

S

3.12.2 Let's Encrypt Certs

This parameter is only relevant when using HA.

This section contains details about the Let's Encrypt API commands and parameters. You can
retrieve or configure each of these parameters using the get or set RESTful API commands.

3.12.2.1 Register a Let's Encrypt Account

To register a Let's Encrypt account to the LoadMaster, run the registerleaccount command. For
example:

/access/registerleaccount

Users can also register a Let's Encrypt account using an email address as an optional parameter, run
the registerleaccount?email=abc@yahoo.com command. For example:

/access/registerleaccount?email=abc@yahoo.com

181

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

3.12.2.2 Get an existing Let's Encrypt account

To get an existing Let's Encrypt account registered with other ACME clients such as Certbot, run the
fetchleaccount?password=<password> command. For example:

curl -X POST --data-binary "@account.key" -k
"https://<Username>:<Password>@<LoadMasterIPAddress>/access/fetchleaccount?password=
<password>"

3.12.2.3 Let's Encrypt Global Parameters

The Let's Encrypt global parameters can be configured using the get or set commands.

To set the Renew Period for the Let's Encrypt certificate, run the
set?param=renewperiod&value=<value> command. For example:

/access/set?param=renewperiod&value=<value>

Valid values for the Renew Period field range from 1 to 60
(days).

To get the details of the Renew Period for the Let's Encrypt certificate, run the
get?param=renewperiod command. For example:

/access/get?param=renewperiod

To set the Let's Encrypt directory URL information, run the
set?param=directoryurl&value=<value> command. For example:

/access/set?param=directoryurl&value=<value>

To get the Let's Encrypt directory URL information, run the get?param=directoryurl command. For
example:

/access/get?param=directoryurl>

3.12.2.4 Request a New Certificate from Let's Encrypt

To request a new certificate from Let's Encrypt, run the addlecert?cert=<cert_
identifier>&cn=<FQDN>&vid=<value> command using cert, cn and vid as mandatory parameters.
For example:

/access/addlecert?cert=<cert_identifier>&cn=<FQDN>&vid=<value>

Other optional parameters are also available, such as:

182

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

san1,san2,..,san10, vid1,vid2,...vid10 are for SAN and it's respective VID, country, state, city,
company, organization, email, key_size, etc.

Below are some examples of commands that contains optional parameters:

/access/addlecert?cert=<cert_identifier>&cn=<FQDN>&vid=<value>&ec=no&key_size=4096

/access/addlecert?cert=<cert_identifier>&cn=<FQDN>&vid=<value>&ec=no&key_size=2048

/access/addlecert?cert=<cert_identifier>&cn=<FQDN>&vid=<value>&ec=yes

/access/addlecert?cert=<cert_
identifier>&cn=<FQDN>&vid=<value>&san1=<FQDN>&vid1=<value>&san2=<FQDN>&vid2=<valu
e>

3.12.2.5 Renew a Let's Encrypt Certificate

To renew a Let's Encrypt certificate, run the renewlecert?cert=<cert_identifier> command. For
example:

/access/renewlecert?cert=<cert_identifier>

3.12.2.6 Delete a Let's Encrypt Certificate

To delete a Let's Encrypt certificate from the LoadMaster, run the dellecert?cert=<cert_identifier>
command. For example:

/access/dellecert?cert=<cert_identifier>

3.12.2.7 List the Let's Encrypt Certificates

To list the Let's Encrypt certificates that are installed on the LoadMaster, run the listlecert
command. For example:

/access/listlecert

3.12.2.8 Get the Let's Encrypt Account Information

To get the Let's Encrypt account information from the LoadMaster, run the leaccountinfo command.
For example:

/access/leaccountinfo

183

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

3.12.2.9 Get Details about a Specific Let's Encrypt Certificate

To get the details of a specific Let's Encrypt certificate from the LoadMaster, run the
getlecert?cert=<cert_identifier> command. For example:

/access/getlecert?cert=<cert_identifier>

3.12.3 Cipher Sets

Custom cipher sets can be manipulated using the commands below.

It is not possible to modify or delete system-defined cipher sets.

3.12.3.1 Modify a Custom Cipher Set/Create a New Custom Cipher Set

The modifycipherset command can be used to update an existing custom cipher set or create a
new custom cipher set.

If the name of an existing custom cipher set is specified, that
cipher set will be updated. If a new name is used, a new cipher
set will be created.

For example:

https://<LoadMasterIPAddress>/access/modifycipherset?name=<CustomCipherSetNam
e>&value=<Cipher(s)>

Multiple ciphers can be assigned by separating them with a colon (:).

3.12.3.2 Retrieve the Details of an Existing Cipher Set

The getcipherset command can be used to retrieve the list of ciphers which are in the specified
cipher set, for example:

https://<LoadMasterIPAddress>/access/getcipherset?name=<CipherSetName>

The valid values for the name parameter are below:

Default

Default_NoRc4

BestPractices

Intermediate_compatibility

Backward_compatibility

184

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

WUI

FIPS

Legacy

<NameOfCustomCipherSet>

The values are case sensitive.

3.12.3.3 Delete a Custom Cipher Set

The delcipherset command can be used to delete an existing custom cipher set. For example:

https://<LoadMasterIPAddress>/access/delcipherset?name=<CustomCipherSetName>

A custom cipher set cannot be deleted if it is assigned to any
Virtual Services. If this command is run when a cipher set is
assigned to a Virtual Service, an error message will be returned
which says Command Failed: Cipher set in use.

3.12.4 Remote Access

Parameters relating to Remote Access that can be managed using get and set commands are
detailed in the following table. Refer to the Using get and set commands section for details on the
get and set commands.

Name

Type

Range

Additional Information

admingw

A

enableapi

B

no (or 0) – Disabled

yes - Enabled

When administering the LoadMaster
from a non-default interface, this
option allows the user to specify a
different default gateway for
administrative traffic only.

To unset this, set the value to an
empty string.

Enables and disables the RESTful
API Interface described in this
document.

To enable the API, you must send a
GET command along with

185

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

eccerts

I

0 - RSA self-signed certs

1 - EC certs with a RSA
signature

2 - EC certs with an EC
signature

param=enableapi&value=yes – in
that order. (The value 1 is not
supported and returns an error.)

Specify the type of self-signed
certificates that the system will use.
The options are described below:

lRSA self-signed certs: By
default, these are RSA
certificates that are signed
with the Kemp RSA root
certificate.

lEC certs with a RSA
signature: The LoadMaster
can generate an EC certificate
also signed by the original
RSA Kemp root certificate.

l EC certs with an EC
signature: The LoadMaster
can generate an EC certificate
signed by the Kemp EC root
certificate. In this mode, any
CSRs generated will also be
EC.

You should not switch from
RSA self-signed certs to EC certs
with an EC signature directly. If you
do this, connections will fail because
there is no EC Kemp Certificate
Authority (CA) certificate. To work
around this, you must first switch
from RSA self-signed certs to EC
certs with a RSA signature.

Then, download the new EC Kemp
CA certificate by clicking Download
ECC Root Cert in the bottom-right

186

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

of the WUI under the main menu
after refreshing the page. After you
have downloaded the certificate,
you can switch to EC certs with an
EC signature with no loss of
connection.

Specify the cipher set to use on
outbound connections (OCSP, email,
LDAP, and so on). This is global for
all outbound connections. For
information on each of the cipher
sets available, refer to the SSL
Accelerated Services Feature
Description.

Re-encrypt
connections are not
affected by the
outbound cipher set.

This parameter is only relevant if
Session Management is enabled.

The valid values are below:

Default

Default_NoRc4

BestPractices

Intermediate_compatibility

Backward_compatibility

WUI

FIPS

Legacy

Null_Ciphers

ECDSA_Default

ECDSA_BestPractices

<NameOfCustomCipherSet>

<EmptyString> - This resets
to the default value (None -
Outbound Default).

0 – Password only access
(default)

1 – Password or client
certificate

2 – Client certificate required

3 – Client certificate required
(verify via OCSP)

outboundcipherset

S

adminclientaccess

I

187

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

tethering

geoclients

geosshport

sshaccess

sshiface

sshport

wuiaccess

wuiiface

wuiport

B

A

I

B

S

I

B

I

I

geopartners

A

0 – Disabled

1 – Enabled

3-65530

3-65530

Allow the LoadMaster to regularly
check the Kemp website for new
software versions.

Set the addresses of the GEO
LoadMasters which can retrieve
service status information from the
LoadMaster.

To unset this, set the value to an
empty string.

The port over which GEO
LoadMasters will communicate with
each other.

Specify over which addresses
remote administrative SSH access to
the LoadMaster is allowed.

Specify the addresses over which
remote administrative SSH access to
the LoadMaster is allowed.

Specify the port used to access the
LoadMaster using the SSH protocol.

Enables or disables WUI access.

Specifies the interface for WUI.

Specifies the port to access the WUI.

This has a default value of 443.

Set the IP address of the GEO
LoadMaster partner(s). These GEO
LoadMasters will keep their DNS
configurations in sync.

To unset this, set the value to an
empty string.

Note: Before partnering GEO

188

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

LoadMasters, a backup should be
taken of the relevant GEO
LoadMaster that has the
correct/preferred configuration. This
backup should then be restored to
the other LoadMasters that will be
partnered with the original
LoadMaster. For more information
and step-by-step instructions, refer
to the GEO, Feature Description.

Allow WUI access from multiple
interfaces. Apart from the main
administrative interface, each
interface can then be enabled to
allow WUI access.

Specify the port used to access the
API interface. If the port is unset,
you can access the API over the web
interface port.

Set the SSH pre-authentication
banner, which is displayed before
the login prompt when logging in
using SSH. Space characters should
be escaped by entering %20.

This field accepts up to 5,000
characters. Anything past the 5,000
character limit will not be displayed.

Specify the ID of the GEO interface in
which the SSH partner tunnel is
created, for example setting this to 0
means the interface eth0. This is the
interface that the GEO

partners will communicate through.

multihomedwui

B

apiport

l

SSHPreAuth

S

Up to 5,000 characters

geo_ssh_iface

I

189

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

3.12.4.1 Set Admin Access

The web administrative access interface and the administrative default gateway can be set in one
step by running the following command with the associated parameters:

/access/setadminaccess?wuiiface=<WUIInterfaceaddress>&wuiport=<Port>&wuidefau
ltgateway=<DefaultGatewayAddress>

Parameters relating to the setadminaccess command are shown in the following table:

Parameter

Type

Range

Additional Information

Mandatory

wuiiface

wuiport

I

I

wuidefaultgateway

S

Valid
interface
index

3-65535

Valid IP
address

The index of an existing interface. This
index number corresponds to the
interface number in the LoadMaster WUI,
for example, the index for eth0 is 0.

Specify the port used to access the
administrative web interface.

When administering the LoadMaster from
a non-default interface, a different
default gateway for administrative traffic
only can be specified using this
parameter.

Y

Y

N

3.12.4.2 Get GEO Partner Status

To return the status of all configured GEO partners, run the following command:

https://<LoadMasterIPAddress>/access/getgeopartnerstatus

An empty list is returned if there are no GEO partners configured. If a status for a particular partner
is not known, it is reported as “Unknown”.

3.12.4.3 WUI Authentication and Authorization Options

Parameters relating to WUI Authentication and Authorization Options that can be managed using
get and set commands are detailed in the following table. Refer to the Using get and set
commands section for the get and set commands.

Name

Type

Range

Description

wuildapep

S

A valid
LDAP endpoint
name

Specify the name of the LDAP endpoint to
use for WUI authentication.

190

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

ldapbackupserver

ldapsecurity

ldapserver

ldaprevalidateinterval

A

I

A

B

Specifies the backup LDAP server for
authentication.

Specifies the security mode for LDAP
authentication.

0 = Not
Encrypted

1 = StartTLS

2 = LDAPS

Specifies the LDAP server to use for
authentication.

Specifies how often to revalidate the
authentication to the LDAP server.

This option is only relevant when the LDAP
endpoint has either StartTLS or LDAPS
selected as the LDAP Protocol. When the
wuiservercertval parameter is enabled, it
ensures that the host name or IP address that
was used to initiate the secure connection
resides in the Certificate Subject or Subject
Alternative Names (SAN) of the certificate.

Enter a space-separated list of existing
remote user groups to assign, for example
testgroup%20testgroup2. Set the parameter
to an empty value to remove all assigned
groups, for example value=.

Enable or disable nested remote user groups.

Specify the domain to use if no domain is
provided in the username when group WUI
authentication is in use. It is always used as
the domain for group search if the Windows
logon is used in the format prefix\username.

3-65535

Specifies the TCP port for the backup RADIUS
server.

wuiservercertval

B

0 - Disabled

1 - Enabled

0 = Disabled

1 = Enabled

wuiusergroups

wuinestedgroups

wuidomain

radiusbackupport

S

B

S

I

191

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

radiusbackupsecret

radiusbackupserver

radiusport

radiusrevalidateinterval

S

A

I

I

3-65535

10-86400

radiussendnasid

B

0 - Disabled

1 - Enabled

radiusnasid

S

radiussendvendorspec

b

0 - Disabled

1 - Enabled

Specifies the password (secret) to the backup
RADIUS server.

Specifies the backup RADIUS server to use for
authentication.

Specifies the TCP port for communication to
the RADIUS server.

Specifies when to revalidate the
authentication to the RADIUS server.

If this parameter is disabled (default), a NAS
identifier is not sent to the RADIUS server. If it
is enabled, a Network Access Server (NAS)
identifier string is sent to the RADIUS server.
By default, this is the hostname.
Alternatively, if you specify a value in the
radiusnasid parameter, this value is used as
the NAS identifier. If the NAS identifier cannot
be added, the RADIUS access request is still
processed.

If the radius_send_nas_id parameter is
enabled, the radius_nas_id parameter is
relevant. When specified, this value is used as
the NAS identifier. Otherwise, the hostname
is used as the NAS identifier. If the NAS
identifier cannot be added, the RADIUS
access request is still processed.

This parameter is only relevant if the
radiussendnasid parameter is enabled.

If this parameter is disabled (default), an
Attribute Value Pair (AVP) is not send to the
RADIUS server. If it is enabled, an Attribute
Value Pair in the RADIUS request sent to the
server doing the authentication against the
user trying to log in to the LoadMaster WUI.

radiussecret

S

Specifies the password (secret) to the RADIUS

192

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

radiusserver

sessionlocalauth

sessionauthmode

A

B

I

Refer to the
table below.

server.

Specifies the RADIUS server to use for
authentication.

IPv6 is not supported for
RADIUS authentication.

Enables or disables local authentication.

Specifies the authentication mode for the
load balancer.

The following table describes the Radius, LDAP and Local user options that are selected depending
on the value given to the sessionauthmode parameter

Radius

LDAP

Local

Value

Authent.

Author.

Authent.

Authent.

Author.

7

263

775

23

22

788

790

791

789

773

262

774

772

No

Yes

Yes

No

No

Yes

Yes

Yes

Yes

Yes

Yes

Yes

Yes

No

No

Yes

No

No

Yes

Yes

Yes

Yes

Yes

No

Yes

Yes

No

No

No

Yes

Yes

Yes

Yes

Yes

Yes

No

No

No

No

No

Yes

Yes

Yes

No

No

No

Yes

Yes

Yes

No

No

No

No

Yes

Yes

Yes

Yes

No

Yes

Yes

No

No

Yes

Yes

No

193

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

278

279

Yes

Yes

No

No

Yes

Yes

No

Yes

No

Yes

3.12.5 Admin WUI Access

Parameters relating to Admin WUI Access that can be managed using get and set commands are
detailed in the following table. Refer to the Using get and set commands section for details on the
get and set commands.

Name

Type

Range

Description

wuicipherset

S

The valid values are below:

Default

Default_NoRc4

BestPractices

Intermediate_compatibility

Backward_compatibility

WUI

FIPS

Legacy

Null_Ciphers

ECDSA_Default

ECDSA_BestPractices

<NameOfCustomCipherSet>

WUITLS13Ciphersets

S

All TLS1.3 available cipher
sets

Specify the cipher set to use for
the LoadMaster WUI.

Specify which TLS1.3 cipher sets
to use for WUI access. Multiple
ciphers can be specified using a
space or comma separated list.
Also, setting this parameter
value to an empty string will
select the default value (that is,
a combination of ciphers TLS_

194

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

AES_256_GCM_SHA384, TLS_
CHACHA20_POLY1305_SHA256,
and TLS_AES_128_GCM_
SHA256).

The list of supported TLS1.3
Ciphers is as follows:

- TLS_AES_256_GCM_SHA384

- TLS_CHACHA20_POLY1305_
SHA256

- TLS_AES_128_GCM_SHA256

- TLS_AES_128_CCM_8_SHA256

- TLS_AES_128_CCM_SHA256

When assigning multiple
certificates for WUI
authentication, the certificates
must be specified in a single
space-separated list.

Enables or disables session
control.

If the sessioncontrol and
sessionbasicauth parameters
are both enabled, there are two
levels of authentication
enforced to access the
LoadMaster WUI. The initial level
is Basic Authentication where
users log in using the bal or user
logins, which are default
usernames defined by the
system.

Specifies the number of seconds
that the WUI can be idle before
logging the user out. This can be
set from 60 to 86400 seconds.

WUICACertList

sessioncontrol

S

B

sessionbasicauth

B

0 – Disabled

1 – Enabled

sessionidletime

I

60-86400

195

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

sessionmaxfailattempts

I

1-999

sessionconcurrent

S

0-9

WUIPreAuth

S

Up to 5,000 characters

WUITLSProtocols

I

0 – 30 bitmask

Number of failed attempts
before locking the user account.

Limit the maximum number of
concurrent logins that a single
user can have to the LoadMaster
WUI (a value of 0 means there is
no limit).

Set the pre-authentication click
through banner which will be
displayed before the LoadMaster
login page. This parameter can
contain plain text or HTML code.
The field cannot contain
JavaScript. Space characters
should be replaced with %20.

This field accepts up to 5,000
characters. Anything past the
5,000 character limit will not be
displayed.

Specify whether or not it is
possible to connect to the
LoadMaster WUI using the
following protocols; SSLv3,
TLS1.0, TLS1.1, TLS1.2, or
TLS1.3. The protocols can be
enabled and disabled using a
bitmask value. Refer to the
following table to find out which
number corresponds to which
settings.

Number

SSLv3

TLS1.0

TLS1.1

TLS1.2

TLS1.3

0

Enabled

Enabled

Enabled

Enabled

Enabled

196

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

1

2

3

4

5

6

7

8

9

10

11

12

13

14

15

16

17

18

19

20

21

22

23

24

25

Disabled

Enabled

Enabled

Enabled

Enabled

Enabled

Disabled

Enabled

Enabled

Enabled

Disabled

Disabled

Enabled

Enabled

Enabled

Enabled

Enabled

Disabled

Enabled

Enabled

Disabled

Enabled

Disabled

Enabled

Enabled

Enabled

Disabled

Disabled

Enabled

Enabled

Disabled

Disabled

Disabled

Enabled

Enabled

Enabled

Enabled

Enabled

Disabled

Enabled

Disabled

Enabled

Enabled

Disabled

Enabled

Enabled

Disabled

Enabled

Disabled

Enabled

Disabled

Disabled

Enabled

Disabled

Enabled

Enabled

Enabled

Disabled

Disabled

Enabled

Disabled

Enabled

Disabled

Disabled

Enabled

Enabled

Disabled

Disabled

Disabled

Enabled

Disabled

Disabled

Disabled

Disabled

Enabled

Enabled

Enabled

Enabled

Enabled

Disabled

Disabled

Enabled

Enabled

Enabled

Disabled

Enabled

Disabled

Enabled

Enabled

Disabled

Disabled

Disabled

Enabled

Enabled

Disabled

Enabled

Enabled

Disabled

Enabled

Disabled

Disabled

Enabled

Disabled

Enabled

Disabled

Enabled

Disabled

Disabled

Enabled

Disabled

Disabled

Disabled

Disabled

Enabled

Disabled

Enabled

Enabled

Enabled

Disabled

Disabled

Disabled

Enabled

Enabled

Disabled

Disabled

197

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

26

27

28

29

30

Enabled

Disabled

Enabled

Disabled

Disabled

Disabled

Disabled

Enabled

Disabled

Disabled

Enabled

Enabled

Disabled

Disabled

Disabled

Disabled

Enabled

Disabled

Disabled

Disabled

Enabled

Disabled

Disabled

Disabled

Disabled

3.12.6 OCSP Configuration

Parameters relating to the Online Certificate Status Protocol (OCSP) configuration that can be
managed using get and set commands are detailed in the table below. Refer to the Using get and
set commands section for details on the get and set commands.

Name

Type

Additional Information

OCSPPort

OCSPUseSSL

OCSPOnServerFail

OCSPServer

OCSPUrl

OCSPcertChecking

I

B

B

A

S

B

SSLStapling

B

The port of the OCSP server.

Use SSL to connect to the OCSP server.

Treat an OCSP server connection failure or timeout as if the OCSP
server had returned a valid response, that is, treat the client
certificate as valid.

The address of the OCSP server. This can either be in IP address or
Fully Qualified Domain Name (FQDN) format.

The URL to access on the OCSP server.

Enabling the OCSPcertChecking parameter enables the LoadMaster
to perform OCSP checks on certain outbound connections. This is
disabled by default.

Enable this parameter to enable the LoadMaster to respond to OCSP
stapling requests. If a client connects using SSL and asks for an
OCSP response, this is returned. Only Virtual Service certificates are
validated. The system holds a cache of OCSP responses that are sent
back to the client. This cache is maintained by the OCSP daemon.
When the OCSP daemon sends a request to the server, it uses the
name specified in the certificate (in the Authority Information
Access field). If it cannot resolve this name, then it uses the default
OCSP server specified in the OCSPServer parameter.

198

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

SSLRefreshInterval

I

Specify how often the LoadMaster should refresh the OCSP stapling
information. The OCSP daemon caches the entry for up to the
amount of time specified here, after which it is refreshed.

Valid values range from 3600 (1 hour (default)) to 86400 seconds (24
hours).

3.12.7 LDAP Configuration

Refer to the sections below for details about the different RESTful API commands relating to LDAP
endpoint configuration.

3.12.7.1 Add an LDAP Endpoint

Add a new LDAP endpoint by running the following command:

https://<LoadMasterIPAddress>/access/addldapendpoint?name=<LDAPEndpointName>

The name cannot contain any spaces or special characters, for
example:
!@#$%^^&*()+={}[]|\:;"'<>?/

You can also specify the following optional parameters when running the addldapendpoint
command. If you do not specify these parameters – default values are used.

Name

Type

Description

Additional Information

ldaptype

server

vinterval

I

S

I

Specify the transport
protocol to use when
communicating with the
LDAP server.

0 – Unencrypted (default)

1 – StartTLS

2 – LDAPS

Specify the address, or
addresses, of the LDAP
server to be used.

You can also specify a port number, if
desired. Separate multiple addresses with a
space.

Specify how often to
revalidate the user the with
the LDAP server.

Range:

10 – 86400 seconds

Default: 60

199

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

referralcount

I

The LoadMaster offers beta
functionality to support
LDAP referral replies from
Active Directory Domain
Controllers. If this is set to
0, referral support is not
enabled. Set this field to a
value between 1 and 10 to
enable referral chasing. The
number specified will limit
the number of hops
(referrals chased).

Multiple hops may increase authentication
latency. There is a performance impact that
depends on the number and depth of
referrals required in your configuration.

You must have intimate knowledge of your
Active Directory structure to set the referral
limit appropriately. The same credentials are
used for all lookups, and so on.

The use of Active Directory Global Catalog
(GC) is the preferred configuration as the
primary means of resolution instead of
enabling LDAP referral chasing. A GC query
can be used to query the GC cache instead of
relying on LDAP and the referral process.
Using Active Directory GC has little or no
performance drag on the LoadMaster. For
steps on how to add/remove the GC, refer to
the following TechNet article:
https://technet.microsoft.com/en-
us/library/cc755257(v=ws.11).aspx

timeout

adminuser

adminpass

I

S

S

Specify the LDAP server
timeout in seconds.

The default value is 5. Valid values range
from 5 to 60.

Specify the username of an
administrator user.

The username that is used to check the LDAP
server.

Specify the password for
the specified administrator
user.

The password that is used to check the LDAP
server.

3.12.7.2 Modify an LDAP Endpoint

Modify an existing LDAP endpoint by running the following command:

https://<LoadMasterIPAddress>/access/modifyldapendpoint?name=<LDAPEndpointNam
e>

You can also specify the following optional parameters when running the modifyldapendpoint
command.

200

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

Name

Type

Description

Additional Information

ldaptype

server

vinterval

I

S

I

Specify the transport protocol to
use when communicating with the
LDAP server.

0 – Unencrypted (default)

1 – StartTLS

2 – LDAPS

Specify the address, or addresses,
of the LDAP server to be used.

You can also specify a port number, if
necessary. Separate multiple
addresses with a space.

Specify how often to revalidate
the user with the LDAP server.

referralcount

I

The LoadMaster offers beta
functionality to support LDAP
referral replies from Active
Directory Domain Controllers. If
this is set to 0, referral support is
not enabled. Set this field to a
value between 1 and 10 to enable
referral chasing. The number
specified will limit the number of
hops (referrals chased).

Range:

10 – 86400 seconds

Default: 60

Multiple hops may increase
authentication latency. There is a
performance impact that depends on
the number and depth of referrals
required in your configuration.

You must have intimate knowledge of
your Active Directory structure to set
the referral limit appropriately. The
same credentials are used for all
lookups, and so on.

The use of Active Directory Global
Catalog (GC) is the preferred
configuration as the primary means of
resolution instead of enabling LDAP
referral chasing. A GC query can be
used to query the GC cache instead of
relying on LDAP and the referral
process. Using Active Directory GC has
little or no performance drag on the
LoadMaster.

timeout

I

Specify the LDAP server timeout in
seconds.

The default value is 5. Valid values
range from 5 to 60.

201

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

adminuser

adminpass

S

S

Specify the username of an
administrator user.

The username that is used to check
the LDAP server.

Specify the password for the
specified administrator user.

The password that is used to check
the LDAP server.

3.12.7.3 Delete an LDAP Endpoint

Delete an existing LDAP endpoint by running the following command:

https://<LoadMasterIPAddress>/access/deleteldapendpoint?name=<LDAPEndpointNam
e>

It is not possible to delete an LDAP endpoint that is currently in
use.

3.12.7.4 Retrieve Details of All LDAP Endpoints

To retrieve the details of all existing LDAP endpoints, run the following command:

https://<LoadMasterIPAddress>/access/showldaplist

3.12.7.5 Retrieve Details of a Specific LDAP Endpoint

To retrieve the details of a specific LDAP endpoint, run the following command:

https://<LoadMasterIPAddress>/access/showldapendpoint?name=<LDAPEndpointName>

3.12.8 Intrusion Detection Options (IPS/IDS)

The Intrusion Detection Rules can be updated using the following command:

https://<LoadMasterIPAddress>/access/updatedetect

There are a number of methods of using this command for example, using a CURL command on
Linux would look like the following:

curl –X POST -–data-binary “@<Detection Rules File>” –k
https://<LoadMasterIPAddress>/access/updatedetect

The above example would install new detection rules (<Detection Rules File>) on the system.

Related parameters that can be managed using get and set commands are detailed in the following
table. Refer to the Using get and set commands section for the get and set commands.

Name

Type

Range

Description

paranoia

I

0 = Low

Sets the sensitivity of the Intrusion Detection System (IDS)
detection.

202

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

1 = Default

2 = High

3 =
Paranoid

3.13 Interfaces

3.13.1 Get Interface Details

Obtain interface details by using the following command:

https://<LoadMasterIPAddress>/access/showiface?interface=<InterfaceID>

To view the interface ID for each of the interfaces, run the stats command. The interface IDs are
displayed as the ifaceID in the XML output. For further information on the stats command, refer to
the Statistics section.

Running the showiface command without using the interface parameter displays details for all
existing interfaces.

3.13.2 Modify Interface Details

Interface parameters can be changed using the following command:

https://<LoadMasterIPAddress>/access/modiface?interface=<InterfaceID>&<parame
ter>=<value>

Only one parameter can be changed on each call. The
parameters are checked in the order below.

Name

Typ
e

Description

Additional Information

interface

I

addr

mtu

S

I

The
number of
the
interface to
modify

IP address

To view the interface ID for each of the interfaces, run the stats
command. The interface IDs are displayed as the ifaceID in the
XML output. For further information on the stats command, refer
to the Statistics section.

Specify the internet address of this interface.

MTU size

Change the maximum size of the Ethernet frame that will be sent
from this interface.

203

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

Range: 512-
9216

0 – Not
used for
HA/cluster
checks

1 – Used for
HA/cluster
checks

Use this
interface
for cluster
synchroniza
tion
operations.

Use this
interface as
the default
gateway

0 - Disabled

1 - Enabled

1 = active-
backup

4 = 802.3ad

IP address
of the
partner
machine
(HA only)

IP address
of the
shared
address (HA
only)

hacheck

B

clupdate

B

gwiface

B

bondmode

I

partner

A

shared

A

This parameter is only relevant in a HA/cluster configuration.
Specify whether or not to use this interface for HA/cluster checks.

The default interface used for checking is eth0. When this option
is enabled for an interface, you are prevented from disabling it on
that interface. To switch to another interface, specify
hacheck=yes/1 for a different interface. You cannot disable this
parameter by specifying hacheck=no/0.

There must be exactly one interface that is configured for cluster
updates. The default interface used for updates is eth0. When this
option is enabled for an interface, you are prevented from
disabling it on that interface. To switch to another interface,
specify clupdate=yes/1 for a different interface. You cannot
disable this parameter by specifying clupdate=no/0.

Specifies if this is a network gateway interface.

If enabling this option, you must then run the following
command:

https://<LoadMasterIPAddress>/access/set?param=dfl
tgw&value=<NewIPAddress>

The bondmode determines the way in which traffic sent out of the
bonded interface is actually dispersed over the real interfaces.

This parameter is only relevant for LoadMasters in HA mode

This parameter is only relevant for LoadMasters in HA mode

204

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

adminwuie
nable

B

geotraffic

B

This option
can only be
set to yes
(1) if the
multihome
dwui
parameter
is set to
yes.

0 – Do not
use for GEO
requests
and
responses

1 – Use for
GEO
requests
and
responses

When both of the adminwuienable and multihomedwui
parameters are enabled, the WUI can be accessed from the IP
address of the relevant interface, and any Additional addresses
set up for that interface.

Refer to the Remote Access section for further information on the
multihomedwui parameter.

Specify whether or not to use this interface for GEO responses
and requests.

3.13.3 Additional Addresses

Additional Addresses can be added to an interface by using the command

https://<LoadMasterIPAddress>/access/addadditional?interface=<InterfaceID>&ad
dr=<AdditionalAdressIP/prefix>

Additional Addresses can be deleted from an interface by using the command

https://<LoadMasterIPAddress>/access/deladditional?interface=<InterfaceID>&ad
dr=<AdditionalAdressIP/prefix>

3.13.4 Bonded Interfaces

A bonded interface can be created by using the following command:

https://<LoadMasterIPAddress>/access/createbond?interface=<InterfaceID>

An interface can be added to a bonded interface by using the following command:

https://<LoadMasterIPAddress>/access/addbond?interface=<InterfaceID>&bond=<Bo
ndID>

An interface can be removed from a bonded interface by using the following command:

205

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

https://<LoadMasterIPAddress>/access/delbond?interface=<InterfaceID>&bond=<Bo
ndID>

A bond can be converted back to a port by using the following command:

https://<LoadMasterIPAddress>/access/unbond?interface=<InterfaceID>

To view the interface ID for each of the interfaces, run the stats command. The interface IDs are
displayed as the ifaceID in the XML output. For further information on the stats command, refer to
the Statistics section.

The BondID is the number of the bond in the Interfaces section of the main menu in the WUI. For
example, bnd2 will have a BondID of 2.

3.13.5 VLANs

A new VLAN can be added to an interface using the following command:

https://<LoadMasterIPAddress>/access/addvlan?interface=<InterfaceID>&vlanid=<
ID>

A VLAN can be removed from an interface using the following command:

https://<LoadMasterIPAddress>/access/delvlan?interface=<InterfaceID>&vlanid=<
ID>

3.13.6 VXLANs

A VXLAN can be added by running one of the following commands:

https://<LoadMasterIPAddress>/access/addvxlan?interface=<InterfaceID>&vni=<VX
LANNetworkIdentifier>&group=<GroupMulticastIP>
https://<LoadMasterIPAddress>/access/addvxlan?interface=<InterfaceID>&vni=<VX
LANNetworkIdentifier>&remote=<RemoteVTEPIPAddress>

A VXLAN can be deleted by running the following command:

https://<LoadMasterIPAddress>/access/delvxlan?interface=<InterfaceID>

To modify VXLAN details (for example set the IP address) please use the modiface command. For
more information, refer to the Running the showiface command without using the interface
parameter displays details for all existing interfaces. section.

To retrieve VXLAN details, use the showiface command. For more information, refer to the Get
Interface Details section.

3.14 Host & DNS Configuration

Some parameters relating to Host & DNS Configuration can be managed using the get and set
commands, for example:

https://<LoadMasterIPAddress>/access/get?param=hostname

206

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

Name

Type

Additional Information

Hostname

ha1hostname

ha2hostname

namserver

nameserver

searchlist

S

S

S

A

A

S

dnssecclient

B

Set the hostname of the local machine.

Set the hostname for the active LoadMaster

Set the hostname for the standby LoadMaster

The IP address of a DNS server which is to be used to resolve names
locally on the LoadMaster. Setting this parameter to an empty string
will delete the name servers. The last remaining name server cannot
be deleted if the dnssecclient parameter is enabled.

This parameter has been deprecated and replaced with the
nameserver parameter.

The IP address of a DNS server which is to be used to resolve names
locally on the LoadMaster. Setting this parameter to an empty string
will delete the name servers. The last remaining name server cannot
be deleted if the dnssecclient parameter is enabled.

Specify the domain name that is to be prepended to requests to the
DNS name server.

Enable or disable DNSSEC client capabilities on the LoadMaster. At
least one name server must be configured before DNSSEC can be
enabled. After changing this setting, the LoadMaster must be
rebooted for the change to be applied. Once the setting is changed,
it cannot be changed again until the LoadMaster has been rebooted.
If using HA, please set the parameter on both devices separately.

0 - Disabled

1 – Enabled

When this option is enabled, the LoadMaster automatically attempts
to update any changedDNS names (based on the update interval)::

If the address is not found, or if it is the same as before – nothing
is done (except a log entry is generated).

If the address is different, the Real Server entry will be updated
with the new address, if possible.

If the new address is invalid for some reason, for example if it is a

DNSNamesEnable

B

207

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

dnsupdateinterval

dnsreloadonerror

I

B

non-local address and the nonlocalrs option has been disabled,
no changes are made and a log is generated.

Set the update interval for DNS entries. Valid values range from 1 to
60 (minutes). The default value is 60.

If this parameter is enabled, DNS entries are reloaded when health
checks have errors and an FQDN is associated with the Real Server
IP address.

3.14.1 Resolve DNS Names Now

To force a new resolution of DNS names, run the resolvenow command, for example:

https://<LoadMasterIPAddress>/access/resolvenow

The LoadMaster will try to resolve the DNS names:

If the address is not found or if it is the same as before – nothing is done (except a log entry is
generated).

If the address is different, the Real Server entry will be updated with the new address, if
possible.

If the new address is invalid for some reason, for example if it is a non-local address and the
nonlocalrs parameter has been disabled, no changes are made and a log is generated. The log is
found in the normal syslog messages. The message "DNS update failed" appears and includes
the reason why. It is a descriptive error message based on what is incorrect.

3.14.2 Hosts for Local Resolution

To list the existing hosts for local resolution, run the gethosts command, for example:

https://<LoadMasterIPAddress>/access/gethosts

To add a host IP address and host FQDN, run the addhostsentry command, using the following
format:

https://<LoadMasterIPAddress>/access/addhostsentry?hostip=<HostIPAddress>&hos
tfqdn=<HostFQDN>

To delete a host IP address and host FQDN, run the delhostsentry command, using the following
format:

https://<LoadMasterIPAddress>/access/delhostsentry?hostip=<HostIPAddress>

208

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

3.15 Route Management

3.15.1 Default Gateway

Parameters relating to Route Management that can be managed using get and set commands, for
example:

https://<LoadMasterIPAddress>/access/get?param=dfltgw

Before setting the default gateway, the network interface addresses must be configured, for
example:

https://<LoadMasterIPAddress>/access/modiface?interface=<ifaceID>&gwiface=1

Name

Type

Default

Additional Information

dfltgw

dfltgwv6

A
(IPv4)

A
(IPv6)

<unset>

<unset>

Specify the IPv4 default gateway that is to be used for
communicating with the internet.

Specify the IPv6 default gateway that is to be used for
communicating with the internet.

3.15.2 Additional Routes

Existing Additional Routes can be listed by running the following command:

https://<LoadMasterIPAddress>/access/showroute

Additional Routes can be added or deleted with the following commands:

https://<LoadMasterIPAddress>/access/addroute?dest=<DestIPAddress>&gateway=<G
atewayIPAddress>
https://<LoadMasterIPAddress>/access/delroute?dest=<DestIPAddress>

3.15.3 Packet Routing Filter

The commands in this section relate to the global packet routing filter option. Packet filtering is
enabled by default. It is not possible to disable the packet routing filter if GEO is enabled. Refer to
the IP Access List Settings section for commands on enabling and disabling GEO.

To check if the packet routing filter is enabled or not, run the following command:

https://<LoadMasterIPAddress>/access/aclcontrol?isenabled

To enable/disable the packet routing filter, run the following command:

https://<LoadMasterIPAddress>/access/aclcontrol?enable=<0/1>

209

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

It is not possible to disable the packet routing filter if GEO is
enabled. If you try to disable the packet routing filter with GEO
enabled, you get the following error:
Cannot disable aclcontrol while GSLB is enabled

The following parameters can only be set if the packet filter is enabled.

Check if the connection is dropped or rejected when it is on the block list:

https://<LoadMasterIPAddress>/access/aclcontrol?isdrop

Enable dropping of block list entries:

https://<LoadMasterIPAddress>/access/aclcontrol?drop=1

Disable dropping of block list entries:

https://<LoadMasterIPAddress>/access/aclcontrol?drop=0

When the Restrict traffic to Interfaces option is enabled, restrictions are enforced upon routing
between attached subnets. To check if the Restrict traffic to Interfaces option is enabled or
disabled, run the following command:

https://<LoadMasterIPAddress>/access/aclcontrol?isifblock

Block - enabled

Free - disabled

To enable the Restrict traffic to Interfaces option:

https://<LoadMasterIPAddress>/access/aclcontrol?ifblock=1

To disable the Restrict traffic to Interfaces option:

https://<LoadMasterIPAddress>/access/aclcontrol?ifblock=0

If the Include WUI in IP Access Lists option is enabled, access to the WUI is also controlled by the
packet filter. In this case, the client that enabled the Include WUI in IP Access Lists option will still
have access. If this option is disabled, access to the WUI is not affected by the packet filter.

To check if Include WUI in IP Access Lists is enabled or disabled, run the following command:

https://<LoadMasterIPAddress>/access/aclcontrol?iswuiblock

To enable the Include WUI in IP Access Lists option, run the following command:

https://<LoadMasterIPAddress>/access/aclcontrol?wuiblock=1

To disable the Include WUI in IP Access Lists option, run the following command:

210

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

https://<LoadMasterIPAddress>/access/aclcontrol?wuiblock=0

To check the IP address of the last client that changed the packet filter (that is, the host that is
allowed in), run the following command:

https://<LoadMasterIPAddress>/access/aclcontrol?wuiaddr

The wuiaddr command is only relevant if the Include WUI in IP
Access Lists option is enabled.

3.15.4 VPN Management

3.15.4.1 Create a New VPN Connection

To create a new Virtual Private Network (VPN) connection, run the following command:

https://<LoadMasterIPAddress>/access/createvpncon?name=<VPNname>

3.15.4.2 Delete an Existing IPsec Connection

An existing IPsec connection can be deleted by running the following command:

https://<LoadMasterIPAddress>/access/deletevpncon?name=<VPNname>

3.15.4.3 Set the VPN Addresses

The VPN addresses can all be set at the same time by running the following command:

https://<LoadMasterIPAddress>/access/setvpnaddr?name=<VPNname>&localip=<
LocalIPAddress>&localsubnets=<LocalSubnetAddress
(es)>&remoteip=<RemoteIPAddress>&remotesubnets=<RemoteSubnetAddress(es)>

All of the parameters listed below are required when running the setvpnaddr command:

Name

Type

Default

Additional Information

localip

String

localsubnets

String

See
additional
information

See
additional
information

In non-HA mode, the default is the LoadMaster IP
address, that is, the IP address of the default gateway
interface.

In HA-mode, the default is the shared IP address.

Set the subnet for the local side of the connection. The
local IP can be the only participant if applicable, given
the /32 CIDR. When the localip is set, the localsubnet is
automatically populated. Multiple local subnets can be
specified using a comma-separated list. Up to 10 IP
addresses can be specified.

211

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

remoteip

String

<unset>

Set the IP address for the remote side of the connection.

remotesubnets

String

<unset>

Set the subnet for the remote side of the connection.
Multiple remote subnets can be specified using a
comma-separated list. Up to 10 IP addresses can be
specified.

These parameters can also be set individually by running the commands listed below.

To set the Local IP Address, run the command below:

https://<LoadMasterIPAddress>/access/setvpnlocalip?name=<VPNname>&localip=<Lo
calIPAddress>

To set the Local Subnet Address, run the command below:

https://<LoadMasterIPAddress>/access/setvpnlocalsubnet
s?name=<VPNname>&localsubnets=<LocalSubnetAddress(es)>

To set the Remote IP Address, run the command below:

https://<LoadMasterIPAddress>/access/setvpnremoteip?name=<VPNname>&remoteip=<
RemoteIPAddress>

To set the Remote Subnet Address, run the command below:

https://<LoadMasterIPAddress>/access/setvpnremotesubnet
s?name=<VPNname>&remotesubnets=<RemoteSubnetAddress(es)>

3.15.4.4 Set the Perfect Forward Secrecy Option

To enable the Perfect Forward Secrecy option on a particular connection, run the command below:

https://<LoadMasterIPAddress>/access/setvpnpfsenable?name=<ConnectionName>

To disable the Perfect Forward Secrecy option on a particular connection, run the command
below:

https://<LoadMasterIPAddress>/access/setvpnpfsdisable?name=<ConnectionName>

3.15.4.5 Set the Connection Secret

To set the connection secret details, run the command below:

https://<LoadMasterIPAddress>/access/setvpnsecret?name=<VPNname>&localid=<Loc
alID>&remoteid=<RemoteID>&key=<PreSharedKey>

All of the parameters are required for this command to work.

Name

Type

Default

Additional Information

localid

String

Same as

Identification for the local side of the connection

212

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

the
localip

remoteid

String

<unset>

Identification for the remote side of the connection. This can be
the remoteip.

key

String

<unset>

The Pre Shared Key (PSK) string. This is the Shared key which is
generated and managed on the Azure side. The key length should
be at least 16 and at most 64 characters.

3.15.4.6 Start the Connection

To start the connection, run the command below:

https://<LoadMasterIPAddress>/access/startvpncon?name=<VPNname>

3.15.4.7 Stop the Connection

To stop the connection, run the command below:

https://<LoadMasterIPAddress>/access/stopvpncon?name=<VPNname>

3.15.4.8 Get the Connection Status

To view the status of the connection, run the command below:

https://<LoadMasterIPAddress>/access/getvpnstatus?name=<VPNname>

3.15.4.9 List All Existing Connections

To list the details about all of the existing VPN connections, run the command below:

https://<LoadMasterIPAddress>/access/listvpns

3.15.4.10 Stop the IKE Daemon

To stop the Internet Key Exchange (IKE) daemon, run the command below:

https://<LoadMasterIPAddress>/access/stopikedaemon

3.15.4.11 Start the IKE Daemon

To start the IKE daemon, run the command below:

https://<LoadMasterIPAddress>/access/startikedaemon

3.15.4.12 Get the IKE Daemon Status

To view the status of the IKE daemon, run the command below:

https://<LoadMasterIPAddress>/access/statusikedaemon

213

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

3.16 Access Lists

The Access Control List (ACL) commands allow you to switch on
or off the ACL and set or get the related parameters. When
running an ACL command without a specified Virtual Service IP
address, the command is run for the global ACL. If a Virtual
Service IP address is set, the command is only run for the ACL
for that specific Virtual Service.

Only users with ‘All Permissions’ can run the global commands.

Users with ‘All Permissions’ and ‘Virtual Service’ permissions
can run the Virtual Service-specific commands.

Show the addresses on the global black or white list:

https://<LoadMasterIPAddress>/access/aclcontrol?list=<ListType>

List Type

block

allow

Add/remove an address to/from the global block or allow list:

https://<LoadMasterIPAddress>/access/aclcontrol?add=<ListType>&addr=<IPAddres
s/CIDR>
https://<LoadMasterIPAddress>/access/aclcontrol?del=<ListType>&addr=<IPAddres
s/CIDR>

The addr can be an IPv4 or an IPv6 address. If the CIDR is not
specified, the system uses a default of /32.

For the three commands below, you can either use the socket information (the IP address, port, and
protocol of the Virtual Service) or the Virtual Service index to specify the Virtual Service to run the
command on.

To retrieve the Virtual Service index, run the listvs command, for example:

https://<LoadMasterIPAddress>/access/listvs

List the block or allow list for a specific Virtual Service:

214

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

https://<LoadMasterIPAddress>/access/aclcontrol?listvs=<ListType>&vsip=<Virtu
alServerIPAddress>&vsprot=<VirtualServerProtocol>&vsport=<VirtualServerPort>

Virtual Server Protocol

tcp

udp

If the CIDR is not specified, the system will use its own default
value which is /32.

You can also use the Virtual Service index to specify the Virtual Service, for example:

https://<LoadMasterIPAddress>/access/aclcontrol?listvs=<ListType>&vs=<Virtual
ServiceIndex>

Add/remove an address to/from a Virtual Service block or allow list:

https://<LoadMasterIPAddress>/access/aclcontrol?addvs=<ListType>&vsip=<Virtua
lServerIPAddress>&vsprot=<VirtualServerProtocol>&vsport=<VirtualServerPort>&a
ddr=<IPAddressToAdd/CIDR>&comment=<Comment>

You can also use the Virtual Service index to specify the Virtual Service, for example:

https://<LoadMasterIPAddress>/access/aclcontrol?addvs=<ListType>&vs=<VirtualS
erviceIndex>&addr=<IPAddressToAdd/CIDR>&comment=<Comment>

The comment parameter is optional. The comment parameter accepts a maximum of 127
characters.

https://<LoadMasterIPAddress>/access/aclcontrol?delvs=<ListType>&vsip=<Virtua
lServerIPAddress>&vsprot=<VirtualServerProtocol>&vsport=<VirtualServerPort>&a
ddr=<IPAddressToRemove/CIDR>

You can also use the Virtual Service index to specify the Virtual Service, for example:

https://<LoadMasterIPAddress>/access/aclcontrol?delvs=<ListType>&vs=<VirtualS
erviceIndex>&addr=<IPAddressToAdd/CIDR>&comment=<Comment>

3.17 Cluster Control

Clustering can be configured using API commands. For details on each of the commands that can be
used, refer to the sections below.

The clustering API commands are only available on
LoadMasters which have a clustering license. To add the
clustering feature to your license, please contact a Kemp

215

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

representative. For further information on clustering, refer to
the LoadMaster Clustering, Feature Description.

3.17.1 Clustering API Commands

The sections below provide details on each of the RESTful API commands relating to clustering. For
step-by-step instructions on how to configure clustering using the RESTful API, refer to the RESTful
API Clustering Example section.

3.17.1.1 Get the Status of the Cluster

To retrieve the status of the cluster, run the command below:

https://<LoadMasterIPAddress>/access/cluster/status

The details for all nodes in the cluster is returned. It lists all the enabled nodes in the cluster in XML
format, for example:

<Response stat="200" code="ok">

<Success>

<Data>

<Status>

<SharedAddress>10.35.47.100</SharedAddress>

<Node>

<Id>1</Id>

<Address>10.35.47.7</Address>

<Enabled>1</Enabled>

<Status>5</Status>

</Node>

<Node>

<Id>2</Id>

<Address>10.35.47.8</Address>

<Enabled>0</Enabled>

<Status>2</Status>

</Node>

</Status>

</Data>

</Success>

</Response>

If the LoadMaster is not in a cluster an error message will be returned using the WUI.

216

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

The status is represented by a number, as follows:

l 0 – The node is down

l 1 – The node is up

l 2 – The node is disabled - connections will not be sent to that node. If there are no Virtual

Services in the node, the node will be in a Disabled state.

l 3 – The node has been disabled and the connections are being shut down in an orderly

fashion. Drain stopping lasts for 10 seconds by default.

l 4 – The node is starting

l 5 – The node is the primary control node.

3.17.1.2 Create a Cluster

If a LoadMaster is not in currently in cluster mode, it can be converted to cluster mode by running
the command below:

https://<LoadMasterIPAddress>/access/cluster/create?SharedAddress=<SharedIPAd
dress>

3.17.1.3 Initiate a Node Joining a Cluster

To initiate a node joining a cluster, run the following command on the LoadMaster:

https://<LoadMasterIPAddress>/access/cluster/joincluster

Running this command will make the LoadMaster available to
be added to the cluster. To finish adding the node, please run
the addnode command. Refer to the Add a Node to the
Cluster section for further information.

3.17.1.4 Add a Node to the Cluster

Before running this command, the node LoadMaster needs to be available to be added. To make the
node LoadMaster available, run the joincluster command on the node LoadMaster. Refer to the
Initiate a Node Joining a Cluster section for further information on the joincluster command.

If the addnode command is run when the node LoadMaster is
not available to be added, an error will be returned which says
that the machine could not be contacted.

217

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

To add a node to the cluster (while the node LoadMaster is available to be added), run the following
command on the shared IP address:

https://<LoadMasterIPAddress>/access/cluster/addnode?Address=<NodeIPAddress>

3.17.1.5 Enable a Node

When a node is first added to the cluster it is disabled by default. To enable a node, run the
following command:

https://<LoadMasterIPAddress>/access/cluster/enablenode?nodeid=<NodeID>

The ID of the node can be found in the ID column in the Cluster Control screen in the LoadMaster
WUI, or by running the status command (refer to the Get the Status of the Cluster section for
further details).

3.17.1.6 Disable a Node

To disable a node, run the following command:

https://<LoadMasterIPAddress>/access/cluster/disablenode?nodeid=<NodeID>

The ID of the node can be found in the ID column in the Cluster Control screen in the LoadMaster
WUI, or by running the status command (refer to the Get the Status of the Cluster section for
further details).

3.17.1.7 Delete a Node

To delete a node from a cluster, run the command below:

https://<LoadMasterIPAddress>/access/cluster/deletenode?NodeId=<NodeID>

The ID of the node can be found in the ID column in the Cluster Control screen in the LoadMaster
WUI, or by running the status command (refer to the Get the Status of the Cluster section for
further details).

3.17.2 RESTful API Clustering Example

The sections above provide details relating to each of the clustering RESTful API commands. This
section provides step-by-step instructions on how to create a cluster and add a node to it, using
these API commands. The example IP addresses which are used in the example commands are
below:

LoadMaster 1: 10.154.11.10

LoadMaster 2: 10.154.11.20

Shared IP Address: 10.154.11.30

Node ID: 2

218

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

Follow the steps below in sequential order to create a cluster and add a node to it:

1. Create a cluster. Run this command on LoadMaster 1:

https://10.154.11.10/access/cluster/create?SharedAddress=10.154.11.30

2. Initiate the node (LoadMaster 2) joining a cluster. Run this command on LoadMaster 2:

https://10.154.11.20/access/cluster/joincluster

3. Add the node (LoadMaster 2) to the cluster. Run this command on LoadMaster 1:

https://10.154.11.10/access/cluster/addnode?Address=10.154.11.20

The addnode command must be run while the node
LoadMaster is available to join the cluster. This command
should be run immediately after the joincluster command.

If the addnode command is run when the node LoadMaster is
not available to be added, an error will be returned which says
that the machine could not be contacted.

4. Enable the node. Run this command on LoadMaster 1:

https://10.154.11.10/access/cluster/enablenode?nodeid=2

3.18 QoS/Limiting

This section contains details about the QoS/Limiting API commands and parameters. You can
retrieve or configure each of these parameters using the get or set RESTful API commands.

Here is an example of a get command to retrieve the MaxConnsLimit parameter value:

/access/get?param=MaxConnsLimit

Here is an example of a set command to set the MaxConnsLimit to 80000:

/access/set?param=MaxConnsLimit&value=80000

The following limiting parameters can be retrieved or configured using the get or set commands:

l MaxConnsLimit: The maximum number of simultaneous connections (TCP and UDP).

l MaxCPSLimit: The global connection limit (per second).

l MaxRPSLimit: The global request limit (per second).

l MaxBandwidthLimit: The global bandwidth limit (kilobits per second)

219

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

l SendRateLimitError: This parameter accepts the following values:

l 0 - no error response (the connection is simply dropped)

l 1 - Send 429 Too Many Requests error response

l 2 - Send 503 Service Unavailable error response

l RateLimitFail: Fail on rate limit. This parameter accepts the following values:

l 0 - disabled the LoadMasterttempts to select a different RS or SubVS to use for the

connection)

l 1 - enabled (forces an error)

l LimitLogging: Generate a summary log entry every 5 seconds. This parameter accepts the

following values:

l 0 - disabled

l 1 - enabled

l ClientRepeatDelay: Set the minimum time after a client is no longer limited before a new
message is generated. If a client generates a message and continues to be blocked for
continuously hitting the limit, no new message is generated. Only if the client goes quiet for
the delay period will a new message be generated. Valid values range from 10 - 86400
seconds.

l ClientMaxConnsLimit: This limits the default maximum number of concurrent connection
attempts (per second) from a specific host. Setting the limit to 0 disables this option. Valid
values range from 0 - 1000000.

l ClientCPSLimit: The global client connection limit.

l ClientRPSLimit: The global client request limit.

l ClientMaxBandwidthLimit: The global client maximum bandwidth limit.

3.18.1 Maximum Client Concurrent Connection Limit

To list the existing client concurrent connection limits, run the clientmaxclimitlist command, for
example:

/access/clientmaxclimitlist

To add a new client concurrent connection limit, run the clientmaxclimitadd command, for
example:

/access/clientmaxclimitadd?l7addr=<Address>&l7limit=<Limit>

220

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

To delete an existing client concurrent connection limit, run the clientmaxclimitdel command, for
example:

/access/clientmaxclimitdel?l7addr=<Address>

3.18.2 Client CPS Limit

To list the existing Connections Per Second (CPS) limits, run the clientcpslimitlist command, for
example:

/access/clientcpslimitlist

To add a new CPS limit, run the clientcpslimitadd command, for example:

/access/clientcpslimitadd?l7addr=<Address>&l7limit=<Limit>

To delete an existing CPS limit, run the clientcpslimitdel command, for example:

/access/clientcpslimitdel?l7addr=<Address>

3.18.3 Legacy Client CPS Limit Commands

Before the rate limiting functionality was improved in LoadMaster version 7.2.52, you could run the
following commands relating to client CPS limits.

Although these commands still work - Kemp recommends using
the new commands outlined in the Client CPS Limit section
above.

Client limiting can be used to limit the default maximum number of connection attempts (per
second) from a specified host. The limit can be set using the set parameter, for example:

https://<LoadMasterIPAddress>/access/set?param=l7limitinput&value=25

Setting the limit to zero disables the option.

A number of addresses or networks can be specified to be limited. To add an address, run the
command below:

https://<LoadMasterIPAddress>/access/afeclientlimitadd?l7addr=<L7Address>&l7l
imit=<L7Limit>

To delete an address, run the command below:

https://<LoadMasterIPAddress>/access/afeclientlimitdel?l7addr=<L7Address>

To list the addresses and their limits, run the command below:

https://<LoadMasterIPAddress>/access/afeclientlimitlist?

221

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

3.18.4 Client RPS Limit

To list the existing RPS limits, run the clientrpslimitlist command, for example:

/access/clientrpslimitlist

To add a new RPS limit, run the clientrpslimitadd command, for example:

/access/clientrpslimitadd?l7addr=<Address>&l7limit=<Limit>

To delete an existing RPS limit, run the clientrpslimitdel command, for example:

/access/clientrpslimitdel?l7addr=<Address>

3.18.5 Client Bandwidth Limit

To list the existing client bandwidth limits, run the clientbandwidthlimitlist command, for example:

/access/clientbandwidthlimitlist

To add a new client bandwidth limit, run the clientbandwidthlimitadd command, for example:

/access/clientbandwidthlimitadd?l7addr=<Address>&l7limit=<Limit>

The global client maximum bandwidth limit
(ClientMaxBandwidthLimit) must be set before you add a
specific client bandwidth limit.

To delete an existing client bandwidth limit, run the clientbandwidthlimitdel command, for
example:

/access/clientbandwidthlimitdel?l7addr=<Address>

3.18.6 Per-Virtual Service Limits

To add a new Virtual Service with limits, run the addvs command, for example:

/access/addvs?vs=<VirtualServiceAddress>&port=<VirtualServicePort>&prot=<tcp/
udp>&ConnsPerSecLimit=<Limit>&RequestsPerSecLimit=<Limit>&MaxConnsLimit=<Limi
t>&bandwidth=<Limit>

To modify the limits for an existing Virtual Service, run the modvs command, for example:

/access/modvs?vs=<VirtualServiceAddress>&port=<VirtualServicePort>&prot=<tcp/
udp>&ConnsPerSecLimit=<Limit>&RequestsPerSecLimit=<Limit>&MaxConnsLimit=<Limi
t>&bandwidth=<Limit>

To modify the limits for an existing SubVS, run the modvs command, for example:

/access/modvs?vs=<SubVSIndex>&ConnsPerSecLimit=<Limit>&RequestsPerSecLimit=<L
imit>&MaxConnsLimit=<Limit>&bandwidth=<Limit>

222

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

You can retrieve the SubVS Index by running the listvs command or by checking the Id at the top of
the SubVS modify screen.

3.18.7 URL-Based Limiting Rules

You can list the existing URL-based limiting rules by running the listlimitrules command, for
example:

/access/listlimitrules

You can add a new URL-based limiting rule by running the addlimitrule command, for example:

/access/addlimitrule?name=ExampleRule&pattern=/test/a.html&limit=5&match=0

You can modify an existing URL-based limiting rule by running the modlimitrule command, for
example:

/access/modlimitrule?name=ExampleRule&pattern=/test/b.html&limit=5&match=0

Valid values for the match parameter are as follows:

l 0 - Request

l 1 - Host

l 2 - User Agent

l 64 - !Request

l 65 - !Host

l 66 - !UserAgent

The values with an exclamation mark (!) before them matches
the inverse, for example, not a specific request or not a specific
user agent.

You can delete an existing URL-based limiting rule by running the dellimitrule command, for
example:

/access/dellimitrule?name=ExampleRule

You can move the position of an existing URL-based limiting rule by running the movelimitrule
command, for example:

/access/movelimitrule?name=ExampleRule3&position=1

Setting the position parameter to a value larger than the size of the list will move the rule to the end
of the list.

223

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

3.19 System Administration

Various system administration tasks can be completed using the RESTful API.

3.19.1 User Management

3.19.1.1 Change the System Password

To change the password of the default bal user, run the command below:

https://<LoadMasterIPAddress>/access/usersetsyspassword?currpassword=<Current
Password>&password=<NewPassword>

3.19.1.2 Set the Minimum Password Length

To set the minimum password length for local users, run the command below:

https://<LoadMasterIPAddress>/access/set?param=minpassword&value=<8-16>

3.19.1.3 List All Local Users

To list all local users and their permissions, run the command below:

https://<LoadMasterIPAddress>/access/userlist

3.19.1.4 Display Permissions for a Particular Local User

To display permissions for a particular local user, run the command below:

https://<LoadMasterIPAddress>/access/usershow?user=<Username>

3.19.1.5 Add a New Local User

To add a new local user, run the command below:

https://<LoadMasterIPAddress>/access/useraddlocal?user=<Username>&password=<U
serPassword>

Name

Type

Description

user

String

The username of the new user.

password

String

The password of the new user.

Mandatory

Yes

Yes – unless
nopass or
radius is set
to yes.

radius

Boolean

Determines whether the user will use RADIUS server
authentication or not when logging in to the LoadMaster.
The RADIUS server details must be set up before this option

No

224

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

nopass

Boolean

can be enabled.

This option is only valid if session management is enabled.
Set this option to yes to create a user with no password.
This can be used to allow certificate-based access. For
further information, please refer to the Local Certificate
Management section.

No

3.19.1.6 Delete a Local User

To delete a local user, run the command below:

https://<LoadMasterIPAddress>/access/userdellocal?user=<Username>

3.19.1.7 Change the Password of a Local User

To change the password of a local user, run the command below:

https://<LoadMasterIPAddress>/access/userchangelocpass?user=<Username>&passwo
rd=<NewPassword>&radius=<0/1>

The username is case sensitive - ensure to enter the username
exactly as it has been set.

All parameters are required. The radius parameter determines whether the user will use RADIUS
server authentication or not when logging in to the LoadMaster. The RADIUS server details must be
set up before this option can be used.

3.19.1.8 Set Permissions for a Local User

To set permissions for a local user, run the command below:

https://<LoadMasterIPAddress>/access/usersetperms?user=<Username>&perms=<Comm
aSeparatedListOfPermissions>

Multiple permissions can be set at the same time by separating the values with a comma, for
example:

https://<LoadMasterIPAddress>/access/usersetperms?user=<Username>&perms=real,
vs

Running this command will overwrite any previous permissions
for this user. For example, if a user had the rules permission
and you ran the command listed above, the user would no

225

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

longer have the rules permission but would have the real and
vs permission.

Valid values for the perms parameter are listed and described in the table below.

Value

real

vs

rules

backup

certs

cert3

Description

This role permits enabling and disabling Real Servers. Users with the Real Servers
permission cannot add SubVSs.

This role relates to managing Virtual Services. This includes SubVSs. Virtual Service
actions permitted vary depending on whether or not the extendedperms parameter
is enabled. For further information, refer to the User Management Feature
Description on the Kemp Documentation Page.

This role permits managing Rules. Rule modifications permitted include add, delete
and modify.

This role permits performing system backups.

This role permits managing SSL Certificates. Certificate management includes
adding, deleting and modifying SSL Certificates.

This role permits managing intermediate Certificates. Certificate management
includes the ability to add and delete intermediate certificates.

certbackup

This role permits the ability to export and import certificates.

users

root

geo

addvs

This role is allowed access to all functionality within the System Configuration >
System Administration > User Management WUI screen.

This role gives users all permissions except the permission to change the bal
password and the permission to create or delete other users.

This role is used only with the LoadMaster GEO product. For more information on
GEO and the Global Server Load Balancing (GSLB) Feature Pack, refer to the GEO,
Feature Description on the Kemp Documentation Page.

This parameter can only be enabled if the extendedperms parameter is enabled.
This role relates to managing Virtual Services. This includes SubVSs. Refer to the
User Management Feature Description on the Kemp Documentation Page
for further details on the permissions provided by this option.

To set the permissions to none, leave the parameter blank, for example &perms=

226

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

3.19.1.9 Local Certificate Management

To return a previously generated certificate for a user, run the userreadcert command, in the
following format:

https://<LoadMasterIPAddress>/access/userreadcert?user=<Username>

To download a previously generated certificate for a user, run the userdownloadcert command:

https://<LoadMasterIPAddress>/access/userdownloadcert?user=<Username>

To generate a new certificate for a user, run the usernewcert command, in the following format:

https://<LoadMasterIPAddress>/access/usernewcert?user=<Username>&passphrase=<
Passphrase>

The passphrase is optional. If entered, it will be used to encrypt
the private key.

To delete an existing user certificate, run the userdelcert command, in the following format:

https://<LoadMasterIPAddress>/access/userdelcert?user=<Username>

3.19.1.10 Remote User Group Management

To return a list of existing groups and their associated permissions, run the grouplist command:

https://<LoadMasterIPAddress>/access/grouplist

To display permissions for a specific user group, run the groupshow command:

https://<LoadMasterIPAddress>/access/groupshow?group=<GroupName>

To add a new group, run the groupaddremote command:

https://<LoadMasterIPAddress>/access/groupaddremote?group=<GroupName>

The following characters are permitted in the group name:
alphanumeric characters, spaces, or the following special
symbols: =~^._+#,@/-.

To configure permissions for a group, run the groupsetperms command:

https://<LoadMasterIPAddress>/access/groupsetperms?group=<GroupName>&perms=<P
ermissions>

Enter a comma-separated list of permissions in the perms parameter. The valid values for the perms
parameter are the same as the ones for the usersetperms command, as outlined in the Set
Permissions for a Local User section.

To delete an existing group, run the groupdelremote command:

227

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

https://<LoadMasterIPAddress>/access/groupdelremote?group=<GroupName>

3.19.1.11 Extended Permissions Management

The Virtual Service operations permitted vary depending on whether or not the extendedperms
parameter is enabled. For further information, refer to the User Management Feature Description
on the Kemp Documentation Page.

The extendedperms parameter can be managed using the get and set commands. Refer to the
Using get and set commands for further information on how to use these commands. For example,
to display the value of the parameter, run the following command:

https://<LoadMasterIPAddress>/access/get?param=extendedperms

The extendedperms parameter is Boolean - set it to 1 to enable extended permissions, or 0 to
disable extended permissions.

3.19.2 Licensing

Similar to when initially licensing a LoadMaster, a license may be updated using the online or offline
method.

Offline licensing requires a Binary Large OBject (BLOB) file which is provided by Kemp.

When updating online, only a Kemp ID and password are needed.

For further information on licensing, refer to the Licensing, Feature Description.

3.19.2.1 License

The LoadMaster’s licence can be updated offline by using the license command.

The License BLOB is emailed to the customer when requested. Each time a license is updated a new
BLOB is needed.

The following is an example of a BLOB:

228

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

The BLOB is the body of text from the word begin to the word end, as is highlighted in the example
in the screenshot above. The BLOB must be copied and pasted into a text file (in the following
example the file is called license.txt). For more information on licensing (including details on how to
retrieve a BLOB), please refer to the Licensing, Feature Description.

There are a number of methods of using the license command for example, using a CURL command
on Linux would look like the following:

curl –X POST -–data-binary “@license.txt” –k
https://<LoadMasterIPAddress>/access/license

This command uploads the BLOB file to the LoadMaster. The example command above assumes that
the license.txt file is in the current directory. If the license.txt file is stored elsewhere, specify the
path to the file after the @ symbol.

229

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

3.19.2.2 AlsiLicense

The AlsiLicense command updates the LoadMaster’s license online. To cause the LoadMaster to
query the Kemp licensing system for an updated licence, and update the license if one is available,
run the following command:

https://<LoadMasterIPAddress>/access/alsilicense?kempid=<KempID>&password=<Ke
mpIDPassword>&lic_type_id=<LicenseTypeID>&orderid=<OrderID>

Name

Type

Description

Mandatory

kempid

String

The email address used when registering for a Kemp ID.

password

String

The Kemp ID account password.

http_proxy

String

Specify the HTTP(S) proxy server and port, in the format
<ProxyAddress>:<Port>.

lic_type_id String

The license type ID.

orderid

String

Specify the order ID received from Kemp.

Yes

Yes

No

No

Yes

3.19.2.3 Accesskey

The access key can be obtained by the following command:

https://<LoadMasterIPAddress>/access/accesskey?

3.19.2.4 KillASLInstance

If the Activation Server Lite (ASL) functionality was used to license a LoadMaster, the
KillASLInstance command can be run to deactivate the client LoadMaster license:

https://<LoadMasterIPAddress>/access/KillASLInstance

Kemp strongly recommends deregistering a LoadMaster using
the Kemp 360 Central WUI/API, rather than the LoadMaster
WUI/API. Deregistering a LoadMaster from the LoadMaster
UI/API can lead to the LoadMaster having an unknown state in
Kemp 360 Central. In these cases, it is not easy to remove the
LoadMaster from Kemp 360 Central and the unknown
LoadMaster is still taking up an available license.

3.19.2.5 Deactivate a non-SPLA License

To deactivate a non-SPLA (Service Provider License Agreement) client LoadMaster license, run the
kill_instance command:

230

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

https://<LoadMasterIPAddress>/access/kill_
instance?name=<KempID>&passwd=<KempIDPassword>&kill=1

Do not run this command unless instructed to by Kemp
Support.

3.19.2.6 Disable/Enable the Activation Licensing Text for Kemp 360 Central

You can disable/enable the activation licensing text for Kemp 360 Central using the following
command:
https://<LoadMasterIPAddress>/access/set?param=hideaslloginmsg&value=<0/1>

You can retrieve the value of the hideaslloginmsg parameter by running the get command:

https://<LoadMasterIPAddress>/access/get?param=hideaslloginmsg

The hideaslloginmsg parameter is only available for root,
admin, and bal users. A non-admin user cannot access this.

3.19.3 System Reboot

The LoadMaster can be shut down or rebooted using the following commands:

https://<LoadMasterIPAddress>/access/shutdown?
https://<LoadMasterIPAddress>/access/reboot?

3.19.4 Update Software

3.19.4.1 Upgrade to a Newer Version of Software

The LoadMaster can be upgraded to a new version of software by using the installpatch command.
There are a number of methods of using this command for example, using a CURL command on
Linux would look like the following:

curl –X POST -–data-binary “@<LM Patch File>” –k
https://<LoadMasterIPAddress>/access/installpatch

This cURL command would install a patch (<LM Patch File>) on the system.

The file being uploaded must be a valid patch file. If the file
does not work in the WUI it will not work using a RESTful API
command.

3.19.4.2 Check the Previously Installed Firmware Version

You may want to check the previously installed LoadMaster firmware version in certain situations,
for example, before you roll back to a previous firmware version. To check the previously installed

231

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

firmware version, run the following command:

https://<LoadMasterIPAddress>/access/getpreviousversion

3.19.4.3 Restore to a Previously Installed Version of Software

The previous version of firmware on the LoadMaster can be restored by using the following
command:

https://<LoadMasterIPAddress>/access/restorepatch

The machine needs to be rebooted for the change to take place.

3.19.4.4 List the Installed Add-On Packs

A list of any add-on packages that are installed on the LoadMaster can be displayed by running the
following command:

https://<LoadMasterIPAddress>/access/listaddon

3.19.4.5 Upload or Update an Add-On Pack

Add-on packs can be uploaded by running the following POST command:

curl -X POST --data-binary "@<Path To Add-On Pack File>" -k
https://<LoadMasterIPAddress>/access/addaddon

If the add-on pack already exists, the add-on pack will be
updated to the version being uploaded.

3.19.4.6 Delete Add-On Pack

Add-on packs can be deleted by running the following command:

https://<LoadMasterIPAddress>/access/deladdon?name=<AddOnPackName>

The name of the existing add-on packs can be displayed by running the listaddon command.

3.19.5 Backup/Restore

LoadMaster configurations can be backed up or restored using the following commands:

https://<LoadMasterIPAddress>/access/backup

If you run this command using cURL the file will be downloaded to your working directory in Linux.

Below is an example of a cURL command to restore a LoadMaster configuration:

curl -X POST --data-binary "@<Path To Backup File>" -k
https://<LoadMasterIPAddress>/access/restore?type=<ResoreTypeNumber>

type takes the integer range from 1 to 15:

232

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

Name

Type

Range

Additional Information

1 = LoadMaster Base configuration

2 = Virtual Service configuration

3 = Base and Virtual Service configuration

4 = GEO configuration

5 = Base and GEO configuration

6 = Virtual Service and GEO configuration

7 = Base, Virtual Service and GEO configuration

type

Integer

1-15

8 = ESP SSO configuration

9 = ESP SSO and base configuration

10 = ESP SSO and Virtual Service configuration

11 = ESP SSO, Virtual Service and base configuration

12 = ESP SSO and GEO configuration

13 = ESP SSO, GEO and base configuration

14 = ESP SSO, GEO and Virtual Service configuration

15 = ESP SSO, GEO, Virtual Service and Base configuration

3.19.5.1 Automated Backups

Parameters relating to automated backups that can be managed using get and set commands are
detailed in the following table. Refer to the Using get and set commands section for the get and
set commands.

Name

Type

Default

Range

Additional Information

backupday

Integer

Daily

0-7

Specify which day to perform the
automated backup (or daily):

0 = Daily

1 = Monday

2 = Tuesday

233

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

3 = Wednesday

4 = Thursday

5 = Friday

6 = Saturday

7 = Sunday

Enable automated timed backups (using
FTP).

Set the IP address or hostname of the
remote host to which you want the backup
archives sent, optionally followed by a
colon and the port number. If no port is
specified, the default port for the selected
protocol is used.

The hour to perform the automated
backup.

0 = Midnight

23 = 11pm

The minute to perform the automated
backup.

Note the range values are full minutes

backupenable

Boolean

N

backuphost

String

backuphour

Integer

backupminute

Integer

0

0

0-23

0-59

backupsecure

Boolean

0 - ftp

backupmethod

String

wput

backuppassword

String

0 – ftp
(insecure)

1 – scp
(secure)

Specify the file transfer method for
automated backups. This is a legacy
parameter. You cannot specify sftp
(secure) if using this parameter.

Specify the file transfer method for
automated backups. Takes a string that
can be either wput, scp, or sftp. Setting
the backupmethod to wput sets the
Backup Method field to Ftp (insecure).

The password of the remote user. This
parameter is used when the backupsecure

234

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

backupident

File

backuppath

backupuser

String

String

3.19.6 Date/Time Settings

method is set to 1 (Ftp (insecure)).

If using scp (1) as the backupsecure
method, the remote identity value must be
provided. This is the SSH private key
generated using ssh-keygen on the remote
scp server.

The key file must be encoded in base64
before uploading.

This parameter can only be set – running a
get on this parameter returns some
asterisks.

Specify the remote path name.

Specify the remote username.

Parameters relating to the date and time that can be managed using get and set commands are
detailed in the following table. Refer to the Using get and set commands section for the get and
set commands.

Name

Type

Additional Information

ntphost

time

timezone

ntpkeyid

ntpkeysecret

ntpkeytype

S

I

S

I

S

S

Specify the host from which the LoadMaster will set the time. Multiple
hosts can be specified in a space-separated list. Please escape the spaces
using %20. The time will be set from the first host to return a valid answer.

The time in hours, minutes and seconds.

The timezone where the LoadMaster is located

The NTP key ID. Valid values range from 1 to 99.

The NTP shared secret string. The NTP secret can be a maximum of 40
characters long. If the secret is more than 20 characters long, it is treated
as a hex string. Setting this value to an empty string will disable the NTPv4
feature.

Specify the NTP Key Type. The valid values are

SHA-1 (SHA1), legacy SHA (SHA), and MD5 (M). Note that the values are

235

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

case sensitive and must be in uppercase.

It is not possible to set the time using a RESTful API command.

3.20 Logging Options

3.20.1 Manage System Logs

To list the existing system log files, run the following command:

https://<LoadMasterIPAddress>/access/logging/listsyslogfiles

To clear all the system log files, run the following command:

https://<LoadMasterIPAddress>/access/logging/clearlogs

The legacy command before clearlogs was resetlogs.

To clear a specific log file, run the following command:

https://<LoadMasterIPAddress>/access/logging/clearlogs?fsel=<FileToClear>

To save all the system log files, run the following command:

https://<LoadMasterIPAddress>/access/logging/savelogs

The legacy command before savelogs was downloadlogs.

To save a specific log file, run the following command:

https://<LoadMasterIPAddress>/access/logging/savelogs?fsel=<FileTodownload>

When using cURL, successful output of the required log file is compressed into .tar and .gzip format
and the downloaded filename can be provided using the -o parameter. To print the response code in
the filename provided in the cURL request, use the following syntax: -w"%{http_code}\n". If the
output fails, it is saved as text in the provided file. For example:

curl -o syslogs.tar.gz -s -w "%{http_code}\n" -k
"https://<Username>:<Password>@<LoadMasterIPAddress>/access/logging/savelogs?
fsel=messages"

3.20.2 Ping Host

To perform a ping, run the following command:

https://<LoadMasterIPAddress>/access/logging/ping?addr=<Address>&intf=<Interf
aceID>

236

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

Parameter

Parameter
Type

addr

Address

intf

Integer

Parameter Description

Mandatory

Specify the host to perform the ping on. This parameter
accepts an IPv4 address, IPv6 address, FQDN, or
hostname.

Specify the ID of the interface from which the ping
should be sent from. If the interface is not specified
here, the correct interface to ping an address on a
particular network will be automatically selected.

Yes

No

The LoadMaster will try to auto-detect what type of ping to use (ping for IPv4 and ping6 for IPv6).
However, it is also possible to force a ping6 on an IPv6 address by running the ping6 command:

https://<LoadMasterIPAddress>/access/logging/ping6?addr=<Address>&intf=<Inter
faceID>

The ping command returns a 200 OK success message even if
an incorrect or non-existing interface is provided.

3.20.3 Run a Traceroute

To perform a traceroute, run the following command:

https://<LoadMasterIPAddress>/access/logging/traceroute?addr=<Address>

The addr parameter accepts an IPv4 address, IPv6 address, FQDN, or hostname.

3.20.4 Debug Options

3.20.4.1 Get/Set Debug Options

Parameters relating to Debug Options that can be managed using get and set commands are
detailed in the table below. Refer to the Using get and set commands section for the get and set
commands. For example, to display the value of the irqbalance parameter, run the following
command:

https://<LoadMasterIPAddress>/access/get?param=irqbalance

Name

Type

Parameter Description

irqpinning

B

You can use this parameter to enable or disable Interrupt Request Line
(IRQ) pinning. This is disabled by default.

Only enable this option in consultation with

237

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

Kemp Support.

When you change the IRQ pinning option
from off to on, IRQ pinning is enabled on all
network interfaces that are assigned an IP
address. When IRQ pinning is enabled and
you add an IP address to an unconfigured
interface, that interface will not have IRQ
pinning enabled until you either toggle the
IRQ pinning off and back on again, or the
system is rebooted.

irqbalance

tcpsack

IPV6forwarding

EnableISetupCli

B

B

B

B

The purpose of IRQBalance is distribute hardware interrupts across
processors on a multiprocessor system. This should only be enabled
after consultation with Kemp technical support.

Use this parameter to enable or disable TCP SACK (Selective
ACKnowledgement) processing. This is a global setting that affects all
Layer 7 Virtual Services. It only works if TCP SACK is enabled on a
Virtual Service client and the LoadMaster.

Enable this parameter to enable Layer 4 IPv6 forwarding. Disable this
option for full IPv6 conformance.

Enable or disable the Command Line Interface (CLI) Service
Management function.

linearesplogs

B

By default, the LoadMaster deletes older log files. If this parameter is
enabled, older log files will no longer be deleted. If the filesystem fills
up, further access using the LoadMaster is blocked.

dhcpv6

B

When this parameter is enabled, the DHCPv6 client will run on the
primary interface. This provides the capability to obtain an IPv6
address on boot. If you want DHCPv6 to be run on every boot, keep this
option enabled. However, this is a long running process and it keeps
running in the background when it is enabled so if you only need an

238

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

IPv6 address to be assigned and you do not need to renew and release
the IPv6 address you should disable this option after the IPv6 address is
assigned.

3.20.4.2 Retrieve RAID Information

Display the Redundant Array of Independent Disks (RAID) controller details, including the model
name, serial number, capacity, state, status, level, and total members in the RAID, by running this
command:

https://<LoadMasterIPAddress>/access/logging/getraidinfo

3.20.4.3 Retrieve RAID Disk Information

Display details about the RAID disks, including the model name, serial number, firmware version,
capacity, type, and speed, by running this command:

https://<LoadMasterIPAddress>/access/logging/getraiddisksinfo

3.20.4.4 Reset Statistics

Reset the statistics by running the following command:

https://<LoadMasterIPAddress>/access/logging/resetstats

3.20.4.5 Flush SSO Authentication Cache

The SSO authentication cache can be flushed by running the ssoflush command:

https://<LoadMasterIPAddress>/access/logging/ssoflush

3.20.5 Extended Log Files

3.20.5.1 List the Extended Log Files

To list the existing extended log files, run the listextlogfiles command:

https://<LoadMasterIPAddress>/access/listextlogfiles

3.20.5.2 Clear Extended Log Files

To clear the extended log files, run the clearextlogs command. To clear all the ESP log files, run the
command without the fsel parameter:

https://<LoadMasterIPAddress>/access/logging/clearextlogs

To clear a specific extended log file, enter the log file to clear in the fsel parameter:

https://<LoadMasterIPAddress>/access/logging/clearextlogs?fsel=connection

239

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

3.20.5.3 Save Extended Log Files

To save (download) the extended log files, run the saveextlogs command.

To save a specific extended log file, enter the log file to save in the fsel parameter:

https://<LoadMasterIPAddress>/access/logging/saveextlogs?fsel=connection

When using cURL, successful output of the required log files is compressed into .tar and .gzip format
and the downloaded filename can be provided using the -o parameter. To print the response code in
the filename provided in the cURL request, use the following syntax: -w"%{http_code}\n". If the
output fails, it is saved as text in the provided file. For example:

curl -o extlogs.tar.gz -s -w "%{http_code}\n" -k
"https://<Username>:<Password>@<LoadMasterIPAddress>/access/logging/saveetxlo
gs?fsel=user"

3.20.5.4 Enable/Disable Extended ESP Logging

To check if the Disable Local Extended ESP Logs optiong is currently enabled/disabled, run the
isextesplogenabled command:

https://<LoadMasterIPAddress>/access/logging/isextesplogenabled

To disable extended ESP logging, run the disableextesplog command:

https://<LoadMasterIPAddress>/access/logging/disableextesplog

To enable extended ESP logging, run the enableextesplog command:

https://<LoadMasterIPAddress>/access/logging/enableextesplog

If Disable Local Extended ESP Logs is disabled (the default option), messages are written to the
extended ESP logs expediently and are not sent to any remote syslog servers that are defined.

If Disable Local Extended ESP Logs is enabled, no messages are written to the extended ESP logs
and messages are only sent to the remote logger (if one is defined). If a remote logger is not defined,
no logs are recorded.

You can no longer configure the system to both populate the local extended ESP logs and send the
same messages to remote syslog servers, as it was in previous releases.

3.20.6 Syslog Options

Parameters relating to Syslog Options that can be managed using get and set commands are
detailed in the table below. Refer to the Using get and set commands section for the get and set
commands.

Name

Type

Parameter Description

240

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

(SyslogLevelParam)

syslogemergency

syslogcritical

syslogerror

syslogwarn

syslognotice

sysloginfo

syslognone

A

A

A

A

A

A

A

Use this option to set the host(s) which will
receive Emergency events only. Entries must be
comma-separated. Up to 10 entries are
supported in total for all levels.

Use this option to set the host(s) which will
receive Emergency and Critical events. Entries
must be comma-separated. Up to 10 entries are
supported in total for all levels.

Use this option to set the host(s) which will
receive Emergency, Critical and Error events.
Entries must be comma-separated. Up to 10
entries are supported in total for all levels.

Use this option to set the host(s) which will
receive Emergency, Critical, Error and
Warning events. Entries must be comma-
separated. Up to 10 entries are supported in
total for all levels.

Use this option to set the host(s) which will
receive Emergency, Critical, Error, Warning
and Notice events. Entries must be comma-
separated. Up to 10 entries are supported in
total for all levels.

Use this option to set the host(s) which will
receive All events. Entries must be comma-
separated. Up to 10 entries are supported in
total for all levels.

Use this option to delete a host, or hosts, from
any syslog level. Because you can only assign a
specific host to one level, you do not need to
specify the syslog level to remove the host
from. Entries must be comma-separated. Up to
10 entries can be deleted at once.

The get command does not retrieve anything

241

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

syslogport

syslogprot

syslogcert

I

S

B

for this parameter.

Specify the port that syslog messages are sent
to on the receiving hosts.

Specify what protocol to use for the connection
to a remote syslog server. Valid values are tcp,
udp, and tls.

This parameter is only relevant when tls is
specified as the syslogprot. When syslogcert is
enabled, it ensures that the host name or
IP address that was used to initiate the secure
connection resides in the Certificate Subject or
Subject Alternative Names (SAN) of the
certificate.

Up to 10 individual IP addresses and/or hostnames can be specified for each of the Syslog
fields. Multiple IP addresses/hostnames must be differentiated using a comma-separated list.

You cannot configure the same host for multiple levels.

To delete all hosts for a syslog level, set the value of the syslog level to an empty string, for example:

https://<LoadMasterIPAddress>/access/set?param=<SyslogLevelParam>&value=

For example:

https://<LoadMasterIPAddress>/access/set?param=syslognotice&value=

3.20.7 SNMP Options

Parameters relating to SNMP Logging Options that can be managed using get and set commands
are detailed in the following table. Refer to the Using get and set commands section for the get
and set commands.

Name

Type

Additional Information

snmpcommunity

snmpcontact

snmpenable

S

S

B

Specify the SNMP community string.

Specify the contact address that is sent in SNMP responses.

0 - Disabled

1 - Enabled

242

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

snmptrapenable

snmpv1sink

snmpv2sink

snmpV3enable

snmpv3user

snmpv3userpasswd

snmplocation

snmpclient

snmpHATrap

B

A

A

B

A

A

S

S

B

snmpAuthProt

S

Enable the generation of SNMP events whenever a significant event
occurs.

Specify the sink address for SNMP type 1 traps.

Specify the sink address for SNMP type 2 traps.

Enable/disable SNMP V3.

0 - Disabled

1 - Enabled

Specify the username.

Specify the user password.

Specify the location that is sent in SNMP responses.

Specify the list of machines that can access the SNMP subsystem. If
no clients are specified, anyone can access SNMP.

Send SNMP traps from the shared IP address. This option is only
available when the LoadMaster is in HA mode.

Specify the relevant authentication protocol:

MD5

SHA

SHA is a more secure protocol.

Note: These values are case sensitive - please enter them in
uppercase.

Enable the SNMP V3 private password.

snmpV3Privenable

snmpv3privpasswd

snmpPrivProt

B

A

S

0 - Disabled

1 - Enabled

Specify the private password.

Specify the relevant privacy protocol:
DESAES

243

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

AES is a more secure protocol.

Note: These values are case sensitive - please enter them in
uppercase.

3.20.8 Email Options

Parameters relating to Email Logging Options that can be managed using get and set commands
are detailed in the following table. Refer to the Using get and set commands section for the get
and set commands.

Name

Type

Range

Additional Information

emailcritical

emaildomain

emailemergency

emailenable

emailerror

emailinfo

emailnotice

emailpassword

emailport

emailserver

S

S

S

B

S

S

S

S

I

S

The email address to receive critical messages.

The domain, if required, for the user account authentication.

The email address to receive emergency messages.

Enables or disables the email logging options.

The email address to receive error messages.

The email address to receive informational messages.

The email address to receive notices.

The email user's password.

0-65535

The TCP port on which your mail server accepts connections
(usually 25).

The host name or address of the SMTP server to send mail
messages through.

Specify the type of security protocol that should be used on
the connection:

emailsslmode

I

0-3

0 = None

1 = STARTTLS, if available

2 = STARTTLS

3 = SSL/TLS

emailuser

S

The user account with access to send email messages.

244

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

emailwarn

S

The email address to receive warnings.

3.20.9 SDN Log Files

3.20.9.1 Debug Options

There are two modes that can be used to gather the SDN statistics.

The modes are described below:

Mode 1: When set to mode 1, the statistics are taken from the switch port that is connected to
the server and the statistics are relayed back to the LoadMaster.

Mode 2: When set to mode 2, the information is taken from all of the switch ports along the
path.

The SDN statistics mode can be managed using the get and set commands by using the parameter
sdnstatsmode with a value of 1 or 2, for example:

https://<LoadMasterIPAddress>/access/set?param=sdnstatsmode&value=2

3.21 Troubleshooting

3.21.1 Get/Set Debug Options

Parameters relating to Troubleshooting that can be managed using get and set commands are
detailed in the table below. Refer to the Using get and set commands section for the get and set
commands.

Name

Type

Parameter Description

backupnetstat

B

netconsole

A

By default, the LoadMaster includes a Netstat output in backups
taken. When this is included, backups take longer to complete. You
can stop the Netstat output from being included by disabling this
parameter.

Netconsole is a kernel module which logs kernel printk messages
over UDP allowing debugging of problems where disk logging fails.
If this parameter is populated, the syslog daemon on a specific host
will receive all critical kernel messages. This can help in
understanding why a LoadMaster is rebooting. Netconsole is mainly
used for capturing kernel panic output.

To unset this, set the value to an empty string.

245

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

netconsoleinterface

I

The interface which hosts the Netconsole.

3.21.2 Run a Top

Performing a top displays memory, CPU, and I/O usage for the LoadMaster. You can specify the
number of samples and an interval between them (the default is 10 samples and a 1 second
interval). You can also show threads and/or sort by memory usage by selecting the appropriate
check boxes.

Perform a top by running the following command:

https://<LoadMasterIPAddress>/access/logging/top

Name

Type

Parameter Description

iterations

interval

I

I

threads

B

mem

B

Specify the number of samples (the default is 10 samples).

Range: 1-30

Specify the interval between them (the default is a 1 second interval).

Range: 1-30

Enable this option to show process threads (disabled by default).

0 - Disabled

1 - Enabled

By default, the results are sorted by CPU usage (so the mem parameter is
defaulted at 0 - Disabled). Enable the mem parameter to sort by memory
usage instead.

0 - Disabled

1 - Enabled

Here is an example with each of the optional parameters set:

https://<LoadMasterIPAddress>/access/logging/top?iterations=4&interval=3&thre
ads=1&mem=1

By default, the LoadMaster does not include top command output in LoadMaster system backups.
To include it, enable the backuptop parameter using the set command:

https://<LoadMasterIPAddress>/access/set?param=backuptop&value=1

246

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

When included in LoadMaster system backups, top is run using the default parameters (regardless of
what is configured in the WUI) and is sorted by memory usage.

3.21.3 Run the Other Debug Options

These other debug options commands can be run using the API:

l /logging/ps

The ps command does not work when run in a browser. Use a
cURL command to run a ps.

l /logging/meminfo

l /logging/ifconfig

l /listifconfig

l /logging/netstat

l /logging/interrupts

l /logging/partitions

l /logging/cpuinfo

l /logging/df

l /logging/lspci

l /logging/lsmod

l /logging/slabinfo

For example:

https://<LoadMasterIPAddress>/access/logging/meminfo

3.21.4 Run a TCP Dump

Run a TCP dump using the following command:

https://<LoadMasterIPAddress>/access/tcpdump?maxpackets=<MaximumNumberOfPacke
ts>&maxtime=<MaximumTime>&interface=<InterfaceID>&port=<Port>&address=<Addres
s>&tcpoptions=<OptionalParameters>

All parameters are optional.

Name

Type

Parameter Description

Mandatory

247

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

maxpackets

maxtime

interface

port

address

I

I

I

I

I

tcpoptions

S

The maximum number of packets to capture. The default
value for this parameter is 10000. Valid values range from 1
to 200000.

The maximum number of seconds to capture. The default
value for this parameter is 10. Valid values range from 1 to
600.

The interface(s) to monitor. The default interface is eth0. A
TCP dump can be captured either by one or all Ethernet
ports.

The port to be monitored.

The (optional) address to be monitored.

Any optional parameters needed. The maximum number of
characters permitted is 255. You can use any options that
you can have in a tcp dump command. For example, if you
do not set the port parameter, you could set the port in the
tcpoptions parameter. You could also set the protocol to
udp. You can enter multiple options.

N

N

N

N

N

N

The output of a TCP dump is a .pcap file, which is downloaded. You can use an application such as
Wireshark to view the output.

3.22 Miscellaneous Options

3.22.1 WUI Settings

Parameters relating to WUI Settings that can be managed using get and set commands are detailed
in the following table. Refer to the Using get and set commands section for the get and set
commands.

Name

Type

Range

Description

hoverhelp

B

0 –
Disable

1 -
Enable

This option allows the display of descriptive text when a
cursor rests on a clickable option in the WUI screen.

248

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

autosave

B

0 –
Disable

1 -
Enable

Disabling auto-save is currently a beta feature. Auto-save is
enabled by default. If it is disabled, this option modifies the
several default WUI behaviors. For further details refer to the
Web User Interface (WUI) Configuration Guide.

This is the Message of the Day (MOTD). Either plain text or a
text file can be used.

motd

S

The maximum number of characters is 5,000.

An error will be displayed if the MOTD is greater than 5,000
characters.

wuidisplaylines

I

10-100

Set the maximum number of lines which can be displayed on
a single statistics page.

If the Message Of The Day (MOTD) is specified using the set
command as above, the maximum number of characters that
can be entered is 5,000.

You can view the third-party acknowledgements file applicable to the LoadMaster release you are
running by using the notice command. For example:

access/notice

3.22.2 L7 Configuration

Parameters relating to L7 Configuration that can be managed using get and set commands are
detailed in the following table. Refer to the Using get and set commands section for the get and
set commands.

Name

Type

Range

Description

addcookieport

addvia

B

B

0 - Disabled

1 - Enabled

When using the LoadMaster behind a NATing
gateway, all client addresses are the same. To
create individual cookies the remote port can
also be added to the cookie. Enabling this option
when not needed wastes resources.

0 - Disabled

1 - Enabled

When enabled, a VIA header field will be added
to all cache responses. The Virtual Service
address will be the address used.

249

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

By default the LoadMaster blocks POSTs that do
not contain a Content-Length or Transfer-
Encoding header to indicate the length of the
requests payload. When this parameter is set to
true, such requests are assumed to have no
payload data and are therefore not rejected.

By default, when the LoadMaster is trying to
locate a Real Server for use with content
switching, it tries to use the same Real Server as
currently selected, even if the port is not the
same. Enabling this parameter forces the port to
also be compared.

allowemptyposts

B

0 - Disabled

1 - Enabled

forcefullrsmatch

B

0 – Disabled

1 – Enabled

0 = Only check
persist on the
first request of a
HTTP/1.1
connection

alwayspersist

S

1 = Check the
persist on every
request

This parameter also accepts no and yes as valid
values. No and yes correspond to 0 and 1
respectively.

2 = All persistent
changes will be
saved, even in
the middle of a
connection

closeonerror

B

0 - Disabled

1 - Enabled

When enabled, the LoadMaster will always close
the client connection when it sends back an
error response. For Example, this changes the
behaviour of the LoadMaster when sending back
a 304 File not changed message after receiving
an If-Modified-Since HTTP header.

dropatdrainend

B

0 - Disabled

1 - Enabled

If enabled, all open connections to disabled Real
Servers will be dropped at the end of the Real
Servers Drain Stop Time OR immediately if there
are no Persist entries associated with the Real

250

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

droponfail

B

Server.

0 - Disabled

1 - Enabled

By default, existing connections are not closed if
a Real Server fails. Enabling this feature causes
all connections to be immediately dropped on
Real Server failure

Determines how 100-Continue Handling
messages are handled. The available options are:

expect100

I

0 - RFC-2616
Compliant

1 - Require 100-
Continue

2 - RFC-7231
Compliant

- RFC-2616 Compliant (0): conforms with the
behavior as outlined in RFC-2616

- Require 100-Continue (1): forces the
LoadMaster to wait for the 100-Continue
message

- RFC-7231 Compliant (2): ensures the
LoadMaster does not wait for 100-Continue
messages. This is the default value.

Modifying how 100 Continue messages are
handled by the system requires an
understanding of the relevant technologies as
described in the RFCs listed above. It is
recommended that you speak with a Kemp
Technical Support engineer before making
changes to these settings.

rfcconform

rsarelocal

localbind

B

B

B

0 - Disabled

1 - Enabled

0 - Disabled

1 - Enabled

0 - Disabled

1 - Enabled

By default, the LoadMaster conforms to the RFC
when parsing HTTP headers. Disabling this will
allow interworking with some broken browsers.

When checking to see if a client is on the local
subnet, also check to see if the client is actually a
Real Server.

In very high load situations, local port exhaustion
can occur. Enabling this option allows the setting
of alternate source addresses. This can be used
to expand the number of available local ports.

251

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

transparent

B

slowstart

addforwardheader

logsplitinterval

authtimeout

authpostwait

clienttokentimeout

ShareSubVSPersist

I

I

I

I

I

I

I

0 - Disabled

1 - Enabled

Globally enable or disable the transparent
handling of connections using the L7 subsystem.
L4 connections are ALWAYS handled
transparently.

0-600

When using the Least Connection (or Weighted
Least Connection) scheduling method, specify
the time (in seconds) over which the load to a
Real Server which has just come online will be
throttled.

0 - X-ClientSide

1 - X-Forwarded-
For

2 - None

This option (which is only available when L7
Transparency is disabled) allows the addition of
either X-ClientSide or X-Forwarded For to the
HTTP header. The default value is X-Forwarded-
For.

1-100

30 – 300

1-2000

60-300

When using Log Insight Scheduling this is the
number of messages which are received on a
connection before the stream is rescheduled.
The default value is 10.

The duration (in seconds) that a connection
remains open for while authentication is
ongoing. This value can be between 30 and 300.

When using KCD backend authentication, the
length of time to wait for a 401 response from a
POST before sending the remainder of the POST
body.

The duration (in seconds) to wait for the client
token while the process of authentication is
ongoing (used for RSA SecurID and RADIUS
authentication). The default value for this
parameter is 120.

0 – Disabled

1 – Enabled

By default, each SubVS has an independent
persistence table. Enabling this parameter will
allow the SubVS to share this information.

loguseragent

B

0 - Disabled

When enabled, the User Agent header field is

252

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

CEFmsgFormat

B

SameSite

I

1 - Enabled

added to the User Logs.

0 - Disabled

1 - Enabled

When enabled, the ESP logs are generated in
Common Event Format (CEF). CEF log format is
easily consumable for Security Information and
Event Management (SIEM) tools, such as; Splunk,
SolarWinds, LogRhythm, AlienVault, and so on.

This option is disabled by default.

0 – SameSite
Option Not
Added
1 –
SameSite=None
2 - SameSite=LAX

3 -
SameSite=Strict

Set the default value for SameSite option for
cookies sent by the LoadMaster during ESP
processing. The default value is SameSite option
not added.

When L7NTLMProxy is enabled, NTLM
authorization works against the Real Servers. If
L7NTLMProxy is disabled, the old insecure NTLM
processing is performed.

Kemp highly recommends
ensuring that L7NTLMProxy is
enabled.

L7NTLMProxy

B

0 - Disabled

1 - Enabled

3.22.3 Network Options

Parameters relating to Network Options that can be managed using get and set commands are
detailed in the following table. Refer to the Using get and set commands section for the get and
set commands.

Name

Type

Range

Additional Information

snat

B

0 -
Disabled

Enabling this option allows the LoadMaster to NAT
connections from the Real Servers to the internet.

253

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

allowupload

B

1 -
Enabled

0 -
Disabled

1 -
Enabled

conntimeout

I

0-86400

keepalive

B

multigw

B

nonlocalrs

B

onlydefaultroutes

B

resetclose

B

0 -
Disabled

1 -
Enabled

0 -
Disabled

1 -
Enabled

0 -
Disabled

1 -
Enabled

0 -
Disabled

1 -
Enabled

0 -
Disabled

1 -
Enabled

The LoadMaster has been optimized with HTTP
workloads in mind. Enabling this option allows non
HTTP uploads to work correctly.

Specify (in seconds) the time a connection can be idle
before it is closed. This is independent of Persistency
Timeout. Setting a value of 0 resets to the default value
of 660 seconds.

By default, the system uses TCP keepalives to check for
failed clients. Enabling this option improves the
reliability of older TCP connections (SSH sessions). This
is not normally required for normal HTTP/HTTPS
services.

Use this option to enable the ability to move the default
gateway to a different interface.

Alternate default gateway support
is not permitted in a cloud
environment.

Enable this option to permit non-local Real Servers to
be assigned to Virtual Services.

This option is enabled by default.

Enable this option to force traffic from Virtual Services,
which have default route entries set, to be routed to the
interface where the Virtual Service’s default route is
located.

When enabled, the LoadMaster will close its connection
to the Real Servers by using TCP RESET instead of the
normal close handshake.

254

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

subnetorigin

B

subnetoriginating

B

tcptimestamp

B

routefilter

B

0 -
Disabled

1 -
Enabled

0 -
Disabled

1 -
Enabled

0 -
Disabled

1 -
Enabled

0 -
Disabled

1 -
Enabled

When transparency is disabled for a Virtual Service, the
source IP address of connections to Real Servers is the
Virtual Service. When enabled, the source IP address is
the local address of the LoadMaster. If the Real Server is
on a subnet, the subnet address of the LoadMaster will
be used.

When transparency is disabled for a Virtual Service, the
source IP address of connections to Real Servers is the
Virtual Service. When enabled, the source IP address is
the local address of the LoadMaster. If the Real Server is
on a subnet, the subnet address of the LoadMaster will
be used.

The LoadMaster can include a timestamp in the SYN
when connecting to Real Servers. Only enable this only
on request from Kemp Support.

When enabled, this option only accepts IP frames from a
host over the interface where the routing algorithm
would route frames to the host. This is known as strict
source route validation.

sslforceserververify

B

0 –
Disabled

1 –
Enabled

By default, when re-encrypting traffic the LoadMaster
does not check the certificate provided by the Real
Server. Enabling this option forces the LoadMaster to
verify that the certificate on the Real Server is valid, that
is, the certificate authority and expiration are OK. This
includes all intermediate certificates.

http_proxy

S

This option allows clients to specify the HTTP(S) proxy
server and port the LoadMaster will use to access the
internet.

255

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

tcpnorecycle

B

0 -
Disabled

1 -
Enabled

This option is disabled by default. Enable this option to
revert to the legacy mode of reusing TCP timewait
connections.

Only enable this after consulting
with Kemp Support.

3.22.4 HA Management

If using the LoadMaster for Azure product, please refer to the
next section.

Parameters relating to HA Parameters that can be managed using get and set commands are
detailed in the following table. Refer to the Using get and set commands section for the get and
set commands.

Name

Type

Range

Description

hastatus

S

Normal HA:

Active, Standby,
Passive (all as
expected).

Cloud HA:

Active, Standby,
Passive (if status
not yet set).

Cluster:

Active (if master),
Standby (if slave),
Passive (if disabled).
For clusters, there is
one master and all
of the others are
standby.

If HA is not

Retrieve the status of a HA or cluster unit. This is
a read only parameter and cannot be set.

256

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

haif

hainitial

macglobal

I

B

B

configured, HA not
configured is
returned.

0 – Disabled

1 – Enabled

0 - Disabled

1 - Enabled

0 = No preferred
host

haprefered

I

1 = Prefer First HA

2 = Prefer Second
HA

0 = legacy heart
beat

1 = carp

1 = 3 seconds

2 = 6 seconds

3 = 9 second

4 = 12 seconds

5 = 15 seconds

1-255

hastyle

B

hatimeout

havhid

I

I

The network interface used when synchronising
the configuration between the members of the
HA cluster

Perform extra network checks at boot time. This
may cause instability and should not be used.

By default, the LoadMaster uses an IP multicast
address when sending CARP packets. Enabling
this option forces the use of the IP broadcast
address instead.

By default, neither partner in a HA cluster has
priority. When a machine restarts after a
switchover that machine becomes a standby.
Specifying a preferred host means that when this
machine restarts it will always become the active
and the partner will revert to standby mode.

By default, the system uses a version of VRRP
(carp) to check the status of the partner. The
system can also support the legacy Heartbeat
program. This option only takes effect when both
machines are rebooted

The time the active must be unavailable before a
switchover occurs.

When using multiple HA LoadMasters on the
same network, this value identifies each cluster
so that there are no potential unwanted
interactions.

257

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

0-200

hawait

mcast

I

I

vmac

B

0 – Disable

Tcpfailover

B

1 – Enable

0 – Disable

hal4update

B

1 – Enable

cookieupdate

B

1 – Enable

0 – Disable

hal7update

B

0 – Disable

This is how long (in seconds) after the initial
boot, before the LoadMaster becomes active. If
the partner machine is running this value is
ignored. This value can be changed to mitigate
the time taken for some intelligent switches to
detect that the LoadMaster has started and to
bring up the link.

The network interface used for multicast traffic
which is used to synchronize Layer 4 and Layer 7
traffic when Inter HA Updates are enabled.

This option creates a shared MAC address for
both units. When failover occurs, the LoadMaster
handles the MAC address handover too. This
allows the switches to keep the MAC address and
not worry about ARP caches or stale records.

When using L4 services, enabling updates allows
L4 connection maintenance across a HA
switchover. This option is ignored for L7 services.

This parameter is now deprecated and has been
replaced with the hal4update parameter.

When using L4 services, enabling updates allows
L4 connection maintenance across a HA
switchover. This option is ignored for L7 services.

When using L7 services, enabling this option
allows sharing of persistency information
between HA partners. If a HA switchover occurs,
the persistency information will then not be lost.
Enabling this option can have a significant
performance impact.

This parameter is now deprecated and has been
replaced with the hal7update parameter.

When using L7 services, enabling this option
allows sharing of persistency information

258

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

1 – Enable

0, 60-86400

0 – HA mode
disabled

1 – HA 1 mode

2 – HA 2 mode

between HA partners. If a HA switchover occurs,
the persistency information will then not be lost.
Enabling this option can have a significant
performance impact.

When a Real Server is disabled, the sessions
persisting on that Real Server continue to be
served until the Drain Time has expired or until
no more sessions are being handled by the Real
Server. No new sessions will be handled by the
Real Server.

Specify the HA mode. If only using a single
LoadMaster, use Non-HA Mode. In non-cloud HA
mode, one LoadMaster must be specified as the
first and another as second. HA will not work if
both LoadMasters are specified the same.

3 – System is using
cloud HA

4 – System is in a
cluster

HA enables two physical or virtual LoadMasters to
become one logical device. Only one of these
units is active and handling traffic at any one
time (HA 1 mode) while the other is a hot standby
(passive - HA 2 mode).

0 - Disable

1 - Enable

0 - Disable

1 - Enable

Enable HA health checking. At least one interface
must be enabled.

Enables LoadMaster to reboot if there is a link
failure.

finalpersist

hamode

hacheck

halinkfailreboot

I

I

B

B

Simply changing the HA mode does not switch between non-HA
and HA. The partner and Virtual IP (VIP) Addresses also need to
be set and a reboot is needed before the system is fully
switched over. For instructions on how to set up HA using the
RESTful API, refer to the Azure HA Parameters section.

After changing the hastyle or hamode a reboot is required for
the changes to take effect.

259

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

3.22.5 Cloud HA Parameters

You can retrieve the HA parameters for a cloud LoadMaster by running the getCloudHaParams
command:

https://<LoadMasterIPAddress>/access/getCloudHaParams

You can set the cloud HA mode by running the following command:

https://<LoadMasterIPAddress>/access/setcloudhamode?hamode=<first/second/sing
le>

Setting the hamode to single, disables HA (the LoadMaster is treated as a single unit).

You can set the cloud HA parameters by running the following command:

https://<LoadMasterIPAddress>/access/setcloudhaparam?partner=<PartnerHostName
OrIPAddress>

Name

Type

Range

Additional Information

partner

hcp

S

I

haprefered

B

hcai

B

Must be a
valid IP
address

Must be a
valid port
value

0 – No
Preferred
Host

1 – Prefer
First

0 -
Disabled

1 -
Enabled

Specify the host name or IP address of the HA partner unit.

Set the port to run the health check over. The port must be the
same on both the active and standby unit for HA to function
correctly.

There are two possible values to set:

0 - No Preferred Host: Each unit takes over when the other unit
fails. No switchover is performed when the partner is restarted.

1 - Prefer First: The active unit always takes over. This is the
default option.

When this option is enabled, the health check listens on all
interfaces. This is required when using a multi-arm
configuration. If this is disabled, the health check listens on the
primary eth0 address (this is the default behavior).

For details on API commands specific to different cloud platforms, refer to the sections below.

260

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

3.22.5.1 Azure HA Parameters

These commands are only relevant to the LoadMasters running
in Azure.

The Azure HA mode can be set by running the following command:

https://<LoadMasterIPAddress>/access/azurehamode?hamode=<first/second/single>

The Azure HA parameters can be set by running the following command:

https://<LoadMasterIPAddress>/access/azurehaparam?partner=<PartnerHostNameOrI
PAddress>&hcp=<HealthCheckPort>

The parameters that can be set using the azurehaparam command are the same as those set using
the setcloudhaparam command. For details about these parameters, refer to the Cloud HA
Parameters section.

The Azure HA parameters can be retrieved by using the following command:

https://<LoadMasterIPAddress>/access/getazurehaparams?

3.22.5.2 AWS HA Parameters

These commands are only relevant to LoadMasters running in
AWS.

The AWS HA mode can be set by running the following command:

https://<LoadMasterIPAddress>/access/awshamode?hamode=<first/second/single>

The AWS HA parameters can be set by running the following command:

https://<LoadMasterIPAddress>/access/awshaparam?partner=<PartnerHostNameOrIPA
ddress>&hcp=<HealthCheckPort>

Name

Type

Range

Additional Information

partner

hcp

S

I

Must be a
valid IP
address

Specify the host name or IP address of the HA partner unit.

Must be a
valid port
value

Set the port over which the health check will be run. The port
must be the same on both the active and standby unit for HA to
function correctly.

haprefered

B

0 – No
Preferred

There are two possible values to set:

0 - No Preferred Host: Each unit takes over when the other unit

261

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

Host

fails. No switchover is performed when the partner is restarted.

1 – Prefer
First

1 - Prefer First: The HA1 (active) unit always takes over. This is
the default option.

0 -
Disabled

1 -
Enabled

When this option is enabled, the health check listens on all
interfaces. This is required when using a multi-arm
configuration. If this is disabled, the health check listens on the
primary eth0 address (this is the default behavior).

hcai

B

The AWS HA parameters can be retrieved by using the following command:

https://<LoadMasterIPAddress>/access/getawshaparams?

Example output for the getawshaparams command is below:

<?xml version="1.0" encoding="ISO-8859-1"?>

<Response stat="200" code="ok">

<Success><Data><AwsHA>

<HaMode>master</HaMode>

<HaPrefered>0</HaPrefered>

<Partner>172.18.0.5</Partner>

<Port>8444</Port>

</AwsHA>

</Data>

</Success>

</Response>

3.22.6 SDN Configuration

3.22.6.1 Add an SDN Controller

To add a new SDN controller to the LoadMaster, run the command below:

https://<LoadMasterIPAddress>/access/addsdncontroller?ipv4=<IPv4Address>&port
=<SDNControllerPort>&https=<0/1>&user=<UserToAccessSDNControllerAPI>&password
=<PasswordForSDNUser>&clid=<ClusterID>

The parameters used in this command are described below:

Name

Mandatory

Type

Default

Range

Additional Information

ipv4

Yes

S

<unset>

Valid
IPv4

The IPv4 address of the SDN controller.

262

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

address
range

Valid
port
range

0 - HTTP

1 -
HTTPS

port

Yes

I

<unset>

https

No

B

0 - HTTP

user

password

No

No

S

S

<unset>

<unset>

clid

No

I

<unset>

1 - 6

Expected Output

<Response stat="200" code="ok">

<Success>Command completed ok</Success>

</Response>

3.22.6.2 Modify an SDN Controller

The port of the SDN controller.

The HTTP method to use.

The username to be used to access the
SDN controller RESTful API.

The password to be used to access the
SDN controller RESTful API.

The cluster ID for the new SDN
controller. If a number is specified, the
SDN controller will be added to the
cluster with the relevant ID number. The
cluster with the ID number specified
must already exist.

If a number is not specified, the SDN
controller will be added to a new cluster.

To modify an existing SDN controller, run the command below:

https://<LoadMasterIPAddress>/access/modsdncontroller?cid=<ControllerID>&ipv4
=<IPv4Address>&port=<SDNControllerPort>&https=<0/1>&user=<UserToAccessSDNCont
rollerAPI>&password=<PasswordForSDNUser>&clid=<ClusterID>

The parameters used in this command are described below:

Name

Mandatory

Type

Default

Range

Additional Information

263

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

cid

Yes

ipv4

No

port

No

https

No

user

password

No

No

I

S

I

B

S

S

Auto
incrementing
number

The ID of the controller to be
modified. To get the controller ID,
run the getsdncontroller
command.

Valid
IPv4
address
range

Valid
port
range

0 - HTTP

1 -
HTTPS

<unset>

<unset>

0 - HTTP

<unset>

<unset>

The IPv4 address of the SDN
controller.

The port of the SDN controller.

The HTTP method to use.

The username to be used to access
the SDN controller RESTful API.

The password to be used to access
the SDN controller RESTful API.

The cluster ID for the new SDN
controller. If a number is specified,
the SDN controller will be added to
the cluster with the relevant ID
number. The cluster with the ID
number specified must already
exist.

If a number is not specified, the
SDN controller will be added to a
new cluster.

clid

No

I

<unset>

1 - 6

Expected Output

<Response stat="200" code="ok">

<Success>

<Data>

<controllers>

<cluster id="2"/>

264

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

<cluster id="3"/>

<cluster id="5"/>

<cluster id="6"/>

<cluster id="7"/>

<cluster id="8"/>

<cluster id="9"/>

<cluster id="10"/>

<cluster id="11"/>

<cluster id="12"/>

<cluster id="13"/>

<cluster id="14"/>

<cluster id="15"/>

<cluster id="16"/>

<cluster id="17"/>

<cluster id="18">

<controller id="30">

<ipv4>172.16.0.6</ipv4>

<port>8443</port>

<https>yes</https>

<user>sdn</user>

<password>*****</password>

</controller>

</cluster>

<cluster id="19">

<controller id="31">

<ipv4>172.16.0.8</ipv4>

<port>8443</port>

<https>yes</https>

<user>sdn</user>

<password>*****</password>

</controller>

</cluster>

<cluster id="20">

<controller id="32">

<ipv4>172.16.0.8</ipv4>

<port>8443</port>

<https>no</https>

265

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

<user/>

<password/>

</controller>

</cluster>

</controllers>

</Data>

</Success>

</Response>

3.22.6.3 Delete an SDN Controller

To delete an SDN controller, run the command below:

https://<LoadMasterIPAddress>/access/delsdncontroller?cid=<ControllerID>&clid
=<ClusterID>

Either the Controller ID or the Cluster ID must be specified. The Controller ID and Cluster ID can be
found by running the getsdncontroller command. For more information, refer to the Show the
Existing SDN Controllers section.

Expected Output

<Response stat="200" code="ok">

<Success>Command completed ok</Success>

</Response>

3.22.6.4 Show the Existing SDN Controllers

To display a list of the SDN controllers that currently exist on the LoadMaster, run the command
below:

https://<LoadMasterIPAddress>/access/getsdncontroller

An example of the returned output is below:

<Response stat="200" code="ok">

<Success>

<Data>

<controllers>

<cluster id="2">

<controller id="29">

<ipv4>172.16.0.6</ipv4>

<port>8443</port>

<https>yes</https>

<user>sdn</user>

266

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

<password>*****</password>

</controller>

</cluster>

<cluster id="3"/>

<cluster id="5"/>

<cluster id="6"/>

<cluster id="7"/>

<cluster id="8"/>

<cluster id="9"/>

<cluster id="10"/>

<cluster id="11"/>

<cluster id="12"/>

<cluster id="13"/>

<cluster id="14"/>

<cluster id="15"/>

<cluster id="16"/>

<cluster id="17"/>

</controllers>

</Data>

</Success>

</Response>

The parameters that appear in the output are explained below:

Cluster ID: The unique ID of the cluster that the SDN controller is a member of.

Any empty cluster parameter sections relate to clusters that
were previously added but were later removed. Each time a
new cluster is added it gets assigned a new ID number.

Controller ID: The ID of the SDN controller.

IPv4: The IPv4 address of the SDN controller.

Port: The port of the SDN controller WUI.

HTTPS: Displays whether HTTPS (yes) or HTTP (no) is used to access the SDN controller.

User: The username to be used to access the SDN controller.

Password: The password of the user to be used to access the SDN controller.

267

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

3.23 Network Telemetry

A number of parameters relating to network telemetry can be retrieved and configured using the get
and set commands. Refer to the table below for details about these parameters:

Name

Type

Default

Range

Additional Information

TelemetryServer

S

<unset>

Define the destination IP
address or Fully
Qualified Domain Name
(FQDN) and port number
of your IPFIX collector
(for example,
1.1.1.1:2055 or
collector.local:3000).
The IPFIX export runs
over the UDP protocol
and you must ensure
that the collector is
reachable over the
network from the
LoadMaster.

TelemetryActiveTimeout

TelemetryInactiveTimeout

TelemetryOptArp

TelemetryOptDhcp

TelemetryOptDns

I

I

B

B

B

300

10 - 6000

30

1 - 59

The global active
timeout value.

The global inactive
timeout value.

1 -
Enabled

1 -
Enabled

0 -
Disabled

1 -
Enabled

0 -
Disabled

1 -
Enabled

Specify whether or not
to collect ARP values.

Specify whether or not
to collect DHCP values.

1 -
Enabled

0 -
Disabled

Specify whether or not
to collect DNS values.

268

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

1 -
Enabled

0 -
Disabled

1 -
Enabled

0 -
Disabled

1 -
Enabled

0 -
Disabled

1 -
Enabled

0 -
Disabled

1 -
Enabled

0 -
Disabled

1 -
Enabled

0 -
Disabled

1 -
Enabled

0 -
Disabled

1 -
Enabled

1 -
Enabled

1 -
Enabled

1 -
Enabled

1 -
Enabled

1 -
Enabled

1 -
Enabled

1 -
Enabled

Specify whether or not
to collect HTTP values.

Specify whether or not
to collect email values.

Specify whether or not
to collect NBAR2 values.

Specify whether or not
to collect Samba values.

Specify whether or not
to collect VoIP values.

Specify whether or not
to collect MSSQL values.

Specify whether or not
to collect PostgresSQL
values.

1 -

0 -

Specify whether or not

TelemetryOptHttp

TelemetryOptMail

TelemetryOptNbar2

TelemetryOptSamba

B

B

B

B

TelemetryOptExtendedVoip

B

TelemetryOptMsSql

TelemetryOptPostgres

TelemetryOptMySql

B

B

B

269

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

TelemetryOptNpm

B

TelemetryOptExtendedNpm

B

TelemetryOptVxlan

B

Enabled

1 -
Enabled

1 -
Enabled

1 -
Enabled

Disabled

1 -
Enabled

0 -
Disabled

1 -
Enabled

0 -
Disabled

1 -
Enabled

0 -
Disabled

1 -
Enabled

to collect MySQL values.

Specify whether or not
to collect NPM values.

Specify whether or not
to collect Extended NPM
values.

Specify whether or not
to collect VXLAN values.

To check if network telemetry monitoring is enabled or disabled on all interfaces, run the
showtelemetry command with no parameters. For example:

/access/showtelemetry?

To check if network telemetry monitoring is enabled or disabled on a specific interface, run the
showtelemetry command with the interface parameter. For example:

/access/showtelemetry?interface=0

To enable or disable network telemetry monitoring on a particular interface, run the
enabletelemetry command. For example:

/access/enabletelemetry?interface=<InterfaceID>&enable=<0/1>

Valid values for enable are:

l 0 - Disabled

l 1 - Enabled

270

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

3.24 Setting Up HA using the RESTful API

The two sections below provide step-by-step instructions on how to set up HA using the RESTful API
on a regular LoadMaster, and a LoadMaster for Azure:

3.24.1 Set up HA on a Regular LoadMaster using RESTful API

The example commands that are needed to set up HA using the RESTful API on a regular LoadMaster
are below:

1. Set device 1 to to HA1:

https://192.168.1.1/access/set?param=hamode&value=1

2. Reboot HA1:

https://192.168.1.1/access/reboot?

3. Set HA1’s partner’s address (HA2 address):

https://192.168.1.1/access/modiface?interface=0&PartnerIPAddress=192.168.1.2

4. Set the shared IP address for the HA pair:

https://192.168.1.1/access/modiface?interface=0&SharedIPAddress=192.168.1.10

5. Set HA2 to secondary:

https://192.168.1.2/access/set?param=hamode&value=2

6. Reboot HA2:

https://192.168.1.2/access/reboot?

7. Set HA2’s partner’s address (HA1’s address):

https://192.168.1.2/access/modiface?interface=0&partner=192.168.1.1

8. Set the shared IP address for the HA pair:

https://192.168.1.2/access/modiface?interface=0&shared=192.168.1.10

Commands such as reboot take several seconds for the
LoadMaster to complete. If scripting, please allow for a proper
delay after the reboot command.

To remove HA, use the commands below:

1. Set to non-HA:

https://192.168.1.1/access/set?param=hamode&value=0

271

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

3 RESTful API Commands

2. Reboot:

https://192.168.1.1/access/reboot?

3.24.2 Set up HA on a LoadMaster for Azure using RESTful API

The example commands that can be used to set up HA on a LoadMaster for Azure using RESTful API
are below:

Set the active unit to first HA mode:

https://192.168.1.1/access/azurehamode?hamode=first

Set the HA parameters (partner address and health check port) for the active:

https://192.168.1.1/access/azurehaparam?partner=192.168.1.2&hcp=8444

Set the standby unit to second HA mode:

https://192.168.1.2/access/azurehamode?hamode=second

Set the HA parameters (partner address and health check port) for the standby:

https://192.168.1.2/access/azurehaparam?partner=192.168.1.1&hcp=8444

To remove HA, use the commands below:

https://192.168.1.1/access/azurehamode?hamode=single
https://192.168.1.2/access/azurehamode?hamode=single

272

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

4 Scripting Examples with the LoadMaster RESTful API

4 Scripting Examples with the
LoadMaster RESTful API

The LoadMaster RESTful API can be used in conjunction with many scripting methods and
applications to allow users and applications to directly access the LoadMaster.

Refer to the RESTful API Programmers Guide, Technical Note for some detailed examples of how the
RESTful API can be used.

273

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

5 List All API Commands and get/set Parameters

5 List All API Commands and
get/set Parameters

A number of parameters can be retrieved and set using the get and set commands. For more details
on how to get the list of parameters, refer to the section List All API Commands and get/set
Parameters.

274

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

References

References

Unless otherwise specified, the following documents can be found at
http://kemptechnologies.com/documentation.

WUI, Configuration Guide

Kemp LoadMaster, Product Overview

SSL Accelerated Services, Feature Description

GEO, Feature Description

RESTful API Programmers Guide, Technical Note

Licensing, Feature Description

CLI, Interface Description

LoadMaster Clustering, Feature Description

Custom Authentication Form, Technical Note

User Management, Feature Description

Content Rules, Feature Description

275

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

RESTful API

Last Updated Date

Last Updated Date

This document was last updated on 17 June 2022.

276

© 2022 Progress Software Corporation and/or one of its subsidiaries or affiliates. All rights reserved.

