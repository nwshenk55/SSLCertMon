# SSLCertMon
Track suspected APT infrastructure via SSL Certificate usage monitoring with Censys IO

### Usage:
1. Import SSL Certs to be tracked into the database
2. Run this script 1x/day to check for IPs that are newly hosting the monitored SSL Certificates

### Notes:
This tool is simply the core framework one would need to identify new suspected APT CNE infrastruture
based on SSL Cert Usage on a daily basis. Ideally, you'd updated it to meet your specific needs.

### Requirements:
Requires a FREE Censys IO API Key - signup here: https://www.censys.io/api

### Dependencies:
1. PyMongo
2. Censys Python (see https://github.com/censys/censys-python). Get it via 'pip install censys'

------------

Sample record from the database created by this tool:

```
{'APT': 'TEST',
 'All_Observed_IPs': {'179-43-128-218': {'Country_Code': 'CH',
                                         'Country_Name': 'Switzerland',
                                         'Date_Seen': '2017-07-05',
                                         'IP': '179.43.128.218',
                                         'Ports_And_Protocols': ['443/https',
                                                                 '22/ssh',
                                                                 '80/http']},
                      '185-183-107-38': {'Country_Code': '',
                                         'Country_Name': '',
                                         'Date_Seen': '2017-07-05',
                                         'IP': '185.183.107.38',
                                         'Ports_And_Protocols': ['443/https',
                                                                 '22/ssh']},
                      '185-86-150-26': {'Country_Code': 'SE',
                                        'Country_Name': 'Sweden',
                                        'Date_Seen': '2017-07-05',
                                        'IP': '185.86.150.26',
                                        'Ports_And_Protocols': ['443/https']},
                      '188-40-155-241': {'Country_Code': 'DE',
                                         'Country_Name': 'Germany',
                                         'Date_Seen': '2017-07-05',
                                         'IP': '188.40.155.241',
                                         'Ports_And_Protocols': ['443/https']},
                      '5-135-199-31': {'Country_Code': 'FR',
                                       'Country_Name': 'France',
                                       'Date_Seen': '2017-07-05',
                                       'IP': '5.135.199.31',
                                       'Ports_And_Protocols': ['443/https',
                                                               '22/ssh']},
                      '86-105-1-136': {'Country_Code': 'IT',
                                       'Country_Name': 'Italy',
                                       'Date_Seen': '2017-07-05',
                                       'IP': '86.105.1.136',
                                       'Ports_And_Protocols': ['443/https',
                                                               '25/smtp']},
                      '86-107-42-11': {'Country_Code': 'GB',
                                       'Country_Name': 'United Kingdom',
                                       'Date_Seen': '2017-07-05',
                                       'IP': '86.107.42.11',
                                       'Ports_And_Protocols': ['443/https',
                                                               '22/ssh',
                                                               '80/http']},
                      '89-34-111-119': {'Country_Code': 'DE',
                                        'Country_Name': 'Germany',
                                        'Date_Seen': '2017-07-05',
                                        'IP': '89.34.111.119',
                                        'Ports_And_Protocols': ['443/https',
                                                                '80/http']},
                      '92-114-92-134': {'Country_Code': 'IT',
                                        'Country_Name': 'Italy',
                                        'Date_Seen': '2017-07-05',
                                        'IP': '92.114.92.134',
                                        'Ports_And_Protocols': ['443/https',
                                                                '22/ssh',
                                                                '25/smtp',
                                                                '80/http']},
                      '94-177-12-74': {'Country_Code': 'RO',
                                       'Country_Name': 'Romania',
                                       'Date_Seen': '2017-07-05',
                                       'IP': '94.177.12.74',
                                       'Ports_And_Protocols': ['443/https',
                                                               '22/ssh',
                                                               '80/http']}},
 'Date_Last_Observed_On_Any_IP': '2017-07-05',
 'Friendly_Name': None,
 'SHA_1': 'a1833c32d5f61d6ef9d1bb0133585112069d770e',
 'Source': None,
 '_id': ObjectId('595d877749dbea77b9243444')}

```
