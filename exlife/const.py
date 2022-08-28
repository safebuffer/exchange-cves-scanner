VULNERABILITIES = [
  {
    "Name": "Microsoft Exchange Remote Code Execution ProxyShell",
    "CVE": "CVE-2021-34473",
    "Versions": [
        # Exchange Server 2013
        "build_v == 15 and major == 0 and minor < 1497",

        # Exchange Server 2016
        "build_v == 15 and major == 1 and minor < 2176",

        # Exchange Server 2019
        "build_v == 15 and major == 2 and minor < 792",

    ],
  },
    {
    "Name": "Microsoft Exchange Remote Code Execution ProxyLogon",
    "CVE": "CVE-2021-26855",
    "Versions": [
        # Exchange Server 2013
        "build_v == 15 and major == 0 and minor < 1497",

        # Exchange Server 2016
        "build_v == 15 and major == 1 and minor < 2176",

        # Exchange Server 2019
        "build_v == 15 and major == 2 and minor < 792",

    ],
  },
  {
    "Name": "Microsoft Exchange Validation Key Remote Code Execution Vulnerability",
    "CVE": "CVE-2020-0688",
    "Versions": [
        # Exchange Server 2013
        "build_v == 15 and major == 0 and minor < 1497",

        # Exchange Server 2016
        "build_v == 15 and major == 1 and minor < 1913 and minor != 1847",

        # Exchange Server 2019
        "build_v == 15 and major == 2 and minor < 529 and minor != 464",

        # Exchange Server 2010
        "build_v == 14 and minor < 468 and minor != 468",

    ],
  },
  {
    "Name": "Microsoft Exchange Memory Corruption Vulnerability",
    "CVE": "CVE-2018-8154",
    "Versions": [
        # Exchange Server 2010 
        "build_v == 14 and minor < 419",

        # Exchange Server 2013 
        "build_v == 15 and major == 0 and minor <= 1347 and minor != 847",

        # Exchange Server 2016 
        "build_v == 15 and major == 1 and minor < 1415",
    ],
  },
  {
    "Name": "Exchange 2003 : out of support",
    "CVE": "N/A",
    "Versions": [
        "build_v == 6"
    ],
  },
  {
    "Name": "Exchange 2007 : out of support",
    "CVE": "N/A",
    "Versions": [
        "build_v == 8"
    ],
  },
  {
    "Name": "Exchange 2010 : out of support",
    "CVE": "N/A",
    "Versions": [
        "build_v == 14"
    ],
  },
]

