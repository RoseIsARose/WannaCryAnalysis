# WannaCry|WannaDecrypt0r NSA-Cybereweapon-Powered Ransomware Worm 

* **Virus Name**: WannaCrypt, WannaCry, WanaCrypt0r, WCrypt, WCRY
* **Vector**: All Windows versions before Windows 10 are vulnerable if not patched for MS-17-010. It uses EternalBlue MS17-010 to propagate.

SECURITY BULLETIN AND UPDATES HERE: https://technet.microsoft.com/en-us/library/security/ms17-010.aspx


# Malware samples

* hxxps://www.hybrid-analysis.com/sample/ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa?environmentId=100
* hxxps://transfer.sh/PnDIl/CYBERed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa.EXE
* hxxps://transfer.sh/ZhnxR/CYBER1be0b96d502c268cb40da97a16952d89674a9329cb60bac81a96e01cf7356830.EXE (main dll)

Binary blob in PE crypted with pass 'WNcry@2ol7'

# Informative Tweets

* EternalBlue confirmed: https://twitter.com/kafeine/status/863049739583016960
* Shell commands: https://twitter.com/laurilove/status/863065599919915010
* Maps/stats: https://twitter.com/laurilove/status/863066699888824322
* Core DLL: https://twitter.com/laurilove/status/863072240123949059
* Hybrid-analysis: https://twitter.com/PayloadSecurity/status/863024514933956608
* Impact assessment: https://twitter.com/CTIN_Global/status/863095852113571840
* Uses DoublePulsar: https://twitter.com/laurilove/status/863107992425779202 
* Your machine is attacking others: https://twitter.com/hackerfantastic/status/863105127196106757
* Tor hidden service C&C: https://twitter.com/hackerfantastic/status/863105031167504385
* FedEx infected via Telefonica? https://twitter.com/jeancreed1/status/863089728253505539
* HOW TO AVOID INFECTION: https://twitter.com/hackerfantastic/status/863070063536091137
* More of this to come: https://twitter.com/hackerfantastic/status/863069142273929217
* C&C hosts: https://twitter.com/hackerfantastic/status/863115568181850113
* Crypted files *will* be deleted after countdown: https://twitter.com/laurilove/status/863116900829724672
* Claim of attrib [take with salt]: https://twitter.com/0xSpamTech/status/863058605473509378

# Cryptography details

* encrypted via AES-128
* AES key generated with a CSPRNG, CryptGenRandom
* AES key is encrypted by RSA-2048

# Bitcoin ransom addresses

3 addresses hard coded into the malware.

* https://blockchain.info/address/13AM4VW2dhxYgXeQepoHkHSQuy6NgaEb94
* https://blockchain.info/address/12t9YDPgwueZ9NyMgw519p7AA8isjr6SMw
* https://blockchain.info/address/115p7UMMngoj1pMvkpHijcRdfJNXj6LrLn

# C&C centers

* `gx7ekbenv2riucmf.onion`
* `57g7spgrzlojinas.onion`
* `xxlvbrloxvriy2c5.onion`
* `76jdd2ir2embyv47.onion`
* `cwwnhwhlz52ma.onion`

# Languages

All language ransom messages available here: https://transfer.sh/y6qco/WANNACRYDECRYPTOR-Ransomware-Messages-all-langs.zip

m_bulgarian, m_chinese (simplified), m_chinese (traditional), m_croatian, m_czech, m_danish, m_dutch, m_english, m_filipino, m_finnish, m_french, m_german, m_greek, m_indonesian, m_italian, m_japanese, m_korean, m_latvian, m_norwegian, m_polish, m_portuguese, m_romanian, m_russian, m_slovak, m_spanish, m_swedish, m_turkish, m_vietnamese
