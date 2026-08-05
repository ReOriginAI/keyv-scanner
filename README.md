# keyv-scanner (and also scans other vulnerable packages like cacheable,cache-manager,...)

## Context

On August 4, 2026, a malicious supply chain attack compromised keyv@6.0.0 ,cacheable, cache-manager and multiple related npm packages in the Keyv and Cacheable ecosystem, deploying a credential-stealing worm known as the "Mini Shai-Hulud" campaign

## How to use

Only for Linux, Ubuntu, Raspberry Pi, Debian, etc

scans machine for vulnerable keyv 6.0.0 and INCLUDES other vulnerable packages listed on https://github.com/wiz-sec-public/wiz-research-iocs/blob/main/reports/keyv-packages.csv

For full system Scan

```bash
git clone https://github.com/ReOriginAI/keyv-scanner.git
cd keyv-scanner
sudo chmod +x check-keyv-andothers-compromise.sh
./check-keyv-andothers-compromise.sh

#full root scan
sudo ./check-keyv-andothers-compromise.sh
```


### For individual directory scan

```bash
git clone https://github.com/ReOriginAI/keyv-scanner.git
cd keyv-scanner
# Check /home directory
sudo ./check-keyv-andothers-compromise.sh /home
```
