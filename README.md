# keyv-scanner

## Context

On August 4, 2026, a malicious supply chain attack compromised keyv@6.0.0 and multiple related npm packages in the Keyv and Cacheable ecosystem, deploying a credential-stealing worm known as the "Mini Shai-Hulud" campaign

## This Repo

Only for Linux

scans machine for vulnerable keyv 6.0.0 on all npm dependencies (including transitive dependencies)

### Scan whole machine

```bash
chmod +x check-keyv-compromise.sh
sudo ./check-keyv-compromise.sh /
echo "Exit status: $?"
```

### Scan specific directory

```bash
# Check /home directory
sudo ./check-keyv-compromise.sh /home

# Check /Volumes/Projects directory
sudo ./check-keyv-compromise.sh /Volumes/Projects
```

### Result exit code

```txt
0  Nothing suspicious found in readable data
1  Compromised or unsafe Keyv reference found
2  Strict mode: scan completed with coverage gaps
3  Invalid arguments, missing Node.js, or fatal scanner failure
```
