# Generator ip set

Install Python and Git
```
sudo apt install -y python3-pip python3-venv git ipset iptables
# add for ipset option
sudo apt install -y ipset iptables iptables-persistent ipset-persistent
```

Install script
```
git clone https://github.com/huhen/update-wg.git
cd update-wg
sudo python3 -m venv /opt/update-wg
sudo /opt/update-wg/bin/pip3 install -r requirements.txt
sudo cp {update-wg.py,update-wg-ipset.py,exclude.txt,include.txt} /opt/update-wg
```

### Option 1: Using traditional WireGuard routes (original method)
Refresh and apply config using traditional AllowedIPs approach
```
sudo /opt/update-wg/bin/python3 /opt/update-wg/update-wg.py
```

### Option 2: Using ipset + iptables (recommended for better performance)
Refresh and apply config using ipset/iptables approach
```
sudo /opt/update-wg/bin/python3 /opt/update-wg/update-wg-ipset.py
```

Edit exclude/include lists
```
sudo nano /opt/update-wg/exclude.txt
sudo nano /opt/update-wg/include.txt
```

### Check current configuration
```
# Check ipset contents (when using ipset method)
sudo ipset list wg_allowed_ips

# Check iptables rules (when using ipset method)
sudo iptables -L -v -n

# Check WireGuard status
sudo wg show
