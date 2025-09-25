# Genreator ip set

Install Python and Git
```
sudo apt install -y python3-pip python3-venv git
```

Install script
```
git clone https://github.com/huhen/update-wg.git
cd update-wg
sudo python3 -m venv /opt/update-wg
sudo /opt/update-wg/bin/pip3 install -r requirements.txt
sudo cp {update-wg.py,exclude.txt,include.txt} /opt/update-wg
```

Refresh and apply config
```
sudo /opt/update-wg/bin/python3 /opt/update-wg/update-wg.py
```

Edit exlude
```
sudo nano /opt/update-wg/exclude.txt
sudo nano /opt/update-wg/include.txt
```
