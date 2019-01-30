# thehive-falcon
thehive-falcon is a Crowdstrike Falcon streaming api alert integration script for TheHive. 


## Usage

To start with, edit falcon_config.json and thehive_config.json and review each field to  make sure it is correct for your environment.

Stand-alone script execution:

```
python thehive_falcon.py falcon_config.json thehive_config.json

```
It uses `logging` to log events.

There is a systemd unit file included which expects you to place the script and configuration files in /opt/thehive-falcon. 
Copy the unit file `thehive-falcon.service` to `/etc/systemd/system` run `systemctl enable thehive-falcon` to install it as a service. 
Run `systemctl start thehive-falcon` to start the service.



