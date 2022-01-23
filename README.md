# Automate DNSDIST Settings

This function has been developed to automate your dnsdist settings in production environents. DNSDIST is a one of the POWERDNS products which is using to handeling and managing dns requests. The dnsdist is a one of the kind of Loadbalancer for balancing DNS traffic between Cache or Recursor servers.


## About The Project

Using this python script you can automate dnsdist configuration regarding to admin values. This script can be integrated with Ansible for fasinating dns configuration. DNSDIST is a important service for security in DNS DDOS atacctions So you will be needed to be comfortable with changing your config in DDOS attactions if you are working with POWERDNS as a your DNS services.

## Installation

```bash
yum repolist && yum install python-dotenv -y
```

### Getting Started

At first you should clone code to your desktop and change variables in .env file based on your environment.

```bash
# Redhat based distributions
yum repolist && yum install git -y 

# Debian based distributions
apt update && apt install git

git clone https://github.com/ali-abaszadeh/DNSDIST-Settings.git
```


## Usage

This function has been developed to automate your dnsdist settings in production environents. DNSDIST is a one of the POWEDNS products which is using to handeling and managing dns requests. The dnsdist is a one of the kind of Loadbalancer for balancing DNS traffic between Cache or Recursor servers.


## License


## Contact

a.abaszadeh1363@gmail.com

Project Link: [https://github.com/ali-abaszadeh/DNSDIST-Settings.git]
