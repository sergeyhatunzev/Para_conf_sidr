import re
import socket
import ipaddress
import requests
from tqdm import tqdm
from collections import OrderedDict


# CIDR-диапазоны
CIDR_RANGES = [
    ipaddress.ip_network('2.94.122.0/24'),
    ipaddress.ip_network('2.94.149.0/24'),
    ipaddress.ip_network('2.94.168.0/24'),
    ipaddress.ip_network('2.94.193.0/24'),
    ipaddress.ip_network('2.94.196.0/24'),
    ipaddress.ip_network('2.94.205.0/24'),
    ipaddress.ip_network('2.94.206.0/24'),
    ipaddress.ip_network('2.94.208.0/24'),
    ipaddress.ip_network('2.95.0.0/16'),
    ipaddress.ip_network('5.61.16.0/21'),
    ipaddress.ip_network('5.61.232.0/21'),
    ipaddress.ip_network('5.101.40.0/22'),
    ipaddress.ip_network('5.181.60.0/22'),
    ipaddress.ip_network('5.181.61.0/24'),
    ipaddress.ip_network('5.188.140.0/22'),
    ipaddress.ip_network('31.44.8.0/21'),
    ipaddress.ip_network('31.44.9.0/24'),
    ipaddress.ip_network('31.177.104.0/22'),
    ipaddress.ip_network('37.18.14.0/24'),
    ipaddress.ip_network('37.18.15.0/24'),
    ipaddress.ip_network('37.139.32.0/22'),
    ipaddress.ip_network('37.139.40.0/22'),
    ipaddress.ip_network('37.230.172.0/22'),
    ipaddress.ip_network('37.230.188.0/22'),
    ipaddress.ip_network('45.84.128.0/22'),
    ipaddress.ip_network('45.133.96.0/22'),
    ipaddress.ip_network('45.136.20.0/22'),
    ipaddress.ip_network('46.16.64.0/21'),
    ipaddress.ip_network('46.21.244.0/22'),
    ipaddress.ip_network('46.42.128.0/18'),
    ipaddress.ip_network('46.42.189.0/24'),
    ipaddress.ip_network('46.243.209.0/24'),
    ipaddress.ip_network('46.243.212.0/24'),
    ipaddress.ip_network('46.243.232.0/22'),
    ipaddress.ip_network('51.250.0.0/17'),
    ipaddress.ip_network('51.250.48.0/24'),
    ipaddress.ip_network('51.250.50.0/23'),
    ipaddress.ip_network('51.250.54.0/23'),
    ipaddress.ip_network('51.250.112.0/21'),
    ipaddress.ip_network('51.250.120.0/22'),
    ipaddress.ip_network('51.250.126.0/24'),
    ipaddress.ip_network('62.84.112.0/20'),
    ipaddress.ip_network('62.105.128.0/19'),
    ipaddress.ip_network('62.141.64.0/18'),
    ipaddress.ip_network('62.141.101.0/24'),
    ipaddress.ip_network('62.141.112.0/20'),
    ipaddress.ip_network('62.217.160.0/20'),
    ipaddress.ip_network('62.231.0.0/19'),
    ipaddress.ip_network('66.90.90.0/23'),
    ipaddress.ip_network('66.90.92.0/23'),
    ipaddress.ip_network('66.90.95.0/24'),
    ipaddress.ip_network('66.90.96.0/24'),
    ipaddress.ip_network('66.90.108.0/24'),
    ipaddress.ip_network('66.90.109.0/24'),
    ipaddress.ip_network('66.90.121.0/24'),
    ipaddress.ip_network('66.90.122.0/24'),
    ipaddress.ip_network('77.41.142.0/23'),
    ipaddress.ip_network('77.41.144.0/20'),
    ipaddress.ip_network('77.41.158.0/24'),
    ipaddress.ip_network('77.41.160.0/19'),
    ipaddress.ip_network('77.41.248.0/21'),
    ipaddress.ip_network('77.106.196.0/23'),
    ipaddress.ip_network('78.107.56.0/24'),
    ipaddress.ip_network('78.107.67.0/24'),
    ipaddress.ip_network('78.107.124.0/24'),
    ipaddress.ip_network('78.108.80.0/24'),
    ipaddress.ip_network('78.108.81.0/24'),
    ipaddress.ip_network('78.108.82.0/23'),
    ipaddress.ip_network('78.108.84.0/23'),
    ipaddress.ip_network('78.108.86.0/23'),
    ipaddress.ip_network('78.108.88.0/23'),
    ipaddress.ip_network('78.108.90.0/23'),
    ipaddress.ip_network('78.108.92.0/23'),
    ipaddress.ip_network('78.108.94.0/23'),
    ipaddress.ip_network('78.159.239.0/24'),
    ipaddress.ip_network('78.159.240.0/24'),
    ipaddress.ip_network('78.159.241.0/24'),
    ipaddress.ip_network('78.159.242.0/24'),
    ipaddress.ip_network('78.159.243.0/24'),
    ipaddress.ip_network('78.159.244.0/24'),
    ipaddress.ip_network('78.159.245.0/24'),
    ipaddress.ip_network('78.159.246.0/24'),
    ipaddress.ip_network('78.159.247.0/24'),
    ipaddress.ip_network('78.159.250.0/24'),
    ipaddress.ip_network('79.104.0.0/17'),
    ipaddress.ip_network('79.104.4.0/24'),
    ipaddress.ip_network('79.104.5.0/24'),
    ipaddress.ip_network('79.104.6.0/24'),
    ipaddress.ip_network('79.104.7.0/24'),
    ipaddress.ip_network('79.104.192.0/19'),
    ipaddress.ip_network('79.104.220.0/24'),
    ipaddress.ip_network('79.104.222.0/24'),
    ipaddress.ip_network('79.104.223.0/24'),
    ipaddress.ip_network('79.137.157.0/24'),
    ipaddress.ip_network('79.137.174.0/23'),
    ipaddress.ip_network('79.137.240.0/21'),
    ipaddress.ip_network('80.243.73.0/24'),
    ipaddress.ip_network('80.243.78.0/24'),
    ipaddress.ip_network('80.243.79.0/24'),
    ipaddress.ip_network('81.9.12.0/22'),
    ipaddress.ip_network('81.9.16.0/20'),
    ipaddress.ip_network('81.9.46.0/24'),
    ipaddress.ip_network('81.9.72.0/24'),
    ipaddress.ip_network('81.9.73.0/24'),
    ipaddress.ip_network('81.9.80.0/20'),
    ipaddress.ip_network('81.9.102.0/24'),
    ipaddress.ip_network('81.9.103.0/24'),
    ipaddress.ip_network('81.9.112.0/20'),
    ipaddress.ip_network('81.9.115.0/24'),
    ipaddress.ip_network('81.94.148.0/24'),
    ipaddress.ip_network('81.211.0.0/17'),
    ipaddress.ip_network('81.211.46.0/24'),
    ipaddress.ip_network('81.211.80.0/24'),
    ipaddress.ip_network('81.211.88.0/21'),
    ipaddress.ip_network('81.211.96.0/19'),
    ipaddress.ip_network('81.222.0.0/17'),
    ipaddress.ip_network('81.222.112.0/20'),
    ipaddress.ip_network('81.222.120.0/24'),
    ipaddress.ip_network('81.222.124.0/23'),
    ipaddress.ip_network('81.222.129.0/24'),
    ipaddress.ip_network('81.222.144.0/20'),
    ipaddress.ip_network('81.222.196.0/23'),
    ipaddress.ip_network('81.222.202.0/24'),
    ipaddress.ip_network('81.222.204.0/24'),
    ipaddress.ip_network('81.222.205.0/24'),
    ipaddress.ip_network('81.222.221.0/24'),
    ipaddress.ip_network('81.222.244.0/23'),
    ipaddress.ip_network('81.222.249.0/24'),
    ipaddress.ip_network('82.142.128.0/18'),
    ipaddress.ip_network('83.102.132.0/24'),
    ipaddress.ip_network('83.102.160.0/24'),
    ipaddress.ip_network('83.166.232.0/21'),
    ipaddress.ip_network('83.166.248.0/21'),
    ipaddress.ip_network('83.217.216.0/22'),
    ipaddress.ip_network('83.222.28.0/22'),
    ipaddress.ip_network('84.23.52.0/22'),
    ipaddress.ip_network('84.201.128.0/18'),
    ipaddress.ip_network('84.201.184.0/22'),
    ipaddress.ip_network('84.201.188.0/23'),
    ipaddress.ip_network('84.252.128.0/20'),
    ipaddress.ip_network('85.21.54.0/24'),
    ipaddress.ip_network('85.21.223.0/24'),
    ipaddress.ip_network('85.192.32.0/22'),
    ipaddress.ip_network('85.249.128.0/19'),
    ipaddress.ip_network('85.249.244.0/23'),
    ipaddress.ip_network('85.249.252.0/24'),
    ipaddress.ip_network('85.249.253.0/24'),
    ipaddress.ip_network('87.229.142.0/23'),
    ipaddress.ip_network('87.229.144.0/23'),
    ipaddress.ip_network('87.229.176.0/21'),
    ipaddress.ip_network('87.229.186.0/23'),
    ipaddress.ip_network('87.229.192.0/21'),
    ipaddress.ip_network('87.229.204.0/22'),
    ipaddress.ip_network('87.229.208.0/20'),
    ipaddress.ip_network('87.229.224.0/19'),
    ipaddress.ip_network('87.229.242.0/24'),
    ipaddress.ip_network('87.239.104.0/21'),
    ipaddress.ip_network('87.242.112.0/22'),
    ipaddress.ip_network('87.254.132.0/23'),
    ipaddress.ip_network('89.31.184.0/21'),
    ipaddress.ip_network('89.112.128.0/17'),
    ipaddress.ip_network('89.113.24.0/21'),
    ipaddress.ip_network('89.113.96.0/21'),
    ipaddress.ip_network('89.113.120.0/21'),
    ipaddress.ip_network('89.113.126.0/24'),
    ipaddress.ip_network('89.113.192.0/18'),
    ipaddress.ip_network('89.169.128.0/18'),
    ipaddress.ip_network('89.208.84.0/22'),
    ipaddress.ip_network('89.208.196.0/22'),
    ipaddress.ip_network('89.208.208.0/22'),
    ipaddress.ip_network('89.208.216.0/23'),
    ipaddress.ip_network('89.208.218.0/23'),
    ipaddress.ip_network('89.208.220.0/22'),
    ipaddress.ip_network('89.208.228.0/22'),
    ipaddress.ip_network('89.221.228.0/22'),
    ipaddress.ip_network('89.221.232.0/22'),
    ipaddress.ip_network('89.221.235.0/24'),
    ipaddress.ip_network('89.221.236.0/22'),
    ipaddress.ip_network('89.232.188.0/22'),
    ipaddress.ip_network('89.232.188.0/24'),
    ipaddress.ip_network('89.232.189.0/24'),
    ipaddress.ip_network('90.156.148.0/22'),
    ipaddress.ip_network('90.156.151.0/24'),
    ipaddress.ip_network('90.156.212.0/22'),
    ipaddress.ip_network('90.156.216.0/22'),
    ipaddress.ip_network('90.156.232.0/21'),
    ipaddress.ip_network('91.219.224.0/22'),
    ipaddress.ip_network('91.231.132.0/22'),
    ipaddress.ip_network('91.231.133.0/24'),
    ipaddress.ip_network('91.231.134.0/24'),
    ipaddress.ip_network('91.231.238.0/24'),
    ipaddress.ip_network('91.233.226.0/24'),
    ipaddress.ip_network('91.238.111.0/24'),
    ipaddress.ip_network('92.255.1.0/24'),
    ipaddress.ip_network('92.255.3.0/24'),
    ipaddress.ip_network('93.77.160.0/19'),
    ipaddress.ip_network('93.171.230.0/24'),
    ipaddress.ip_network('94.100.176.0/20'),
    ipaddress.ip_network('94.139.244.0/22'),
    ipaddress.ip_network('94.139.244.0/24'),
    ipaddress.ip_network('95.25.120.0/22'),
    ipaddress.ip_network('95.25.124.0/22'),
    ipaddress.ip_network('95.25.128.0/22'),
    ipaddress.ip_network('95.25.132.0/22'),
    ipaddress.ip_network('95.25.136.0/22'),
    ipaddress.ip_network('95.25.140.0/22'),
    ipaddress.ip_network('95.25.144.0/22'),
    ipaddress.ip_network('95.25.148.0/22'),
    ipaddress.ip_network('95.25.152.0/22'),
    ipaddress.ip_network('95.25.156.0/22'),
    ipaddress.ip_network('95.25.160.0/22'),
    ipaddress.ip_network('95.25.164.0/22'),
    ipaddress.ip_network('95.25.168.0/22'),
    ipaddress.ip_network('95.25.172.0/22'),
    ipaddress.ip_network('95.25.176.0/22'),
    ipaddress.ip_network('95.25.180.0/22'),
    ipaddress.ip_network('95.25.184.0/22'),
    ipaddress.ip_network('95.25.188.0/22'),
    ipaddress.ip_network('95.25.204.0/23'),
    ipaddress.ip_network('95.25.206.0/23'),
    ipaddress.ip_network('95.25.208.0/23'),
    ipaddress.ip_network('95.25.210.0/23'),
    ipaddress.ip_network('95.25.212.0/23'),
    ipaddress.ip_network('95.25.214.0/23'),
    ipaddress.ip_network('95.26.0.0/23'),
    ipaddress.ip_network('95.26.2.0/23'),
    ipaddress.ip_network('95.26.4.0/23'),
    ipaddress.ip_network('95.26.6.0/23'),
    ipaddress.ip_network('95.26.8.0/23'),
    ipaddress.ip_network('95.26.10.0/23'),
    ipaddress.ip_network('95.26.160.0/23'),
    ipaddress.ip_network('95.26.162.0/23'),
    ipaddress.ip_network('95.26.164.0/23'),
    ipaddress.ip_network('95.26.166.0/23'),
    ipaddress.ip_network('95.26.168.0/23'),
    ipaddress.ip_network('95.26.170.0/23'),
    ipaddress.ip_network('95.26.172.0/24'),
    ipaddress.ip_network('95.26.173.0/24'),
    ipaddress.ip_network('95.26.174.0/23'),
    ipaddress.ip_network('95.26.176.0/23'),
    ipaddress.ip_network('95.26.178.0/23'),
    ipaddress.ip_network('95.26.180.0/23'),
    ipaddress.ip_network('95.26.182.0/23'),
    ipaddress.ip_network('95.26.184.0/23'),
    ipaddress.ip_network('95.26.186.0/24'),
    ipaddress.ip_network('95.26.192.0/23'),
    ipaddress.ip_network('95.26.194.0/23'),
    ipaddress.ip_network('95.26.208.0/23'),
    ipaddress.ip_network('95.26.210.0/23'),
    ipaddress.ip_network('95.26.212.0/23'),
    ipaddress.ip_network('95.26.214.0/23'),
    ipaddress.ip_network('95.26.231.0/24'),
    ipaddress.ip_network('95.26.232.0/24'),
    ipaddress.ip_network('95.26.233.0/24'),
    ipaddress.ip_network('95.26.234.0/24'),
    ipaddress.ip_network('95.27.0.0/23'),
    ipaddress.ip_network('95.27.2.0/23'),
    ipaddress.ip_network('95.27.4.0/23'),
    ipaddress.ip_network('95.27.6.0/23'),
    ipaddress.ip_network('95.27.8.0/23'),
    ipaddress.ip_network('95.27.10.0/23'),
    ipaddress.ip_network('95.27.68.0/23'),
    ipaddress.ip_network('95.27.70.0/23'),
    ipaddress.ip_network('95.27.72.0/23'),
    ipaddress.ip_network('95.27.74.0/23'),
    ipaddress.ip_network('95.27.76.0/23'),
    ipaddress.ip_network('95.27.78.0/23'),
    ipaddress.ip_network('95.27.80.0/23'),
    ipaddress.ip_network('95.27.82.0/23'),
    ipaddress.ip_network('95.27.84.0/23'),
    ipaddress.ip_network('95.29.176.0/22'),
    ipaddress.ip_network('95.30.0.0/16'),
    ipaddress.ip_network('95.30.222.0/24'),
    ipaddress.ip_network('95.31.119.0/24'),
    ipaddress.ip_network('95.163.32.0/19'),
    ipaddress.ip_network('95.163.133.0/24'),
    ipaddress.ip_network('95.163.180.0/22'),
    ipaddress.ip_network('95.163.208.0/21'),
    ipaddress.ip_network('95.163.216.0/22'),
    ipaddress.ip_network('95.163.248.0/21'),
    ipaddress.ip_network('109.71.200.0/21'),
    ipaddress.ip_network('109.71.200.0/22'),
    ipaddress.ip_network('109.71.204.0/22'),
    ipaddress.ip_network('109.120.180.0/22'),
    ipaddress.ip_network('109.120.188.0/22'),
    ipaddress.ip_network('128.70.0.0/18'),
    ipaddress.ip_network('128.70.64.0/18'),
    ipaddress.ip_network('128.71.0.0/16'),
    ipaddress.ip_network('128.73.42.0/24'),
    ipaddress.ip_network('128.73.70.0/24'),
    ipaddress.ip_network('128.73.80.0/24'),
    ipaddress.ip_network('128.73.85.0/24'),
    ipaddress.ip_network('128.73.129.0/24'),
    ipaddress.ip_network('128.73.147.0/24'),
    ipaddress.ip_network('128.73.156.0/24'),
    ipaddress.ip_network('128.73.162.0/24'),
    ipaddress.ip_network('128.73.182.0/24'),
    ipaddress.ip_network('128.73.221.0/24'),
    ipaddress.ip_network('128.73.223.0/24'),
    ipaddress.ip_network('128.73.234.0/24'),
    ipaddress.ip_network('128.73.235.0/24'),
    ipaddress.ip_network('128.73.236.0/24'),
    ipaddress.ip_network('128.73.237.0/24'),
    ipaddress.ip_network('128.73.239.0/24'),
    ipaddress.ip_network('128.73.240.0/24'),
    ipaddress.ip_network('128.73.241.0/24'),
    ipaddress.ip_network('128.73.242.0/24'),
    ipaddress.ip_network('128.74.248.0/22'),
    ipaddress.ip_network('128.75.224.0/19'),
    ipaddress.ip_network('128.75.230.0/24'),
    ipaddress.ip_network('128.75.232.0/24'),
    ipaddress.ip_network('128.75.237.0/24'),
    ipaddress.ip_network('128.140.168.0/21'),
    ipaddress.ip_network('130.193.32.0/19'),
    ipaddress.ip_network('130.193.61.0/24'),
    ipaddress.ip_network('130.193.62.0/24'),
    ipaddress.ip_network('139.181.32.0/24'),
    ipaddress.ip_network('146.185.208.0/22'),
    ipaddress.ip_network('146.185.240.0/22'),
    ipaddress.ip_network('151.236.66.0/24'),
    ipaddress.ip_network('151.236.68.0/24'),
    ipaddress.ip_network('151.236.69.0/24'),
    ipaddress.ip_network('151.236.71.0/24'),
    ipaddress.ip_network('151.236.79.0/24'),
    ipaddress.ip_network('151.236.82.0/24'),
    ipaddress.ip_network('151.236.92.0/24'),
    ipaddress.ip_network('151.236.93.0/24'),
    ipaddress.ip_network('151.236.97.0/24'),
    ipaddress.ip_network('151.236.98.0/24'),
    ipaddress.ip_network('151.236.101.0/24'),
    ipaddress.ip_network('151.236.103.0/24'),
    ipaddress.ip_network('151.236.104.0/24'),
    ipaddress.ip_network('151.236.105.0/24'),
    ipaddress.ip_network('151.236.108.0/24'),
    ipaddress.ip_network('151.236.110.0/24'),
    ipaddress.ip_network('151.236.112.0/24'),
    ipaddress.ip_network('151.236.114.0/24'),
    ipaddress.ip_network('151.236.115.0/24'),
    ipaddress.ip_network('151.236.116.0/24'),
    ipaddress.ip_network('151.236.117.0/24'),
    ipaddress.ip_network('151.236.118.0/24'),
    ipaddress.ip_network('151.236.119.0/24'),
    ipaddress.ip_network('151.236.120.0/24'),
    ipaddress.ip_network('151.236.121.0/24'),
    ipaddress.ip_network('151.236.124.0/24'),
    ipaddress.ip_network('151.236.126.0/24'),
    ipaddress.ip_network('155.212.192.0/20'),
    ipaddress.ip_network('158.160.0.0/16'),
    ipaddress.ip_network('176.112.168.0/21'),
    ipaddress.ip_network('178.22.88.0/21'),
    ipaddress.ip_network('178.154.192.0/19'),
    ipaddress.ip_network('178.154.224.0/19'),
    ipaddress.ip_network('178.154.243.0/24'),
    ipaddress.ip_network('178.154.244.0/24'),
    ipaddress.ip_network('178.154.245.0/24'),
    ipaddress.ip_network('178.237.16.0/20'),
    ipaddress.ip_network('178.237.29.0/24'),
    ipaddress.ip_network('178.250.240.0/23'),
    ipaddress.ip_network('178.250.242.0/23'),
    ipaddress.ip_network('178.250.244.0/23'),
    ipaddress.ip_network('178.250.246.0/23'),
    ipaddress.ip_network('185.5.136.0/22'),
    ipaddress.ip_network('185.16.148.0/22'),
    ipaddress.ip_network('185.16.244.0/22'),
    ipaddress.ip_network('185.16.244.0/23'),
    ipaddress.ip_network('185.16.246.0/24'),
    ipaddress.ip_network('185.16.247.0/24'),
    ipaddress.ip_network('185.84.108.0/23'),
    ipaddress.ip_network('185.84.110.0/23'),
    ipaddress.ip_network('185.86.144.0/22'),
    ipaddress.ip_network('185.100.104.0/22'),
    ipaddress.ip_network('185.130.112.0/22'),
    ipaddress.ip_network('185.131.68.0/22'),
    ipaddress.ip_network('185.141.224.0/24'),
    ipaddress.ip_network('185.141.226.0/24'),
    ipaddress.ip_network('185.141.227.0/24'),
    ipaddress.ip_network('185.180.200.0/22'),
    ipaddress.ip_network('185.187.63.0/24'),
    ipaddress.ip_network('185.206.164.0/22'),
    ipaddress.ip_network('185.226.52.0/22'),
    ipaddress.ip_network('185.241.192.0/22'),
    ipaddress.ip_network('188.66.38.0/23'),
    ipaddress.ip_network('188.93.56.0/21'),
    ipaddress.ip_network('193.32.216.0/22'),
    ipaddress.ip_network('193.32.216.0/24'),
    ipaddress.ip_network('193.203.40.0/22'),
    ipaddress.ip_network('194.67.0.0/18'),
    ipaddress.ip_network('194.67.1.0/24'),
    ipaddress.ip_network('194.67.4.0/22'),
    ipaddress.ip_network('194.67.9.0/24'),
    ipaddress.ip_network('194.67.10.0/24'),
    ipaddress.ip_network('194.67.18.0/24'),
    ipaddress.ip_network('194.67.21.0/24'),
    ipaddress.ip_network('194.67.43.0/24'),
    ipaddress.ip_network('194.67.45.0/24'),
    ipaddress.ip_network('194.67.46.0/23'),
    ipaddress.ip_network('194.67.48.0/24'),
    ipaddress.ip_network('194.67.62.0/23'),
    ipaddress.ip_network('194.85.128.0/19'),
    ipaddress.ip_network('194.85.154.0/24'),
    ipaddress.ip_network('194.154.64.0/19'),
    ipaddress.ip_network('194.154.66.0/24'),
    ipaddress.ip_network('194.154.70.0/24'),
    ipaddress.ip_network('194.154.82.0/24'),
    ipaddress.ip_network('194.186.0.0/16'),
    ipaddress.ip_network('194.186.20.0/24'),
    ipaddress.ip_network('194.186.22.0/24'),
    ipaddress.ip_network('194.186.28.0/23'),
    ipaddress.ip_network('194.186.30.0/24'),
    ipaddress.ip_network('194.186.41.0/24'),
    ipaddress.ip_network('194.186.48.0/23'),
    ipaddress.ip_network('194.186.50.0/24'),
    ipaddress.ip_network('194.186.53.0/24'),
    ipaddress.ip_network('194.186.61.0/24'),
    ipaddress.ip_network('194.186.62.0/24'),
    ipaddress.ip_network('194.186.63.0/24'),
    ipaddress.ip_network('194.186.76.0/24'),
    ipaddress.ip_network('194.186.98.0/24'),
    ipaddress.ip_network('194.186.100.0/22'),
    ipaddress.ip_network('194.186.101.0/24'),
    ipaddress.ip_network('194.186.102.0/23'),
    ipaddress.ip_network('194.186.104.0/23'),
    ipaddress.ip_network('194.186.115.0/24'),
    ipaddress.ip_network('194.186.122.0/23'),
    ipaddress.ip_network('194.186.129.0/24'),
    ipaddress.ip_network('194.186.134.0/24'),
    ipaddress.ip_network('194.186.138.0/24'),
    ipaddress.ip_network('194.186.154.0/23'),
    ipaddress.ip_network('194.186.154.0/24'),
    ipaddress.ip_network('194.186.165.0/24'),
    ipaddress.ip_network('194.186.167.0/24'),
    ipaddress.ip_network('194.186.188.0/24'),
    ipaddress.ip_network('194.186.189.0/24'),
    ipaddress.ip_network('194.186.199.0/24'),
    ipaddress.ip_network('194.186.212.0/24'),
    ipaddress.ip_network('194.186.220.0/24'),
    ipaddress.ip_network('194.186.224.0/23'),
    ipaddress.ip_network('194.186.228.0/22'),
    ipaddress.ip_network('194.186.231.0/24'),
    ipaddress.ip_network('194.186.233.0/24'),
    ipaddress.ip_network('194.186.238.0/24'),
    ipaddress.ip_network('194.186.239.0/24'),
    ipaddress.ip_network('194.247.51.0/24'),
    ipaddress.ip_network('195.16.32.0/19'),
    ipaddress.ip_network('195.46.160.0/19'),
    ipaddress.ip_network('195.46.163.0/24'),
    ipaddress.ip_network('195.46.168.0/24'),
    ipaddress.ip_network('195.46.171.0/24'),
    ipaddress.ip_network('195.46.187.0/24'),
    ipaddress.ip_network('195.46.188.0/24'),
    ipaddress.ip_network('195.46.190.0/24'),
    ipaddress.ip_network('195.58.3.0/24'),
    ipaddress.ip_network('195.68.128.0/18'),
    ipaddress.ip_network('195.68.138.0/24'),
    ipaddress.ip_network('195.178.4.0/24'),
    ipaddress.ip_network('195.190.96.0/19'),
    ipaddress.ip_network('195.190.108.0/22'),
    ipaddress.ip_network('195.190.117.0/24'),
    ipaddress.ip_network('195.209.160.0/20'),
    ipaddress.ip_network('195.211.20.0/22'),
    ipaddress.ip_network('195.218.128.0/17'),
    ipaddress.ip_network('195.218.135.0/24'),
    ipaddress.ip_network('195.218.144.0/20'),
    ipaddress.ip_network('195.218.160.0/24'),
    ipaddress.ip_network('195.218.168.0/24'),
    ipaddress.ip_network('195.218.190.0/23'),
    ipaddress.ip_network('195.218.195.0/24'),
    ipaddress.ip_network('195.218.224.0/20'),
    ipaddress.ip_network('195.222.160.0/19'),
    ipaddress.ip_network('195.222.160.0/20'),
    ipaddress.ip_network('195.222.176.0/20'),
    ipaddress.ip_network('195.239.0.0/16'),
    ipaddress.ip_network('195.239.26.0/23'),
    ipaddress.ip_network('195.239.28.0/24'),
    ipaddress.ip_network('195.239.31.0/24'),
    ipaddress.ip_network('195.239.39.0/24'),
    ipaddress.ip_network('195.239.50.0/24'),
    ipaddress.ip_network('195.239.62.0/23'),
    ipaddress.ip_network('195.239.72.0/22'),
    ipaddress.ip_network('195.239.80.0/24'),
    ipaddress.ip_network('195.239.81.0/24'),
    ipaddress.ip_network('195.239.82.0/23'),
    ipaddress.ip_network('195.239.83.0/24'),
    ipaddress.ip_network('195.239.84.0/24'),
    ipaddress.ip_network('195.239.85.0/24'),
    ipaddress.ip_network('195.239.93.0/24'),
    ipaddress.ip_network('195.239.112.0/21'),
    ipaddress.ip_network('195.239.112.0/24'),
    ipaddress.ip_network('195.239.113.0/24'),
    ipaddress.ip_network('195.239.122.0/23'),
    ipaddress.ip_network('195.239.124.0/23'),
    ipaddress.ip_network('195.239.136.0/21'),
    ipaddress.ip_network('195.239.143.0/24'),
    ipaddress.ip_network('195.239.166.0/24'),
    ipaddress.ip_network('195.239.168.0/24'),
    ipaddress.ip_network('195.239.169.0/24'),
    ipaddress.ip_network('195.239.178.0/24'),
    ipaddress.ip_network('195.239.179.0/24'),
    ipaddress.ip_network('195.239.194.0/24'),
    ipaddress.ip_network('195.239.200.0/24'),
    ipaddress.ip_network('195.239.202.0/24'),
    ipaddress.ip_network('195.239.203.0/24'),
    ipaddress.ip_network('195.239.208.0/23'),
    ipaddress.ip_network('195.239.224.0/24'),
    ipaddress.ip_network('195.239.226.0/24'),
    ipaddress.ip_network('195.239.229.0/24'),
    ipaddress.ip_network('195.239.230.0/23'),
    ipaddress.ip_network('195.239.232.0/24'),
    ipaddress.ip_network('195.239.233.0/24'),
    ipaddress.ip_network('195.239.234.0/24'),
    ipaddress.ip_network('195.239.245.0/24'),
    ipaddress.ip_network('195.239.248.0/24'),
    ipaddress.ip_network('212.44.128.0/19'),
    ipaddress.ip_network('212.44.131.0/24'),
    ipaddress.ip_network('212.44.146.0/24'),
    ipaddress.ip_network('212.46.218.0/24'),
    ipaddress.ip_network('212.111.84.0/22'),
    ipaddress.ip_network('212.119.192.0/18'),
    ipaddress.ip_network('212.119.194.0/24'),
    ipaddress.ip_network('212.119.196.0/24'),
    ipaddress.ip_network('212.119.201.0/24'),
    ipaddress.ip_network('212.119.249.0/24'),
    ipaddress.ip_network('212.119.253.0/24'),
    ipaddress.ip_network('212.233.72.0/21'),
    ipaddress.ip_network('212.233.88.0/21'),
    ipaddress.ip_network('212.233.96.0/22'),
    ipaddress.ip_network('212.233.120.0/22'),
    ipaddress.ip_network('213.33.128.0/17'),
    ipaddress.ip_network('213.33.176.0/24'),
    ipaddress.ip_network('213.33.177.0/24'),
    ipaddress.ip_network('213.33.178.0/24'),
    ipaddress.ip_network('213.33.232.0/21'),
    ipaddress.ip_network('213.33.240.0/20'),
    ipaddress.ip_network('213.165.192.0/19'),
    ipaddress.ip_network('213.219.212.0/22'),
    ipaddress.ip_network('213.221.0.0/18'),
    ipaddress.ip_network('213.221.48.0/20'),
    ipaddress.ip_network('213.242.220.0/24'),
    ipaddress.ip_network('217.16.16.0/20'),
    ipaddress.ip_network('217.19.112.0/20'),
    ipaddress.ip_network('217.19.112.0/23'),
    ipaddress.ip_network('217.19.114.0/24'),
    ipaddress.ip_network('217.19.116.0/24'),
    ipaddress.ip_network('217.19.120.0/21'),
    ipaddress.ip_network('217.19.121.0/24'),
    ipaddress.ip_network('217.20.144.0/20'),
    ipaddress.ip_network('217.28.224.0/20'),
    ipaddress.ip_network('217.69.128.0/20'),
    ipaddress.ip_network('217.118.92.0/24'),
    ipaddress.ip_network('217.174.188.0/22'),
    ipaddress.ip_network('217.195.212.0/23'),
    ipaddress.ip_network('217.195.216.0/23'),
    ipaddress.ip_network('217.195.219.0/24'),
]

# ===========================================

MAIN_URL = 'https://raw.githubusercontent.com/Epodonios/v2ray-configs/refs/heads/main/All_Configs_Sub.txt'

ADDITIONAL_URLS = [
    "https://github.com/sakha1370/OpenRay/raw/refs/heads/main/output/all_valid_proxies.txt",
    "https://raw.githubusercontent.com/sevcator/5ubscrpt10n/main/protocols/vl.txt",
    "https://raw.githubusercontent.com/yitong2333/proxy-minging/refs/heads/main/v2ray.txt",
    "https://raw.githubusercontent.com/acymz/AutoVPN/refs/heads/main/data/V2.txt",
    "https://raw.githubusercontent.com/miladtahanian/V2RayCFGDumper/refs/heads/main/config.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_RAW.txt",
    "https://github.com/Epodonios/v2ray-configs/raw/main/Splitted-By-Protocol/trojan.txt",
    "https://raw.githubusercontent.com/YasserDivaR/pr0xy/refs/heads/main/ShadowSocks2021.txt",
    "https://raw.githubusercontent.com/mohamadfg-dev/telegram-v2ray-configs-collector/refs/heads/main/category/vless.txt",
    "https://raw.githubusercontent.com/mheidari98/.proxy/refs/heads/main/vless",
    "https://raw.githubusercontent.com/youfoundamin/V2rayCollector/main/mixed_iran.txt",
    "https://raw.githubusercontent.com/mheidari98/.proxy/refs/heads/main/all",
    "https://github.com/Kwinshadow/TelegramV2rayCollector/raw/refs/heads/main/sublinks/mix.txt",
    "https://github.com/LalatinaHub/Mineral/raw/refs/heads/master/result/nodes",
    "https://raw.githubusercontent.com/miladtahanian/multi-proxy-config-fetcher/refs/heads/main/configs/proxy_configs.txt",
    "https://raw.githubusercontent.com/Pawdroid/Free-servers/refs/heads/main/sub",
    "https://github.com/MhdiTaheri/V2rayCollector_Py/raw/refs/heads/main/sub/Mix/mix.txt",
    "https://github.com/Epodonios/v2ray-configs/raw/main/Splitted-By-Protocol/vmess.txt",
    "https://github.com/MhdiTaheri/V2rayCollector/raw/refs/heads/main/sub/mix",
    "https://github.com/Argh94/Proxy-List/raw/refs/heads/main/All_Config.txt",
    "https://raw.githubusercontent.com/shabane/kamaji/master/hub/merged.txt",
    "https://raw.githubusercontent.com/wuqb2i4f/xray-config-toolkit/main/output/base64/mix-uri",
    "https://raw.githubusercontent.com/AzadNetCH/Clash/refs/heads/main/AzadNet.txt",
    "https://raw.githubusercontent.com/STR97/STRUGOV/refs/heads/main/STR.BYPASS#STR.BYPASS%F0%9F%91%BE",
    "https://raw.githubusercontent.com/V2RayRoot/V2RayConfig/refs/heads/main/Config/vless.txt",
]

GOIDA_URL = 'https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/refs/heads/main/githubmirror/26.txt'

# Функции
def is_ip_address(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False

def is_valid_domain(host):
    if not host or host.strip() == '':
        return False
    if len(host) > 253:
        return False
    labels = host.split('.')
    for label in labels:
        if len(label) == 0 or len(label) > 63:
            return False
        if label.startswith('-') or label.endswith('-'):
            return False
    return True

def extract_host_from_vless(vless_url):
    try:
        match = re.search(r'@([^:]+):', vless_url)
        if not match:
            return None
        return match.group(1).strip()
    except:
        return None

def resolve_to_ipv4(host):
    try:
        if not is_valid_domain(host):
            return None
        return socket.gethostbyname(host)
    except (socket.gaierror, UnicodeError, OSError):
        return None

def ipv4_in_ranges(ip_obj):
    return any(ip_obj in net for net in CIDR_RANGES)

def modify_config(line, new_ip):
    modified = re.sub(r'@[^:]+:', f'@{new_ip}:', line)
    modified = re.sub(r'fp=[^&]+&', 'fp=firefox&', modified)
    return modified

def get_base_vless(url):
    try:
        url = url.split('#')[0]
        core_part = url.split('?')[0].replace('vless://', '')
        core_part = core_part.rstrip('/')
        return core_part.strip()
    except:
        return url.strip()

# Имена выходных файлов (будут в корне репозитория)
sidr_output = 'sidr_vless.txt'
clean_output = 'clean_vless.txt'

all_vless_lines = []

print("Скачиваем основной источник...")
try:
    resp = requests.get(MAIN_URL, timeout=15)
    resp.raise_for_status()
    vless = [l.strip() for l in resp.text.splitlines() if l.strip().startswith('vless://')]
    all_vless_lines.extend(vless)
    print(f"Основной: {len(vless)} vless")
except Exception as e:
    print(f"Ошибка основного: {e}")

print("Скачиваем дополнительные источники...")
for i, url in enumerate(ADDITIONAL_URLS, 1):
    try:
        resp = requests.get(url, timeout=15)
        resp.raise_for_status()
        vless = [l.strip() for l in resp.text.splitlines() if l.strip().startswith('vless://')]
        all_vless_lines.extend(vless)
        print(f"Источник {i}: {len(vless)} vless")
    except Exception as e:
        print(f"Ошибка источника {i}: {e}")

print(f"\nВсего собрано vless: {len(all_vless_lines)}")

unique_lines = list(OrderedDict.fromkeys(all_vless_lines))
print(f"После удаления дубликатов: {len(unique_lines)} уникальных")

matched_with_ip = []

with tqdm(unique_lines, desc="Обработка", unit="конфиг") as pbar:
    for line in pbar:
        host_or_ip = extract_host_from_vless(line)
        if not host_or_ip:
            continue

        final_ip = None
        if is_ip_address(host_or_ip):
            try:
                ip_obj = ipaddress.ip_address(host_or_ip)
                if ip_obj.version == 4 and ipv4_in_ranges(ip_obj):
                    final_ip = host_or_ip
            except:
                pass
        else:
            print f("Получаем IP {host_or_ip}")
            
            ip_str = resolve_to_ipv4(host_or_ip)
            print f("Получен Ip { ip_str}")
            if ip_str and ipv4_in_ranges(ipaddress.ip_address(ip_str)):
                final_ip = ip_str

        if final_ip:
            matched_with_ip.append(modify_config(line, final_ip))

with open(sidr_output, 'w', encoding='utf-8') as f:
    for cfg in matched_with_ip:
        f.write(cfg + '\n')

print(f"\nПодходящих (российские IP): {len(matched_with_ip)}. Сохранено в {sidr_output}")

print("\nДедупликация с GoidaVPN...")
goida_bases = set()
try:
    resp = requests.get(GOIDA_URL)
    resp.raise_for_status()
    goida_bases = {get_base_vless(l.strip()) for l in resp.text.splitlines() if l.strip().startswith('vless://')}
    print(f"Загружено баз Goida: {len(goida_bases)}")
except Exception as e:
    print(f"Ошибка Goida: {e}. Пропуск дедупликации.")

if goida_bases:
    clean_configs = [cfg for cfg in matched_with_ip if get_base_vless(cfg) not in goida_bases]
    duplicates = len(matched_with_ip) - len(clean_configs)

    with open(clean_output, 'w', encoding='utf-8') as f:
        for cfg in clean_configs:
            f.write(cfg + '\n')

    print(f"Удалено дубликатов Goida: {duplicates}")
    print(f"Осталось уникальных: {len(clean_configs)}. Сохранено в {clean_output}")
else:
    print("Дедупликация пропущена — используй sidr_vless.txt")

print("\nГотово!")
