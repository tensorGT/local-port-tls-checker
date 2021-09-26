import argparse
import asyncio
import ipaddress
import json
import socket
import ssl
from datetime import datetime
from typing import Dict, List, Optional

ALLOWED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
