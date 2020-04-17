'''
Configure logger
'''
import logging
from pathlib import Path
Path("/var/log/secops").mkdir(parents=True, exist_ok=True)
logging.basicConfig(
    filename="/var/log/secops/assassin.log",
    level=logging.DEBUG,
    format="[%(asctime)s] [%(filename)s:%(lineno)s - %(funcName)5s() - %(processName)s] %(levelname)s - %(message)s"
)