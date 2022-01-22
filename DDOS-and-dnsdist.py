##########################  Anti DDOS and dnsdist setting script using of POWERDNS dnsdist to prevent and secure all the servers ###########################

# This function automate your settings in dnsdist configuration files. )
# Before running this script, please install python-dotenv package on your OS.
import os
import re
from dotenv import load_dotenv
load_dotenv()


# This function get and show dnsdist.security.conf file contents to users
def show_security():
    dnsdist_sec_path = os.getenv("DNSDIST_SECURITY")
    print(dnsdist_sec_path)
    with open(dnsdist_sec_path, 'r') as file:
        lines = file.readlines()
        for line in lines:
            print(line.strip())


# This function add "DROP Action" to dnsdist.security.conf file to drop all ips which have exceeded query rate
def add_drop_action():
    # Getting input values from .env file
    # Getting dnsdist.security.conf file path
    dnsdist_sec_path = os.getenv("DNSDIST_SECURITY")
    # setting drop action to dropping exceeded ips
    drop_rate = os.getenv("DROP_RATE")
    ipv4_netmask = os.getenv("IPV4_NETMASK")
    ipv6_netmask = os.getenv("IPV6_NETMASK")
    # Create drop string to insert to file
    drop_string = 'addAction(MaxQPSIPRule(', drop_rate, ', ', ipv4_netmask, ', ', ipv6_netmask, '), DropAction())'
    # Convert tuple to string with Join method
    drop_string = ''.join(drop_string)
    print(drop_string)
    with open(dnsdist_sec_path, "r") as file:
        lines = file.readlines()
    # Writing drop string to config file
    with open(dnsdist_sec_path, "w") as file1:
        for line in lines:
            if line.strip() == 'function maintenance()':
                file1.write(line)
                file1.write(drop_string)
                file1.write("\n")
            else:
                file1.write(line)
    #os.system('systemctl restart dnsdist.service')


# This function add "Exceeded NXDOMAIN rate" to dnsdist.security.conf file to prevent and block all ips which have exceeded NXDOMAINs
def add_nxdomain_action():
    # Getting input values from .env file
    # Getting dnsdist.security.conf file path
    dnsdist_sec_path = os.getenv("DNSDIST_SECURITY")
    # setting drop action to dropping exceeded ips
    nxdomain_num = os.getenv("NXDOMAIN_NUMBER")
    nxdomain_rate = os.getenv("NXDOMAIN_RATE")
    nxdomain_blk_time = os.getenv("NXDOMAIN_BLOCKTIME")
    # Create nxdomain string to insert to file
    nxdomain_string = 'addDynBlocks(exceedNXDOMAINs(', nxdomain_num, ', ', nxdomain_rate, '), "Exceeded NXD rate", ', nxdomain_blk_time, ')'
    # Convert tuple to string with Join method
    nxdomain_string = ''.join(nxdomain_string)
    print(nxdomain_string)
    with open(dnsdist_sec_path, "r") as file:
        lines = file.readlines()
    # Writing drop string to config file
    with open(dnsdist_sec_path, "w") as file1:
        for line in lines:
            if line.strip() == 'function maintenance()':
                file1.write(line)
                file1.write(nxdomain_string)
                file1.write("\n")
            else:
                file1.write(line)
    #os.system('systemctl restart dnsdist.service')


# This function add "Exceeded query rate" to dnsdist.security.conf file to prevent and block all ips which have exceeded queries
def add_exceed_rate_action():
    # Getting input values from .env file
    # Getting dnsdist.security.conf file path
    dnsdist_sec_path = os.getenv("DNSDIST_SECURITY")
    # setting drop action to dropping exceeded ips
    exceed_qps_num = os.getenv("EXCEED_QPS_NUM")
    exceed_timecuration = os.getenv("EXCEED_TIMECURATION")
    dyn_blk_time = os.getenv("DYN_BLOCKTIME")
    # Create nxdomain string to insert to file
    dyn_block_string = 'addDynBlocks(exceedQRate(', exceed_qps_num, ', ', exceed_timecuration, '), "Exceeded query rate", ', dyn_blk_time, ')'
    # Convert tuple to string with Join method
    dyn_block_string = ''.join(dyn_block_string)
    print(dyn_block_string)
    with open(dnsdist_sec_path, "r") as file:
        lines = file.readlines()
    # Writing drop string to config file
    with open(dnsdist_sec_path, "w") as file1:
        for line in lines:
            if line.strip() == 'function maintenance()':
                file1.write(line)
                file1.write(dyn_block_string)
                file1.write("\n")
            else:
                file1.write(line)
    #os.system('systemctl restart dnsdist.service')


# This function add "Exceeded ServFail rate" to dnsdist.security.conf file to prevent and block all ips which have exceeded servfails
#SERVFAIL is the all purpose “something went wrong” response. By far the most common cause for it is that there’s
# something broken or misconfigured with the authoritative DNS for the domain you’re querying so that your local DNS
# server sends out questions and never gets any answers back. After a few seconds of no responses it’ll give up and
# return this error
def add_exceed_servfail_action():
    # Getting input values from .env file
    # Getting dnsdist.security.conf file path
    dnsdist_sec_path = os.getenv("DNSDIST_SECURITY")
    # setting servfail rule/action to block exceeded ips
    # getting needed variables from .env file
    exceed_servfail_num = os.getenv("EXCEED_SERVFAIL_NUM")
    servfail_timecuration = os.getenv("SERVFAIL_TIMECURATION")
    srvfail_dyn_blk_time = os.getenv("SERVFAIL_DYN_BLOCKTIME")
    # Create ServFail  string to insert to file
    dyn_srvfail_string = 'addDynBlocks(exceedServFails(', exceed_servfail_num, ', ', servfail_timecuration, '), "Exceeded ServFail rate", ', srvfail_dyn_blk_time, ')'
    # Convert tuple to string with Join method
    dyn_srvfail_string = ''.join(dyn_srvfail_string)
    print(dyn_srvfail_string)
    with open(dnsdist_sec_path, "r") as file:
        lines = file.readlines()
    # Writing drop string to config file
    with open(dnsdist_sec_path, "w") as file1:
        for line in lines:
            if line.strip() == 'function maintenance()':
                file1.write(line)
                file1.write(dyn_srvfail_string)
                file1.write("\n")
            else:
                file1.write(line)
    #os.system('systemctl restart dnsdist.service')


# This function add "Server Pool Action" to dnsdist.security.conf file.
# This action send out all incoming traffic from specific IPs or clients to pool server.
# we know we’re getting a whole bunch of traffic for a domain used in DoS attacks, for example ‘example.com’.
# We can do two things with this kind of traffic. Either we block it outright Or we configure a server pool dedicated
# to receiving the nasty stuff
def add_server_pool_action():
    # Getting input values from .env file. Getting dnsdist.security.conf file path
    dnsdist_sec_path = os.getenv("DNSDIST_SECURITY")
    # setting server pool rule/action to assign exceeded ips and domains to abuse pool.
    # getting needed variables from .env file
    pool_srv_addr = os.getenv("POOL_SERVER_ADDRESS")
    pool_srv_name = os.getenv("POOL_SERVER_NAME")
    srv_pool_based_domain = os.getenv("SRV_POOL_BASED_DOMAIN")
    # Create pool action string to insert to file
    # Add a backend server with address 192.0.2.3 and assign it to the "abuse" pool
    pool_srv_string1 = 'newServer({address = ', repr(pool_srv_addr), ', pool = ', repr(pool_srv_name), '})'

    if srv_pool_based_domain == "yes":
        # Send all queries for "bad-domain1.example." and "bad-domain2.example" to the "abuse" pool
        bad_domains_list = os.getenv("BAD_DOMAINS_LIST")
        bad_domains_list = bad_domains_list.split(',')
        bad_domains_list1 = []
        for item in bad_domains_list:
            bad_domains_list1.append(repr(item))
        pool_srv_string2 = 'addAction({', ", ".join(bad_domains_list1), '}, PoolAction(', repr(pool_srv_name) ,'))'
    else:
        # Send all queries for "192.168.12.0/24" and "192.168.13.14" to the "abuse" pool
        bad_ips_list = os.getenv("BAD_IPS_LIST")
        bad_ips_list = bad_ips_list.split(',')
        bad_ips_list1 = []
        for item in bad_ips_list:
            bad_ips_list1.append(repr(item))
        pool_srv_string2 = 'addAction({', ", ".join(bad_ips_list1), '}, PoolAction(', repr(pool_srv_name), '))'
    #addAction({"192.168.12.0/24", "192.168.13.14"}, PoolAction("abuse"))
    #getServer(4): rmPool("abuse")
    # Convert tuple to string with Join method
    pool_srv_string1 = ''.join(pool_srv_string1)
    pool_srv_string2 = ''.join(pool_srv_string2)
    print(pool_srv_string1)
    print(pool_srv_string2)
    with open(dnsdist_sec_path, "r") as file:
        lines = file.readlines()
    # Writing pool action string to config file
    with open(dnsdist_sec_path, "w") as file1:
        for line in lines:
            file1.write(line)
        file1.write(pool_srv_string1)
        file1.write("\n")
        file1.write(pool_srv_string2)
    #os.system('systemctl restart dnsdist.service')


# This adds a 60 second dynamic block to any IP address that exceeds 10 A queries per second over 10 seconds,
# and leaves the block in place for 60 seconds.
def add_exceed_qtype_rate_action():
    # Example : addDynBlocks(exceedQTypeRate(1, 10, 10), "Exceeded A query rate", 60)
    # Getting input values from .env file
    # Getting dnsdist.security.conf file path
    dnsdist_sec_path = os.getenv("DNSDIST_SECURITY")
    # setting exceed QTypeRate action to block exceeded ips
    exceed_qtype = os.getenv("EXCEED_QTYPE")
    exceed_qtype_rate = os.getenv("EXCEED_QTYPE_RATE")
    block_qtype_time_duration = os.getenv("BLOCK_QTYPE_TIME_DURATION")
    # Create exceed QTypeRate string to insert to file
    # Set which action is performed when a query is blocked. Only DNSAction.Drop (the default), DNSAction.NoOp,
    # DNSAction.NXDomain, DNSAction.Refused, DNSAction.Truncate and DNSAction.NoRecurse are supported
    exceed_qtype_string = 'addDynBlocks(exceedQTypeRate(', exceed_qtype, ', ', exceed_qtype_rate, '), "Exceeded A query rate", ', block_qtype_time_duration, ')'
    # Convert tuple to string with Join method
    exceed_qtype_string = ''.join(exceed_qtype_string)
    print(exceed_qtype_string)
    with open(dnsdist_sec_path, "r") as file:
        lines = file.readlines()
    # Writing QTYPE string to config file
    with open(dnsdist_sec_path, "w") as file1:
        for line in lines:
            if line.strip() == 'function maintenance()':
                file1.write(line)
                file1.write(exceed_qtype_string)
                file1.write("\n")
            else:
                file1.write(line)
    #os.system('systemctl restart dnsdist.service')


# This function add "exceedRespByterate Action" to dnsdist.security.conf file.
# This action block all IPs or clients which they have exceeded response times to drop them.
def add_exceed_resp_byte_rate_action():
    # Getting input values from .env file
    # Getting dnsdist.security.conf file path
    dnsdist_sec_path = os.getenv("DNSDIST_SECURITY")
    # setting exceed QTypeRate action to block exceeded ips
    exceed_respbyte_rate = os.getenv("EXCEED_RESPBYTE_RATE")
    exceed_respbyte_time = os.getenv("EXCEED_RESPBYTE_TIME")
    block_respbyte_time_duration = os.getenv("BLOCK_RESPBYTE_TIME_DURATION")
    # Create exceed RespByteRate string to insert to file
    # Set which action is performed when a query is blocked. Only DNSAction.Drop (the default), DNSAction.NoOp,
    # DNSAction.NXDomain, DNSAction.Refused, DNSAction.Truncate and DNSAction.NoRecurse are supported
    exceed_respbyte_string = 'addDynBlocks(exceedRespByterate(', exceed_respbyte_rate, ', ', exceed_respbyte_time, \
                             '), "Exceeded Resp BW rate", ',block_respbyte_time_duration, ')'
    # Convert tuple to string with Join method
    exceed_respbyte_string = ''.join(exceed_respbyte_string)
    print(exceed_respbyte_string)
    with open(dnsdist_sec_path, "r") as file:
        lines = file.readlines()
    # Writing QTYPE string to config file
    with open(dnsdist_sec_path, "w") as file1:
        for line in lines:
            if line.strip() == 'function maintenance()':
                file1.write(line)
                file1.write(exceed_respbyte_string)
                file1.write("\n")
            else:
                file1.write(line)
    #os.system('systemctl restart dnsdist.service')


# This function add regex action to dnsdist configuration file and matches the query name against the regex.
# For example: addAction(RegexRule("[0-9]{5,}"), DelayAction(750)) -- miliseconds
# Above rule delays any query for a domain name with 5 or more consecutive degits in it.
# Another example: addAction(RegexRule("[0-9]{4,}\\.example$"), DropAction())
def add_regex_action():
    # Getting input values from .env file
    # Getting dnsdist.security.conf file path
    dnsdist_sec_path = os.getenv("DNSDIST_SECURITY")
    # setting exceed QTypeRate action to block exceeded ips
    regex_rule = os.getenv("REGEX_RULE")
    regex_action = os.getenv("REGEX_ACTION")
    # Create Regex string to insert to file
    # Set which action is performed when a query is matched. DNSAction.Drop, DNSAction.NoOp,
    # DNSAction.NXDomain, DNSAction.Refused, DNSAction.Truncate and DNSAction.NoRecurse are supported
    regex_string = 'addAction(RegexRule(', repr(regex_rule), '), ', regex_action, ')'
    # Convert tuple to string with Join method
    regex_string = ''.join(regex_string)
    print(regex_string)
    with open(dnsdist_sec_path, "r") as file:
        lines = file.readlines()
    # Writing QTYPE string to config file
    with open(dnsdist_sec_path, "w") as file1:
        for line in lines:
            if line.strip() == 'function maintenance()':
                file1.write(line)
                file1.write(regex_string)
                file1.write("\n")
            else:
                file1.write(line)
    # os.system('systemctl restart dnsdist.service')


# For Example: addDynBlocks(exceedQTypeRate(DNSQType.ANY, 5, 10), "Exceeded ANY rate", 60)
def add_exceed_any_rate_action():
    # Getting input values from .env file
    # Getting dnsdist.security.conf file path
    dnsdist_sec_path = os.getenv("DNSDIST_SECURITY")
    # setting exceed ANY rate action to block exceeded ips
    any_qps_num = os.getenv("ANY_QPS_NUMBER")
    any_time_curation = os.getenv("ANY_TIME_CURATION")
    any_time_block = os.getenv("ANY_TIME_BLOCK")
    # Create ANY rate string to insert to file
    any_rate_string = 'addDynBlocks(exceedQTypeRate(DNSQType.ANY, ', any_qps_num, ', ', any_time_curation, '), "Exceeded ANY rate", ', any_time_block, ')'
    # Convert tuple to string with Join method
    any_rate_string = ''.join(any_rate_string)
    print(any_rate_string)
    with open(dnsdist_sec_path, "r") as file:
        lines = file.readlines()
    # Writing ANY rate string to config file
    with open(dnsdist_sec_path, "w") as file1:
        for line in lines:
            if line.strip() == 'function maintenance()':
                file1.write(line)
                file1.write(any_rate_string)
                file1.write("\n")
            else:
                file1.write(line)
    # os.system('systemctl restart dnsdist.service')


# This function remove action from dnsdist.security.conf file
def remove_dnsdist_action():
    # Getting input values from .env file
    # Getting dnsdist.security.conf file path
    dnsdist_sec_path = os.getenv("DNSDIST_SECURITY")
    action_name = os.getenv("ACTION_NAME")
    if action_name == 'drop':
        with open(dnsdist_sec_path, "r") as file:
            lines = file.readlines()
    # Writing again strings to config file
        with open(dnsdist_sec_path, "w") as file1:
            for line in lines:
                if line.startswith('addAction(MaxQPSIPRule'):
                    print("DROP action deleted from configuration file")
                else:
                    file1.write(line)

    if action_name == 'nxdomain':
        with open(dnsdist_sec_path, "r") as file:
            lines = file.readlines()
    # Writing again strings to config file
        with open(dnsdist_sec_path, "w") as file1:
            for line in lines:
                if line.startswith('addDynBlocks(exceedNXDOMAINs'):
                    print("NXDOMAIN action deleted from configuration file")
                else:
                    file1.write(line)

    if action_name == 'ServFail':
        with open(dnsdist_sec_path, "r") as file:
            lines = file.readlines()
    # Writing again strings to config file
        with open(dnsdist_sec_path, "w") as file1:
            for line in lines:
                if line.startswith('addDynBlocks(exceedServFails'):
                    print("ServFail action deleted from configuration file")
                else:
                    file1.write(line)

    if action_name == 'RespByteRate':
        with open(dnsdist_sec_path, "r") as file:
            lines = file.readlines()
    # Writing again strings to config file
        with open(dnsdist_sec_path, "w") as file1:
            for line in lines:
                if line.startswith('addDynBlocks(exceedRespByterate'):
                    print("RespByteRate action deleted from configuration file")
                else:
                    file1.write(line)

    if action_name == 'QTyteRate':
        with open(dnsdist_sec_path, "r") as file:
            lines = file.readlines()
    # Writing again strings to config file
        with open(dnsdist_sec_path, "w") as file1:
            for line in lines:
                if line.startswith('addDynBlocks(exceedQTypeRate'):
                    print("QTyteRate action deleted from configuration file")
                else:
                    file1.write(line)

    if action_name == 'ExceedQRate':
        with open(dnsdist_sec_path, "r") as file:
            lines = file.readlines()
    # Writing again strings to config file
        with open(dnsdist_sec_path, "w") as file1:
            for line in lines:
                if line.startswith('addDynBlocks(exceedQRate'):
                    print("ExceedQRate action deleted from configuration file")
                else:
                    file1.write(line)

    if action_name == 'PoolAction':
        pool_srv_name = os.getenv("POOL_SERVER_NAME")
        with open(dnsdist_sec_path, "r") as file:
            lines = file.readlines()
        # Writing again strings to config file
        with open(dnsdist_sec_path, "w") as file1:
            for line in lines:
                if pool_srv_name not in line:
                    file1.write(line)

    if action_name == 'RegexAction':
        regex_search = os.getenv("REGEX_RULE")
        with open(dnsdist_sec_path, "r") as file:
            lines = file.readlines()
        # Writing again strings to config file
        with open(dnsdist_sec_path, "w") as file1:
            for line in lines:
                if regex_search not in line:
                    file1.write(line)

    # For Example: addDynBlocks(exceedQTypeRate(DNSQType.ANY, 5, 10), "Exceeded ANY rate", 60)
    if action_name == 'ANYRateAction':
        any_rate_search = 'addDynBlocks(exceedQTypeRate(DNSQType.ANY'
        with open(dnsdist_sec_path, "r") as file:
            lines = file.readlines()
        # Writing again strings to config file
        with open(dnsdist_sec_path, "w") as file1:
            for line in lines:
                if any_rate_search not in line:
                    file1.write(line)


def show_acl():
    dnsdist_acl_path = os.getenv("DNSDIST_ACL")
    print(dnsdist_acl_path)
    with open(dnsdist_acl_path, 'r') as file:
        lines = file.readlines()
        for line in lines:
            print(line.strip())


def add_acl():
    # Getting input values from .env file
    dnsdist_acl_path = os.getenv("DNSDIST_ACL")
    add_acl_range = os.getenv("ACL_RANGE")
    # Create add_acl string to insert to file
    # for example: addACL('192.0.2.0/25')
    add_acl_string = 'addACL(', repr(add_acl_range), ')'
    # Convert tuple to string with Join method
    add_acl_string = ''.join(add_acl_string)
    print(add_acl_string)
    # Writing ACL string to config file
    with open(dnsdist_acl_path, "a") as file1:
        file1.write(add_acl_string)
        file1.write("\n")
    # os.system('systemctl restart dnsdist.service')


def del_acl():
    # Getting input values from .env file
    dnsdist_acl_path = os.getenv("DNSDIST_ACL")
    del_acl_range = os.getenv("ACL_RANGE")
    with open(dnsdist_acl_path, "r") as file:
        lines = file.readlines()
    # Writing again strings to config file
    with open(dnsdist_acl_path, "w") as file1:
        for line in lines:
            if del_acl_range not in line:
                file1.write(line)
    #os.system('systemctl restart dnsdist.service')


def show_backend_servers():
    dnsdist_servers_path = os.getenv("DNSDIST_SERVERS")
    print(dnsdist_servers_path)
    with open(dnsdist_servers_path, 'r') as file:
        lines = file.readlines()
        for line in lines:
            print(line.strip())


def add_backend_servers():
    # for example: newServer({address="127.0.0.1:1001", name="PDNS-Recursor1"})
    # Getting input values from .env file
    dnsdist_servers_path = os.getenv("DNSDIST_SERVERS")
    # adding new backend servers to dnsdist
    new_srv_addr = os.getenv("NEW_BACKK_SRV_ADDR")
    new_srv_name = os.getenv("NEW_BACKK_SRV_NAME")
    # Create add servers string to insert to file
    add_backend_servers_string = 'newServer({address=', repr(new_srv_addr), ', name=', repr(new_srv_name), '})'
    # Convert tuple to string with Join method
    add_backend_servers_string = ''.join(add_backend_servers_string)
    print(add_backend_servers_string)
    # Writing add server string to config file
    with open(dnsdist_servers_path, "a") as file1:
        file1.write(add_backend_servers_string)
        file1.write("\n")
    # os.system('systemctl restart dnsdist.service')


def del_backend_servers():
    # Getting input values from .env file
    dnsdist_servers_path = os.getenv("DNSDIST_SERVERS")
    backend_srv_to_del = os.getenv("BACKK_SRV_ADDR_TO_DEL")
    with open(dnsdist_servers_path, "r") as file:
        lines = file.readlines()
    # Writing again strings to config file
    with open(dnsdist_servers_path, "w") as file1:
        for line in lines:
            if backend_srv_to_del not in line:
                file1.write(line)
    #os.system('systemctl restart dnsdist.service')


def show_spoof():
    dnsdist_spoof_path = os.getenv("DNSDIST_SPOOF")
    print(dnsdist_spoof_path)
    with open(dnsdist_spoof_path, 'r') as file:
        lines = file.readlines()
        for line in lines:
            print(line.strip())


def add_spoof():
    # for example: addAction("com", SpoofAction("1.1.1.1"))
    # Getting input values from .env file
    dnsdist_spoof_path = os.getenv("DNSDIST_SPOOF")
    # adding new spoof to dnsdist
    domain_to_spoof = os.getenv("DOMAIN_TO_SPOOF")
    addr_to_spoof = os.getenv("ADDR_TO_SPOOF")
    # Create spoof string to insert to file
    add_spoof_string = 'addAction(', repr(domain_to_spoof), ', SpoofAction(', repr(addr_to_spoof), '))'
    # Convert tuple to string with Join method
    add_spoof_string = ''.join(add_spoof_string)
    print(add_spoof_string)
    # Writing add server string to config file
    with open(dnsdist_spoof_path, "a") as file1:
        file1.write(add_spoof_string)
        file1.write("\n")
    # os.system('systemctl restart dnsdist.service'


def del_spoof():
    # Getting input values from .env file
    dnsdist_spoof_path = os.getenv("DNSDIST_SPOOF")
    # Getting input values from .env file
    domain_to_spoof = os.getenv("DOMAIN_TO_SPOOF")
    addr_to_spoof = os.getenv("ADDR_TO_SPOOF")
    with open(dnsdist_spoof_path, "r") as file:
        lines = file.readlines()
    # Writing again strings to config file
    with open(dnsdist_spoof_path, "w") as file1:
        for line in lines:
            if domain_to_spoof not in line:
                if addr_to_spoof not in line:
                    file1.write(line)
    #os.system('systemctl restart dnsdist.service')


def show_console_control_sockt():
    dnsdist_console_path = os.getenv("DNSDIST_CONSOLE")
    print(dnsdist_console_path)
    with open(dnsdist_console_path, 'r') as file:
        lines = file.readlines()
        for line in lines:
            print(line.strip())


def add_console_control_sockt():
    # For example: controlSocket('127.0.0.1:5199') and setKey("sPCnzEZaHcfHDVz7sP6qZZehIBunDazJQ00DSGuVMNo=")
    # Getting input values from .env file
    dnsdist_console_path = os.getenv("DNSDIST_CONSOLE")
    # adding new console control socket to dnsdist configuration file
    ctrl_sock_addr = os.getenv("CONTROL_SOCKET_ADDR")
    ctrl_api_key = os.getenv("CONTROL_API_KEY")
    # Create console control string to insert to file
    add_console_string1 = 'controlSocket(', repr(ctrl_sock_addr), ')'
    add_console_string2 = 'setKey(', repr(ctrl_api_key), ')'
    # Convert tuple to string with Join method
    add_console_string1 = ''.join(add_console_string1)
    add_console_string2 = ''.join(add_console_string2)
    # Writing add server string to config file
    with open(dnsdist_console_path, "r") as file:
        lines = file.readlines()
        for line in lines:
            if ctrl_sock_addr in line:
                raise Exception('The address already exist')
    with open(dnsdist_console_path, "a") as file1:
        print("The console address inserted to file")
        file1.write(add_console_string1)
        file1.write("\n")
        file1.write(add_console_string2)
        file1.write("\n")
    # os.system('systemctl restart dnsdist.service'


def del_console_control_sockt():
    # For example: controlSocket('127.0.0.1:5199') and setKey("sPCnzEZaHcfHDVz7sP6qZZehIBunDazJQ00DSGuVMNo=")
    # Getting input values from .env file
    dnsdist_console_path = os.getenv("DNSDIST_CONSOLE")
    # adding new console control socket to dnsdist configuration file
    ctrl_sock_addr = os.getenv("CONTROL_SOCKET_ADDR")
    ctrl_api_key = os.getenv("CONTROL_API_KEY")
    with open(dnsdist_console_path, "r") as file:
        lines = file.readlines()
    # Writing again strings to config file
    with open(dnsdist_console_path, "w") as file1:
        for line in lines:
            if ctrl_sock_addr not in line:
                if ctrl_api_key not in line:
                    file1.write(line)
    print("The control socket address and api deleted")
    #os.system('systemctl restart dnsdist.service')


def show_listen():
    dnsdist_listen_path = os.getenv("DNSDIST_LISTEN")
    print(dnsdist_listen_path)
    with open(dnsdist_listen_path, 'r') as file:
        lines = file.readlines()
        for line in lines:
            print(line.strip())


def add_listen():
    # For example: addLocal('0.0.0.0:5300', { reusePort=true })
    # Getting input values from .env fil
    dnsdist_listen_path = os.getenv("DNSDIST_LISTEN")
    print(dnsdist_listen_path)
    # adding new listen to dnsdist configuration file
    listen_addr = os.getenv("LISTEN_ADDR")
    # Create listen string to insert to file
    add_listen_reuseport_string = 'addLocal(', repr(listen_addr), ', { reusePort=true })'
    # Convert tuple to string with Join method
    add_listen_reuseport_string = ''.join(add_listen_reuseport_string)
    # Writing add server string to config file
    #with open(dnsdist_listen_path, "r") as file:
        #lines = file.readlines()
    with open(dnsdist_listen_path, "a") as file1:
        file1.write(add_listen_reuseport_string)
        file1.write("\n")
        print("The listen address {} inserted to file".format(repr(listen_addr)))
    # os.system('systemctl restart dnsdist.service'


def del_listen():
    # For example: addLocal('0.0.0.0:5300', { reusePort=true })
    # Getting input values from .env fil
    dnsdist_listen_path = os.getenv("DNSDIST_LISTEN")
    print(dnsdist_listen_path)
    # Deleting specefic listen from dnsdist configuration file
    listen_addr = os.getenv("LISTEN_ADDR")
    with open(dnsdist_listen_path, "r") as file:
        lines = file.readlines()
    # Writing again strings to config file
    with open(dnsdist_listen_path, "w") as file1:
        for line in lines:
            if listen_addr not in line:
                file1.write(line)
    print("The listen address {} deleted".format(repr(listen_addr)))
    # os.system('systemctl restart dnsdist.service')


def show_action_log():
    # log all queries to a 'dndist.log' file, in text-mode (not binary) appending and unbuffered
    # For example: addAction(AllRule(), LogAction("/var/log/dnsdist.log", false, true, false))
    dnsdist_log_path = os.getenv("DNSDIST_LOGS")
    print(dnsdist_log_path)
    with open(dnsdist_log_path, 'r') as file:
        lines = file.readlines()
        for line in lines:
            print(line.strip())


def add_action_log():
    # log all queries which they matched with specific RCodeRule to a 'custom-name.log' file, in text-mode (not binary) appending and unbuffered
    # For example: addAction(RCodeRule(dnsdist.SERVFAIL), LogAction("/var/log/dnsdist-servfail.log", false, true, false))
    dnsdist_log_path = os.getenv("DNSDIST_LOGS")
    # adding new action log to dnsdist configuration file
    rcoderule_log_action = os.getenv("RCODE_RULE_LOG_ACTION")
    log_file_path = os.getenv("LOG_FILE_PATH")
    # Create log action string to insert to file
    add_log_action_string = 'addAction(RCodeRule(dnsdist.', rcoderule_log_action, ', LogAction(', repr(log_file_path), ', false, true, false))'
    # Convert tuple to string with Join method
    add_log_action_string = ''.join(add_log_action_string)
    print(add_log_action_string)
    # Writing add server string to config file
    with open(dnsdist_log_path, "a") as file:
        file.write(add_log_action_string)
        file.write("\n")
        print("The new log action {} inserted to {}".format(repr(rcoderule_log_action), repr(log_file_path)))
    # os.system('systemctl restart dnsdist.service'


def del_action_log():
    # Delete action log from custom-name.log file
    # For example: addAction(RCodeRule(dnsdist.SERVFAIL), LogAction("/var/log/dnsdist-servfail.log", false, true, false))
    dnsdist_log_action_path = os.getenv("DNSDIST_LOGS")
    # Deleting specefic listen from dnsdist configuration file
    rcoderule_log_action = os.getenv("RCODE_RULE_LOG_ACTION")
    with open(dnsdist_log_action_path, "r") as file:
        lines = file.readlines()
    # Writing again strings to config file
    with open(dnsdist_log_action_path, "w") as file1:
        for line in lines:
            if rcoderule_log_action not in line:
                file1.write(line)
    print("The log action {} deleted".format(repr(rcoderule_log_action)))
    # os.system('systemctl restart dnsdist.service')


def show_policy():
    # show dnsdist policy
    # For example: setServerPolicy(roundrobin)
    dnsdist_policy_path = os.getenv("DNSDIST_POLICY")
    print(dnsdist_policy_path)
    with open(dnsdist_policy_path, 'r') as file:
        lines = file.readlines()
        for line in lines:
            print(line.strip())


def add_policy():
    # For example: setServerPolicy(roundrobin)
    # adding new policy to dnsdist configuration file
    dnsdist_policy_path = os.getenv("DNSDIST_POLICY")
    server_policy = os.getenv("SERVER_POLICY")
    # Create server policy string to insert to file
    server_policy_string = 'setServerPolicy(', server_policy, ')'
    # Convert tuple to string with Join method
    server_policy_string = ''.join(server_policy_string)
    print(server_policy_string)
    # Writing add server string to config file
    with open(dnsdist_policy_path, "a") as file:
        file.write(server_policy_string)
        file.write("\n")
        print("The {} policy added".format(repr(server_policy)))
    # os.system('systemctl restart dnsdist.service'


def del_policy():
    # For example: setServerPolicy(roundrobin)
    # Deleting policy from dnsdist configuration file
    dnsdist_policy_path = os.getenv("DNSDIST_POLICY")
    server_policy = os.getenv("SERVER_POLICY")
    with open(dnsdist_policy_path, "r") as file:
        lines = file.readlines()
    # Writing again strings to config file
    with open(dnsdist_policy_path, "w") as file1:
        for line in lines:
            if server_policy not in line:
                file1.write(line)
    print("The {} policy deleted".format(repr(server_policy)))
    # os.system('systemctl restart dnsdist.service')


def show_webserver():
    # show dnsdist webserver config file
    # For example: webserver("192.168.15.207:8080", "fwutech")
    dnsdist_webserver_path = os.getenv("DNSDIST_WEBSERVER")
    print(dnsdist_webserver_path)
    with open(dnsdist_webserver_path, 'r') as file:
        lines = file.readlines()
        for line in lines:
            print(line.strip())


def add_webserver():
    # Add dnsdist webserver to config file
    # For example: webserver("192.168.15.207:8080", "fwutech")
    dnsdist_webserver_path = os.getenv("DNSDIST_WEBSERVER")
    webserver_addr = os.getenv("WEBSERVER_ADDRESS")
    webserver_pass = os.getenv("WEBSEREVR_PASSWORD")
    # Create webserver string to insert to file
    webserver_string = 'webserver(', repr(webserver_addr), ', ', repr(webserver_pass), ')'
    # Convert tuple to string with Join method
    webserver_string = ''.join(webserver_string)
    print(webserver_string)

    # Writing add server string to config file
    with open(dnsdist_webserver_path, "r") as file:
        lines = file.readlines()
        for line in lines:
            if webserver_addr in line:
                raise Exception('The address already exist')
    with open(dnsdist_webserver_path, "w") as file1:
        for line in lines:
            file1.write(line)
            file1.write("\n")
        file1.write(webserver_string)
        file1.write("\n")
        print("The webserver with address {} added".format(repr(webserver_addr)))
    # os.system('systemctl restart dnsdist.service'


def del_webserver():
    # Delete dnsdist webserver from config file
    # For example: webserver("192.168.15.207:8080", "fwutech")
    dnsdist_webserver_path = os.getenv("DNSDIST_WEBSERVER")
    webserver_addr = os.getenv("WEBSERVER_ADDRESS")
    with open(dnsdist_webserver_path, "r") as file:
        lines = file.readlines()
    # Writing again strings to config file
    with open(dnsdist_webserver_path, "w") as file1:
        for line in lines:
            if webserver_addr not in line:
                file1.write(line)
    print("The address {} deleted".format(repr(webserver_addr)))
    # os.system('systemctl restart dnsdist.service')



def main():
    if os.getenv("DNS_ACTION_DROP") == 'yes':
        add_drop_action()

    if os.getenv("DNS_ACTION_NXDOMAIN") == 'yes':
        add_nxdomain_action()

    if os.getenv("DNS_ACTION_SERVFAIL") == 'yes':
        add_exceed_servfail_action()

    if os.getenv("DNS_ACTION_RATE_LIMIT") == 'yes':
        add_exceed_rate_action()

    if os.getenv("DNS_ACTION_QTYPE") == 'yes':
        add_exceed_qtype_rate_action()

    if os.getenv("DNS_ACTION_RESP_BYTE") == 'yes':
        add_exceed_resp_byte_rate_action()

    if os.getenv("DNS_ACTION_POOL") == 'yes':
        add_server_pool_action()

    if os.getenv("ADD_REGEX_ACTION") == 'yes':
        add_regex_action()

    if os.getenv("ADD_ANY_RATE_ACTION") == 'yes':
        add_exceed_any_rate_action()

    if os.getenv("DNS_SECURITY_SHOW") == 'yes':
        show_security()

    if os.getenv("DNS_REMOVE_ACTION") == 'yes':
        remove_dnsdist_action()

    if os.getenv("SHOW_ACL") == 'yes':
        show_acl()

    if os.getenv("ADD_ACL") == 'yes':
        add_acl()

    if os.getenv("DEL_ACL") == 'yes':
        del_acl()

    if os.getenv("SHOW_BACKEND_SERVERS") == 'yes':
        show_backend_servers()

    if os.getenv("ADD_BACKEND_SERVERS") == 'yes':
        add_backend_servers()

    if os.getenv("DEL_BACKEND_SERVERS") == 'yes':
        del_backend_servers()

    if os.getenv("SHOW_SPOOF") == 'yes':
        show_spoof()

    if os.getenv("ADD_SPOOF") == 'yes':
        add_spoof()

    if os.getenv("DEL_SPOOF") == 'yes':
        del_spoof()

    if os.getenv("SHOW_CONSOLE_CONTROL_SOCKET") == 'yes':
        show_console_control_sockt()

    if os.getenv("ADD_CONSOLE_CONTROL_SOCKET") == 'yes':
        add_console_control_sockt()

    if os.getenv("DEL_CONSOLE_CONTROL_SOCKET") == 'yes':
        del_console_control_sockt()

    if os.getenv("SHOW_LISTEN") == 'yes':
        show_listen()

    if os.getenv("ADD_LISTEN") == 'yes':
        add_listen()

    if os.getenv("DEL_LISTEN") == 'yes':
        del_listen()

    if os.getenv("SHOW_ACTION_LOGS") == 'yes':
        show_action_log()

    if os.getenv("ADD_ACTION_LOGS") == 'yes':
        add_action_log()

    if os.getenv("DEL_ACTION_LOGS") == 'yes':
        del_action_log()

    if os.getenv("SHOW_POLICY") == 'yes':
        show_policy()

    if os.getenv("ADD_POLICY") == 'yes':
        add_policy()

    if os.getenv("DEL_POLICY") == 'yes':
        del_policy()

    if os.getenv("SHOW_WEBSERVER") == 'yes':
        show_webserver()

    if os.getenv("ADD_WEBSERVER") == 'yes':
        add_webserver()

    if os.getenv("DEL_WEBSERVER") == 'yes':
        del_webserver()



#if __name__ == '__main__':
#    main()


show_security()
