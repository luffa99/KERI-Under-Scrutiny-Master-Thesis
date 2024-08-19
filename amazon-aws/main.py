import csv
import datetime
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import boto3
import paramiko
from botocore.exceptions import NoCredentialsError
import json
import requests
from requests.structures import CaseInsensitiveDict
from scp import SCPClient
import json
import socket
from tqdm import tqdm
import pandas as pd
import matplotlib.pyplot as plt
import glob
import statistics
import multiprocessing
import seaborn as sns
import matplotlib.ticker as ticker


class WatcherInfo:
    def __init__(self, name, ip, port, eid, publicip, region_name, region_key):
        self.name = name
        self.ip = ip
        self.port = port
        self.eid = eid
        self.publicip = publicip
        self.region_name = region_name
        self.region_key = region_key
    
    def setInstace(self, instance):
        self.instance = instance

class WitnessInfo:
    def __init__(self, name, ip, port, eid, publicip, region_name, region_key):
        self.name = name
        self.ip = ip
        self.port = port
        self.eid = eid
        self.publicip = publicip
        self.region_name = region_name
        self.region_key = region_key
    
    def setInstace(self, instance):
        self.instance = instance

class UInfo:
    def __init__(self, name, ip, port, users, publicip, region_name, region_key):
        self.name = name
        self.ip = ip
        self.port = port
        self.users = users
        self.publicip = publicip
        self.region_name = region_name
        self.region_key = region_key

    def setInstace(self, instance):
        self.instance = instance

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def check_port(host, port, timeout=3):
    """
    Check if a port is open on a given host.
    
    Args:
    host (str): The hostname or IP address to check.
    port (int): The port number to check.
    timeout (int, optional): The timeout for the connection attempt in seconds. Defaults to 3.
    
    Returns:
    bool: True if the port is open, False otherwise.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
    except (socket.timeout, socket.error):
        return False
    else:
        sock.close()
        return True


def generate_date_time_string():
    # Get the current date and time
    now = datetime.datetime.now()

    # Extract month, day, hour, and minute components
    month = now.strftime('%m')  # Get month (zero-padded, e.g., '01' to '12')
    day = now.strftime('%d')    # Get day (zero-padded, e.g., '01' to '31')
    hour = now.strftime('%H')   # Get hour (24-hour format, zero-padded, e.g., '00' to '23')
    minute = now.strftime('%M') # Get minute (zero-padded, e.g., '00' to '59')

    # Generate the formatted string "MMDD-hh:ss"
    formatted_string = f"{month}{day}-{hour}:{minute}"

    return formatted_string

def generate_date_time_string_with_year():
    # Get the current date and time
    now = datetime.datetime.now()

    # Extract month, day, hour, and minute components
    year = now.strftime('%Y')
    month = now.strftime('%m')  # Get month (zero-padded, e.g., '01' to '12')
    day = now.strftime('%d')    # Get day (zero-padded, e.g., '01' to '31')
    hour = now.strftime('%H')   # Get hour (24-hour format, zero-padded, e.g., '00' to '23')
    minute = now.strftime('%M') # Get minute (zero-padded, e.g., '00' to '59')

    # Generate the formatted string "MMDD-hh:ss"
    formatted_string = f"{year}-{month}-{day} @ {hour}:{minute}"

    return formatted_string

def create_ssh_client(hostname, key):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    attempts = 0
    delay = 5  # Initial delay in seconds
    max_attempts = 3
    
    while attempts < max_attempts:
        try:
            client.connect(hostname, username='ec2-user', key_filename=f"./private/{key}.pem", timeout=5)
            return client
        except Exception as e:
            print(f"SSH connection attempt failed ({e}) for {hostname}. Retrying in {delay} seconds...")
            time.sleep(delay)
            attempts += 1
            delay *= 2  # Exponential backoff: double the delay for the next attempt
    # raise Exception(f"Unble to ssh after {max_attempts} attempts- exiting")

def spawn_witness_instances(region):
    witness_instances = []
    if region.witness_hw is None:
        return witness_instances
    for instanceType in region.witness_hw.keys():
        try:
            witness_instances += region.client.create_instances(
                ImageId=region.ami,  # Amazon Linux 2 AMI (HVM), SSD Volume Type - this can change based on region
                MinCount=region.witness_hw[instanceType],
                MaxCount=region.witness_hw[instanceType],
                InstanceType=instanceType,  # Free tier eligible instance type
                KeyName=region.key,  # Replace with your key pair name
                TagSpecifications=[
                    {
                        'ResourceType': 'instance',
                        'Tags': [
                            {
                                'Key': 'Name',
                                'Value': "Py-Wit-{}".format(DATA_TIME_STRING)
                            }
                        ]
                    }
                ],
                SecurityGroupIds=[region.secgroup]
            )
        except Exception as e:
            print(f"{bcolors.FAIL}Cannot allocate {region.witness_hw[instanceType]} instances in {region.region_name} {bcolors.ENDC}")
            raise e

    return witness_instances

def start_witness_instances_iteration(_i, param):
    # i, public_ip_address = iter
    # print(i, public_ip_address)
    [public_ip_address, region_name, region_key, offset] = param
    i = _i+offset
    ssh_client = create_ssh_client(public_ip_address, region_key)
    try:
        scp_client = SCPClient(ssh_client.get_transport())
        unique_name = DATA_TIME_STRING+"_"+region_name+"_"+KEY_PAIRS[i]["public_identifier"]
        scp_client.put(os.path.join(TEST_DIRECTORY, "src", "logger.sh"), "~/")
        program_command = './logger.sh {}.log &'\
                .format(unique_name)
        ssh_client.exec_command(program_command)
        scp_client.put(os.path.join(TEMP_DIR, "witness"), "~/")
        scp_client.put(os.path.join(TEMP_DIR, "witness.yml"), "~/")       
        program_command = './witness --db-path "{}" --public-url "http://{}:{}" --http-port {} --seed "{}"  > {}.out 2> {}.error &'\
                .format(unique_name, public_ip_address, KEY_PAIRS[i]["port"], KEY_PAIRS[i]["port"], 
                        KEY_PAIRS[i]["private_seed"], unique_name, unique_name)
        ssh_client.exec_command(program_command)
        time.sleep(1)
        # Test the witness is running and is reachable from outside
        if check_port(public_ip_address, KEY_PAIRS[i]["port"]):
            # print(f"Successfully started WITNESS {unique_name}@{public_ip_address}")
            return WitnessInfo(unique_name, public_ip_address, KEY_PAIRS[i]["port"], KEY_PAIRS[i]["public_identifier"], public_ip_address, region_name, region_key)
        else:
            print(f"ERROR STARTING WITNESS {unique_name}@{public_ip_address}")
    except Exception as e:
        print(f"An error occurred while transferring the file(witness): {e}")
    finally:
        if ssh_client is not None:
            scp_client.close()
            ssh_client.close()

def start_witness_instances(instances, all_instances, region, offset):
    # Wait until all instances are running
    for instance in instances:
        all_instances.append(instance)
        # print(f'Waiting for instance {instance.id} to be running...')
        instance.wait_until_running()
        instance.load()  # Reload the instance attributes
    # print('All WIT instances are up and running!')
    time.sleep(5)
    # print('Transfer files and start WITNESSES')

    # Transfer file to each instance and start
    # for i, instance in enumerate(tqdm(instances)):
    ips = [[instance.public_ip_address, region.region_name, region.key, offset] for instance in instances]
    pool = multiprocessing.Pool()
    witnessinfos = pool.starmap(start_witness_instances_iteration, enumerate(ips))
    pool.close()
    pool.join()

    for wit, instance in zip(witnessinfos, instances):
        wit.setInstace(instance)

    # print('ALL witness instances are started!')

    return [witnessinfos, offset+len(ips)]

def spawn_watcher_instances(region):
    watcher_instances = []
    if region.watcher_hw is None:
        return watcher_instances
    for instanceType in region.watcher_hw.keys():
        try:
            watcher_instances += region.client.create_instances(
                ImageId=region.ami,  # Amazon Linux 2 AMI (HVM), SSD Volume Type - this can change based on region
                MinCount=region.watcher_hw[instanceType],
                MaxCount=region.watcher_hw[instanceType],
                InstanceType=instanceType,  # Free tier eligible instance type
                KeyName=region.key,  # Replace with your key pair name
                TagSpecifications=[
                    {
                        'ResourceType': 'instance',
                        'Tags': [
                            {
                                'Key': 'Name',
                                'Value': "Py-Wat-{}".format(DATA_TIME_STRING)
                            }
                        ]
                    }
                ],
                SecurityGroupIds=[region.secgroup]
            )
        except Exception as e:
            print(f"{bcolors.FAIL}Cannot allocate {region.watcher_hw[instanceType]} instances in {region.region_name} {bcolors.ENDC}")
            raise e

    return watcher_instances

def start_watcher_instances_iteration(j, param):
    [public_ip_address, region_name, region_key, offset] = param
    i = j+50+offset # Watchers have indexes from 50 to 99
    ssh_client = create_ssh_client(public_ip_address, region_key)
    try:
        scp_client = SCPClient(ssh_client.get_transport())
        unique_name = DATA_TIME_STRING+"_"+region_name+"_"+KEY_PAIRS[i]["public_identifier"]
        scp_client.put(os.path.join(TEST_DIRECTORY, "src", "logger.sh"), "~/")
        program_command = './logger.sh {}.log &'\
                .format(unique_name)
        ssh_client.exec_command(program_command)
        scp_client.put(os.path.join(TEMP_DIR, "watcher"), "~/")
        scp_client.put(os.path.join(TEMP_DIR, "watcher.yml"), "~/")       
        program_command = 'mkdir config'
        ssh_client.exec_command(program_command)
        scp_client.put(os.path.join(TEMP_DIR, "config", "witnessConfigs.json"), "~/config/") 
        # Do insert witnesses as initial_oobi for watchers!
        program_command = r"sed -i 's/initial_oobis: \[\]/initial_oobis: '$(sed -e ':a; N; $!ba; s/\n//g; s/[]\/$*.^[]/\\&/g; s/ //g' config/witnessConfigs.json)'/' watcher.yml"
        ssh_client.exec_command(program_command)
        program_command = './watcher --db-path "{}" --public-url "http://{}:{}" --http-port {} --tel-storage-path {}_tel --seed "{}"  > {}.out 2> {}.error &'\
                .format(unique_name, public_ip_address, KEY_PAIRS[i]["port"], KEY_PAIRS[i]["port"], unique_name,
                        KEY_PAIRS[i]["private_seed"], unique_name, unique_name)
        ssh_client.exec_command(program_command)
        time.sleep(1)
        # Test the witness is running and is reachable from outside
        if check_port(public_ip_address, KEY_PAIRS[i]["port"]):
            # print(f"Successfully started WATCHER {unique_name}@{public_ip_address}")
            return WatcherInfo(unique_name, public_ip_address, KEY_PAIRS[i]["port"], KEY_PAIRS[i]["public_identifier"], public_ip_address, region_name, region_key)
        else:
            print(f"ERROR STARTING WATCHER {unique_name}@{public_ip_address}")
    except Exception as e:
        print(f"An error occurred while transferring the file (watcher): {e}")
    finally:
        if ssh_client is not None:
            scp_client.close()
            ssh_client.close()

def start_watcher_instances(instances, all_instances, region, offset):
    # Wait until all instances are running
    for instance in instances:
        all_instances.append(instance)
        # print(f'Waiting for instance {instance.id} to be running...')
        instance.wait_until_running()
        instance.load()  # Reload the instance attributes
    # print('All WAT instances are up and running!')
    time.sleep(1)
    # print('Transfer files and start WATCHERS')
    # Transfer file to each instance and start
    # for j, instance in enumerate(tqdm(instances)):

    ips = [[instance.public_ip_address, region.region_name, region.key, offset] for instance in instances]
    pool = multiprocessing.Pool()
    watchersinfos = pool.starmap(start_watcher_instances_iteration, enumerate(ips))
    pool.close()
    pool.join()

    for wit, instance in zip(watchersinfos, instances):
        wit.setInstace(instance)

    # print('ALL watcher instances are started!')
    
    return [watchersinfos, offset+len(ips)]

def spawn_users_instances(region):
    user_instances = []
    if region.user_hw is None:
        return user_instances
    for instanceType in region.user_hw.keys():
        try:
            user_instances += region.client.create_instances(
                ImageId=region.ami,  # Amazon Linux 2 AMI (HVM), SSD Volume Type - this can change based on region
                MinCount=region.user_hw[instanceType],
                MaxCount=region.user_hw[instanceType],
                InstanceType=instanceType,  # Free tier eligible instance type
                KeyName=region.key,  # Replace with your key pair name
                TagSpecifications=[
                    {
                        'ResourceType': 'instance',
                        'Tags': [
                            {
                                'Key': 'Name',
                                'Value': "Py-U-{}".format(DATA_TIME_STRING)
                            }
                        ]
                    }
                ],
                SecurityGroupIds=[region.secgroup]
            )
        except Exception as e:
            print(f"{bcolors.FAIL}Cannot allocate {region.user_hw[instanceType]} instances in {region.region_name} {bcolors.ENDC}")
            raise e

    return user_instances

def start_user_instances_iteration(_i, ips):
    # [public_ip_address, private_ip_address], i = iter
    [public_ip_address, private_ip_address, region_name, region_key, offset] = ips
    i =_i + offset
    ssh_client = create_ssh_client(public_ip_address, region_key)
    try:
        scp_client = SCPClient(ssh_client.get_transport())
        unique_name = DATA_TIME_STRING+"_"+region_name+"_U"+str(i)
        scp_client.put(os.path.join(TEST_DIRECTORY, "src", "logger.sh"), "~/")
        program_command = './logger.sh {}.log &'\
                .format(unique_name)
        ssh_client.exec_command(program_command)
        scp_client.put(os.path.join(TEMP_DIR, "tests"), "~/")
        program_command = 'mkdir config'
        ssh_client.exec_command(program_command)
        scp_client.put(os.path.join(TEMP_DIR, "config", "witnessConfigs.json"), "~/config/")      
        scp_client.put(os.path.join(TEMP_DIR, "config", "watcherConfigs.json"), "~/config/")     
        program_command = './tests {} {} {} {} {} {} > {}.out 2> {}.error &'\
                .format(TOT_USERS_PER_USER_INSTANCE, USER_WITNESSES, USER_WITNESSES_THREESHOLD, USER_WATCHERS,
                        private_ip_address, DATA_TIME_STRING, unique_name, unique_name)
        ssh_client.exec_command(program_command)
        time.sleep(1)
        # Test the witness is running and is reachable from outside
        if check_port(public_ip_address, 5000):
            # print(f"Successfully started USER {unique_name}@{public_ip_address}")
            return UInfo(unique_name, public_ip_address, 5000, TOT_USERS_PER_USER_INSTANCE, public_ip_address, region_name, region_key)
        else:
            print(f"ERROR STARTING USER {unique_name}@{public_ip_address}")
    except Exception as e:
        print(f"An error occurred while transferring the file (user): {e}")
    finally:
        if ssh_client is not None:
            scp_client.close()
            ssh_client.close()

def start_user_instances(instances, all_instances, region, offset):
    # Wait until all instances are running
    for instance in instances:
        all_instances.append(instance)
        # print(f'Waiting for instance {instance.id} to be running...')
        instance.wait_until_running()
        instance.load()  # Reload the instance attributes
    # print('All USER instances are up and running!')
    time.sleep(1)
    # print('Transfer files and start USERS')

    # Transfer file to each instance and start
    # for i, instance in enumerate(tqdm(instances)):
    ips = [[instance.public_ip_address, instance.private_ip_address, region.region_name, region.key, offset] for instance in instances]
    pool = multiprocessing.Pool()
    userinfos = pool.starmap(start_user_instances_iteration, enumerate(ips))
    pool.close()
    pool.join()
    # Filter out nones
    f_userinfos = [x for x in userinfos if x is not None]
    started_ips = {uinfo.publicip for uinfo in f_userinfos}
    f_ips = [ip for ip in ips if ip[0] in started_ips]
    f_instances = [instance for instance in instances if instance.public_ip_address in started_ips]

    for wit, instance in zip(f_userinfos, f_instances):
        wit.setInstace(instance)

    return [f_userinfos, offset+len(f_ips)]

def build_witness_watcher():
    # Build command
    command = ["cargo", "build", "--manifest-path", os.path.join(KERIOX_DIRECTORY,"Cargo.toml"), "--bin", "witness", "--bin", "watcher", "--release"]
    my_env = os.environ.copy()
    my_env["CARGO_IGNORE_PARENT_MANIFEST"] = f"true"

    # Execute the command
    result = subprocess.run(command, env=my_env, capture_output=True) # ''', capture_output=True, text=True'''

    # Print the output
    # print(result.stderr)
    # print(result.stdout)

    # Check the return code to see if the command was successful
    if result.returncode == 0:
        print("Witness & Watcher build OK.")
    else:
        exit("[build_witness_watcher] Build failed with return code: {}".format(result.returncode))

    shutil.copy(os.path.join(KERIOX_DIRECTORY, "target", "release", "witness"), TEMP_DIR)
    shutil.copy(os.path.join(KERIOX_DIRECTORY, "target", "release", "watcher"), TEMP_DIR)
    shutil.copy(os.path.join(TEST_DIRECTORY, "config", "witness.yml"), TEMP_DIR)
    shutil.copy(os.path.join(TEST_DIRECTORY, "config", "watcher.yml"), TEMP_DIR)

def build_tests():
    # Build command
    command = ["cargo", "build", "--manifest-path", os.path.join(TEST_DIRECTORY,"Cargo.toml"), "--bin", "tests", "--bin", "issuer", "--target=x86_64-unknown-linux-musl", "--release"]
    my_env = os.environ.copy()
    my_env["CARGO_IGNORE_PARENT_MANIFEST"] = f"true"
    result = subprocess.run(command, env=my_env, capture_output=True) #''', capture_output=True, text=True'''
    # print(result.stderr)
    if result.returncode == 0:
        print("Tests build OK.")
    else:
        exit("[build_tests] Build failed with return code: {}".format(result.returncode))
    # print("skipping test build")
    shutil.copy(os.path.join(TEST_DIRECTORY, "target", "x86_64-unknown-linux-musl", "release", "tests"), TEMP_DIR)
    shutil.copy(os.path.join(TEST_DIRECTORY, "target", "x86_64-unknown-linux-musl", "release", "issuer"), TEMP_DIR)

def initiate_ec2_session(region_name):
    # Create a session using your AWS credentials
    session = boto3.Session(
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_ACCESS_KEY_SECRET,
        region_name=region_name  # Specify your preferred region
    )
    ec2 = session.resource('ec2')
    return ec2

def parse_keypairs():
    with open(os.path.join(TEST_DIRECTORY, "config", "wit_wat_keypairs.json"), 'r') as file:
        parsed_json = json.load(file)
        return parsed_json

def create_wsconfigfile(ws, filename):
    array_of_dicts = []
    for w in ws:
        array_of_dicts.append({"eid" : w.eid, 
                               "scheme" : "http",
                               "url" : f"http://{w.ip}:{w.port}"})
    with open(os.path.join(TEMP_DIR, "config", filename), 'w') as file:
        json.dump(array_of_dicts, file, indent=4)

def create_nodesconfigfile(users, filename):
    array_of_dicts = []
    for u in users:
        array_of_dicts.append(f"http://{u.publicip}:{u.port}")
    with open(os.path.join(TEMP_DIR, "config", filename), 'w') as file:
        json.dump(array_of_dicts, file, indent=4)

def sanity_check_parameters():
    if TOT_WATCHERS < 1 or TOT_WITNESS < 1:
        exit(f"Error: Must have at least 1 Witness and 1 Watcher, but TOT_WATCHERS = {TOT_WATCHERS} and TOT_WITNESS = {TOT_WITNESS}")
    if TOT_WATCHERS > 50 or TOT_WITNESS > 50:
        exit(f"Error: Must have at most 50 Witnesses and 50 Watchers, but TOT_WATCHERS = {TOT_WATCHERS} and TOT_WITNESS = {TOT_WITNESS}")

    if USER_WITNESSES > TOT_WITNESS:
        exit(f"Error: USER_WITNESSES = {USER_WITNESSES} > TOT_WITNESS = {TOT_WITNESS}")
    if USER_WITNESSES_THREESHOLD > USER_WITNESSES:
        exit(f"Error: USER_WITNESSES_THREESHOLD = {USER_WITNESSES_THREESHOLD} > USER_WITNESSES = {USER_WITNESSES}")
    if USER_WATCHERS > TOT_WATCHERS:
        exit(f"Error: USER_WATCHERS = {USER_WATCHERS} > TOT_WATCHERS = {TOT_WATCHERS}")
    if USER_WITNESSES < 1 or USER_WITNESSES_THREESHOLD < 1 or USER_WATCHERS < 1:
        exit(f"Error: User needs at least 1 Witness and 1 Watcher, but USER_WITNESSES = {USER_WITNESSES}, USER_WITNESSES_THREESHOLD = {USER_WITNESSES_THREESHOLD}, USER_WATCHERS = {USER_WATCHERS}")

    if ISSUER_WITNESSES > TOT_WITNESS:
        exit(f"Error: ISSUER_WITNESSES = {ISSUER_WITNESSES} > TOT_WITNESS = {TOT_WITNESS}")
    if ISSUER_WITNESSES_THREESHOLD > ISSUER_WITNESSES:
        exit(f"Error: ISSUER_WITNESSES_THREESHOLD = {ISSUER_WITNESSES_THREESHOLD} > ISSUER_WITNESSES = {ISSUER_WITNESSES}")
    if ISSUER_WATCHERS > TOT_WATCHERS:
        exit(f"Error: ISSUER_WATCHERS = {ISSUER_WATCHERS} > TOT_WATCHERS = {TOT_WATCHERS}")
    if ISSUER_WITNESSES < 1 or ISSUER_WITNESSES_THREESHOLD < 1 or ISSUER_WATCHERS < 1:
        exit(f"Error: Issuer needs at least 1 Witness and 1 Watcher, but ISSUER_WITNESSES = {ISSUER_WITNESSES}, ISSUER_WITNESSES_THREESHOLD = {ISSUER_WITNESSES_THREESHOLD}, ISSUER_WATCHERS = {ISSUER_WATCHERS}")

    if not os.path.isdir(KERIOX_DIRECTORY):
        exit(f"Error: KERIOX_DIRECTORY = '{KERIOX_DIRECTORY}' is not a valid directory")
    if not os.path.isdir(TEST_DIRECTORY):
        exit(f"Error: TEST_DIRECTORY = '{TEST_DIRECTORY}' is not a valid directory")

def start_issuer():
    command = [os.path.join(TEMP_DIR,"issuer") + f" {ISSUER_WITNESSES} {ISSUER_WITNESSES_THREESHOLD} {ISSUER_WATCHERS} {DATA_TIME_STRING}"]
    return subprocess.Popen(command, shell=True, cwd=TEMP_DIR)

def collect_output_iteration(arg):
    [name, public_ip_address, region_key] = arg
    ssh_client = create_ssh_client(public_ip_address, region_key)
    try:
        scp_client = SCPClient(ssh_client.get_transport())
        scp_client.get(name+".out", os.path.join(TEMP_DIR, "out", name+".out"))
        scp_client.get(name+".error", os.path.join(TEMP_DIR, "error", name+".error"))
        if os.stat(os.path.join(TEMP_DIR, "error", name+".error")).st_size == 0:
            os.remove(os.path.join(TEMP_DIR, "error", name+".error"))
        scp_client.get(name+".log", os.path.join(TEMP_DIR, "performance", name+".log"))
        if len(name) < 40: # Only users have shorter names
            scp_client.get("times.json", os.path.join(TEMP_DIR, "performance", name+"_times.json"))
    except Exception as e:
        print(f"An error occurred while transferring the file (collect): {e}")
    finally:
        if ssh_client is not None:
            scp_client.close()
            ssh_client.close()

def collect_output(all_objects):
    # Transfer file to each instance and start
    os.mkdir(os.path.join(TEMP_DIR, "out"))
    os.mkdir(os.path.join(TEMP_DIR, "error"))
    os.mkdir(os.path.join(TEMP_DIR, "performance"))
    os.mkdir(os.path.join("experiments", f"24{DATA_TIME_STRING}"))

    filtred_objects = [[object.name, object.instance.public_ip_address, object.region_key] for object in all_objects]
    pool = multiprocessing.Pool()
    _ = pool.map(collect_output_iteration, filtred_objects)
    pool.close()
    pool.join()

    # for object in tqdm(all_objects):
    shutil.copytree(os.path.join(TEMP_DIR, "out"), os.path.join("experiments", f"24{DATA_TIME_STRING}", "out"))
    shutil.copytree(os.path.join(TEMP_DIR, "error"), os.path.join("experiments", f"24{DATA_TIME_STRING}", "error"))
    shutil.copytree(os.path.join(TEMP_DIR, "performance"), os.path.join("experiments", f"24{DATA_TIME_STRING}", "performance"))

def terminate_instances(instances, regions, wait=False):
    instance_ids = [instance.id for instance in instances]
    # response = ec2.instances.filter(InstanceIds=instance_ids).terminate()
    for k in regions.keys():
        try:
            regions[k].client.instances.filter(InstanceIds=instance_ids).terminate()
        except Exception:
            pass
        try:
            regions[k].client.instances.terminate()        
        except Exception:
            pass
        regions[k].client.instances.terminate()
    
    print(f"{bcolors.FAIL}Sent message to terminate all instances{bcolors.ENDC}")

    # Wait until all instances are running
    if wait:
        for instance in instances:
            # print(f'Waiting for instance {instance.id} to terminate...')
            try:
                instance.wait_until_terminated()
            except Exception:
                pass

def parse_execution_results(input_string, user_results):
    try:
        # Define a regex pattern to capture the required numbers
        pattern = r"Executed (\d+) users / (\d+) success / (\d+) fail"
        match = re.match(pattern, input_string)
        
        if not match:
            raise ValueError("Input string is not in the expected format.")
        
        _users = int(match.group(1))
        success = int(match.group(2))
        fail = int(match.group(3))
        
        user_results["success"] += success
        user_results["fail"] += fail
    
    except Exception as e:
        pass

def parse_execution_times(input_strings, user_results):
    try:
        # Define a regex pattern to capture the required numbers
        # pattern = r'Inception executed in: (\d+)ms'
        # match = re.match(pattern, input_string_1)
        # if not match:
        #     raise ValueError("Input string is not in the expected format.")
        # user_results["icp_time"].append(int(match.group(1)))
        # # print(int(match.group(1)))

        # pattern = r'KEL executed in: (\d+)ms'
        # match = re.match(pattern, input_string_2)
        # if not match:
        #     raise ValueError("Input string is not in the expected format.")
        # user_results["kel_time"].append(int(match.group(1)))

        for i in range(6):
            j = str(i+1)
            pattern = r'Test '+j+r': (\d+)ms'
            match = re.match(pattern, input_strings[i])
            if not match:
                raise ValueError("Input string is not in the expected format.")
            user_results[j].append(int(match.group(1)))

    except Exception as e:
        pass

def print_execution_times(users, user_results):
    for user in users:
        try:
            with open(os.path.join(TEMP_DIR, "out", user.name+".out"), 'r') as file:
                lines = file.readlines()
                # print(f"{bcolors.OKBLUE}{user.name}{bcolors.ENDC}")
                last_three_lines = lines[-3:]
                parse_execution_results(lines[-5], user_results)
                parse_execution_times([lines[-6], lines[-5], lines[-4], lines[-3], lines[-2], lines[-1]], user_results)
                # for line in last_three_lines:
                #     print(line, end='')  # end='' to avoid adding extra newlines
        except Exception as e:
            print(f"{bcolors.WARNING}Cannot find out file for {user.name}{bcolors.ENDC}")
        try:
            with open(os.path.join(TEMP_DIR, "performance", user.name+"_times.json"), 'r') as file:
                data = json.load(file)
                for icp_time in data[0]:
                    user_results["1"].append(int(icp_time))
                for kel_time in data[1]:
                    user_results["2"].append(int(kel_time))
                for rot_time in data[2]:
                    user_results["3"].append(int(rot_time))
                for rot_time in data[3]:
                    user_results["4"].append(int(rot_time))
                for rot_time in data[4]:
                    user_results["5"].append(int(rot_time))
                for rot_time in data[5]:
                    user_results["6"].append(int(rot_time))
        except Exception as e:
            print(f"{bcolors.WARNING}Cannot find times file for {user.name}{bcolors.ENDC}")

    if len(user_results["icp_time"]) > 0 and len(user_results["kel_time"]) > 0:
        print(f"{bcolors.OKBLUE}ICP TIME: avg={statistics.mean(user_results['icp_time'])}ms, median={statistics.median(user_results['icp_time'])}ms, min={min(user_results['icp_time'])}ms, max={max(user_results['icp_time'])}ms{bcolors.ENDC}")
        print(f"{bcolors.OKBLUE}KEL TIME: avg={statistics.mean(user_results['kel_time'])}ms, median={statistics.median(user_results['kel_time'])}ms, min={min(user_results['kel_time'])}ms, max={max(user_results['kel_time'])}ms{bcolors.ENDC}")

    if len(user_results["1"]) > 0 and len(user_results["6"]) > 0:
        print(f"{bcolors.OKBLUE}1 TIME (SINGLE): avg={statistics.mean(user_results['1'])}ms, median={statistics.median(user_results['1'])}ms, min={min(user_results['1'])}ms, max={max(user_results['1'])}ms{bcolors.ENDC}")
        print(f"{bcolors.OKBLUE}2 TIME (SINGLE): avg={statistics.mean(user_results['2'])}ms, median={statistics.median(user_results['2'])}ms, min={min(user_results['2'])}ms, max={max(user_results['2'])}ms{bcolors.ENDC}")
        print(f"{bcolors.OKBLUE}3 TIME (SINGLE): avg={statistics.mean(user_results['3'])}ms, median={statistics.median(user_results['3'])}ms, min={min(user_results['3'])}ms, max={max(user_results['3'])}ms{bcolors.ENDC}")
        print(f"{bcolors.OKBLUE}4 TIME (SINGLE): avg={statistics.mean(user_results['4'])}ms, median={statistics.median(user_results['4'])}ms, min={min(user_results['4'])}ms, max={max(user_results['4'])}ms{bcolors.ENDC}")
        print(f"{bcolors.OKBLUE}5 TIME (SINGLE): avg={statistics.mean(user_results['5'])}ms, median={statistics.median(user_results['5'])}ms, min={min(user_results['5'])}ms, max={max(user_results['5'])}ms{bcolors.ENDC}")
        print(f"{bcolors.OKBLUE}6 TIME (SINGLE): avg={statistics.mean(user_results['6'])}ms, median={statistics.median(user_results['6'])}ms, min={min(user_results['6'])}ms, max={max(user_results['6'])}ms{bcolors.ENDC}")
        with open('experients_3.csv', mode='a', newline='') as file:
            writer = csv.writer(file)
            writer.writerow([DATA_TIME_STRING,TOT_USERS_PER_USER_INSTANCE,TOT_USERS,user_results['success'],USER_WITNESSES_THREESHOLD,TOT_WITNESS,USER_WATCHERS,TOT_WATCHERS,statistics.mean(user_results['1']),statistics.mean(user_results['3']),statistics.mean(user_results['6'])])


def read_data(file):
    columns = ['Time', 'CPU_Load', 'Memory', 'Memory_Bytes', 'Network_Tx', 'Network_Rx']
    df = pd.read_csv(file, header=None, names=columns)
    df['Time'] = pd.to_datetime(df['Time'])
    return df

def load_timings_from_folder(folder_path):
    timings_1 = []
    timings_2 = []
    timings_3 = []
    timings_4 = []
    timings_5 = []
    timings_6 = []

    # Iterate over all files in the specified folder
    for filename in os.listdir(folder_path):
        if filename.endswith("times.json"):
            file_path = os.path.join(folder_path, filename)
            with open(file_path, 'r') as file:
                data = json.load(file)
                timings_1.extend(data[0])  # "Timings 1" is the first list
                timings_2.extend(data[1])  # "Timings 2" is the second list
                timings_3.extend(data[2])  # "Timings 1" is the first list
                timings_4.extend(data[3])  # "Timings 2" is the second list
                timings_5.extend(data[4])  # "Timings 1" is the first list
                timings_6.extend(data[5])  # "Timings 2" is the second list
    
    return timings_1, timings_2, timings_3, timings_4, timings_5, timings_6

def plot_distribution(data, title, xlabel, ylabel, filename, users):
    plt.figure(figsize=(10, 6))
    sns.histplot(data, kde=True)

    # Print total number of collected times on the chart
    tot_users = len(data)
    plt.title(f"{title}\nTotal users: {tot_users} ({users})")

    # Improve readability of the x-axis values
    plt.gca().xaxis.set_major_formatter(ticker.FuncFormatter(lambda x, pos: f"{int(x):,}".replace(',', "'")))
    plt.xlabel(xlabel)
    plt.ylabel(ylabel)
    plt.savefig(os.path.join("experiments", filename))
    plt.close()

def plot_time_distributions(file_name, user_results):
    experiment, users = file_name
    timings_1, timings_2, timings_3, timings_4, timings_5, timings_6 = load_timings_from_folder(os.path.join("experiments", "24"+experiment, "performance"))

    # Plot distribution for "Timings 1"
    plot_distribution(timings_1, 'Distribution of Timings 1', 'Execution Time (ms)', 'Frequency', os.path.join(f"24{experiment}", f"{experiment}_{users}_t1.png"), users)
    # Plot distribution for "Timings 2"
    plot_distribution(timings_2, 'Distribution of Timings 2', 'Execution Time (ms)', 'Frequency', os.path.join(f"24{experiment}", f"{experiment}_{users}_t2.png"), users)
    # Plot distribution for "Timings 2"
    plot_distribution(timings_3, 'Distribution of Timings 3', 'Execution Time (ms)', 'Frequency', os.path.join(f"24{experiment}", f"{experiment}_{users}_t3.png"), users)
    # Plot distribution for "Timings 2"
    plot_distribution(timings_4, 'Distribution of Timings 4', 'Execution Time (ms)', 'Frequency', os.path.join(f"24{experiment}", f"{experiment}_{users}_t4.png"), users)
    # Plot distribution for "Timings 2"
    plot_distribution(timings_5, 'Distribution of Timings 5', 'Execution Time (ms)', 'Frequency', os.path.join(f"24{experiment}", f"{experiment}_{users}_t5.png"), users)
    # Plot distribution for "Timings 2"
    plot_distribution(timings_6, 'Distribution of Timings 6', 'Execution Time (ms)', 'Frequency', os.path.join(f"24{experiment}", f"{experiment}_{users}_t6.png"), users)

    # Write success rate
    with open(os.path.join("experiments", "24"+experiment, experiment)+'.json', 'w') as json_file:
        json.dump(user_results, json_file, indent=4)

# Function to plot data
def plot_data(dfs, columns_to_plot, user_results, interactive):
    plt.figure(figsize=(10, 6))
    # colors = ['blue', 'green', 'red', 'orange', 'purple', 'brown', 'pink', 'gray', 'olive', 'cyan']
    colors = [{"Witness" : "blue", "Watcher" : "green", "User" : "red"}, {"Witness" : "cyan", "Watcher" : "olive", "User" : "orange"}]
    labels = {"Witness" : False, "Watcher" : False, "User" : False}
    alpha = {"Witness" : 1.0, "Watcher" : 1.0, "User" : 0.2}
    for _df in dfs:
        df = _df.df
        if not labels[_df.name]:
            for idx, col in enumerate(columns_to_plot):
                plt.plot(df['Time'], df[col], label=_df.name+f" ({col})", color=colors[idx%2][_df.name])
            labels[_df.name] = True
        else:
            for idx, col in enumerate(columns_to_plot):
                plt.plot(df['Time'], df[col], color=colors[idx%2][_df.name], alpha=alpha[_df.name])

    try:
        with open(os.path.join(TEMP_DIR, "issuer_timings.json"), 'r') as file:
            timing_data = json.load(file)

        for val in timing_data:
            plt.axvline(x = pd.to_datetime(val), color = 'gray')
    except Exception as e:
        print(f"{bcolors.WARNING}Cannot find issuer timing data{bcolors.ENDC}")

    plt.xlabel('Time')
    plt.ylabel('Values (load %)')
    plt.suptitle(f'Experiment - 24{DATA_TIME_STRING} - {user_results["success"]}/{user_results["tot"]}({user_results["success"]/user_results["tot"]*100}%) success rate', y=1.01, fontsize=15)
    plt.title(f"WITNESS={TOT_WITNESS}, WATCHERS={TOT_WATCHERS}, USER_INSTANCES={TOT_USER_INSTANCES}, USERS_PER_UI={TOT_USERS_PER_USER_INSTANCE},\nU_WIT={USER_WITNESSES}, U_THREESHOLD={USER_WITNESSES_THREESHOLD}, U_WAT={USER_WATCHERS}, I_WIT={ISSUER_WITNESSES}, I_THREESHOLD={ISSUER_WITNESSES_THREESHOLD}, I_WAT={ISSUER_WATCHERS},\nWIT={WITNESS_HW}, WAT={WATCHER_HW}, U={USER_HW}", style = "italic", fontsize=10)
    plt.legend()
    # if len(user_results["icp_time"]) > 0 and len(user_results["kel_time"]) > 0:
    #     icp_times = f"ICP TIME: avg={statistics.mean(user_results['icp_time'])}ms, median={statistics.median(user_results['icp_time'])}ms, min={min(user_results['icp_time'])}ms, max={max(user_results['icp_time'])}ms"
    #     kel_times = f"KEL TIME: avg={statistics.mean(user_results['kel_time'])}ms, median={statistics.median(user_results['kel_time'])}ms, min={min(user_results['kel_time'])}ms, max={max(user_results['kel_time'])}ms"
        # icp_times_s = f"ICP TIME (SINGLE): avg={statistics.mean(user_results['icp_time_s'])}ms, median={statistics.median(user_results['icp_time_s'])}ms, min={min(user_results['icp_time_s'])}ms, max={max(user_results['icp_time_s'])}ms"
        # kel_times_s = f"KEL TIME (SINGLE): avg={statistics.mean(user_results['kel_time_s'])}ms, median={statistics.median(user_results['kel_time_s'])}ms, min={min(user_results['kel_time_s'])}ms, max={max(user_results['kel_time_s'])}ms"

        # plt.figtext(0.5, 0.01, icp_times, ha="center", fontsize=10)
        # plt.figtext(0.5, -0.02, kel_times, ha="center", fontsize=10)
        # plt.figtext(0.5, -0.06, icp_times_s, ha="center", fontsize=10)
        # plt.figtext(0.5, -0.09, kel_times_s, ha="center", fontsize=10)

    plt.savefig(os.path.join("experiments", "24"+DATA_TIME_STRING, f"{DATA_TIME_STRING}_{TOT_USER_INSTANCES*TOT_USERS_PER_USER_INSTANCE}.png"), dpi=150, bbox_inches='tight', pad_inches=0.3) 
    # if interactive:
    #     plt.show()

def plot_data_traffic(dfs, columns_to_plot, user_results, interactive):
    plt.figure(figsize=(10, 6))
    # colors = ['blue', 'green', 'red', 'orange', 'purple', 'brown', 'pink', 'gray', 'olive', 'cyan']
    colors = [{"Witness" : "blue", "Watcher" : "green", "User" : "red"}, {"Witness" : "cyan", "Watcher" : "olive", "User" : "orange"}]
    labels = {"Witness" : False, "Watcher" : False, "User" : False}
    alpha = {"Witness" : 1.0, "Watcher" : 1.0, "User" : 0.2}
    for _df in dfs:
        df = _df.df
        if not labels[_df.name]:
            for idx, col in enumerate(columns_to_plot):
                plt.plot(df['Time'], df[col], label=_df.name+f" ({col})", color=colors[idx%2][_df.name])
            labels[_df.name] = True
        else:
            for idx, col in enumerate(columns_to_plot):
                plt.plot(df['Time'], df[col], color=colors[idx%2][_df.name], alpha=alpha[_df.name])

    try:
        with open(os.path.join(TEMP_DIR, "issuer_timings.json"), 'r') as file:
            timing_data = json.load(file)

        for val in timing_data:
            plt.axvline(x = pd.to_datetime(val), color = 'gray')
    except Exception as e:
        print(f"{bcolors.WARNING}Cannot find issuer timing data{bcolors.ENDC}")

    plt.xlabel('Time')
    plt.ylabel('Bytes')
    plt.suptitle(f'Experiment - 24{DATA_TIME_STRING} - {user_results["success"]}/{user_results["tot"]}({user_results["success"]/user_results["tot"]*100}%) success rate', y=1.01, fontsize=15)
    plt.title(f"WITNESS={TOT_WITNESS}, WATCHERS={TOT_WATCHERS}, USER_INSTANCES={TOT_USER_INSTANCES}, USERS_PER_UI={TOT_USERS_PER_USER_INSTANCE},\nU_WIT={USER_WITNESSES}, U_THREESHOLD={USER_WITNESSES_THREESHOLD}, U_WAT={USER_WATCHERS}, I_WIT={ISSUER_WITNESSES}, I_THREESHOLD={ISSUER_WITNESSES_THREESHOLD}, I_WAT={ISSUER_WATCHERS},\nWIT={WITNESS_HW}, WAT={WATCHER_HW}, U={USER_HW}", style = "italic", fontsize=10)
    plt.legend()
    if len(user_results["icp_time"]) > 0 and len(user_results["kel_time"]) > 0:
        icp_times = f"ICP TIME: avg={statistics.mean(user_results['icp_time'])}ms, median={statistics.median(user_results['icp_time'])}ms, min={min(user_results['icp_time'])}ms, max={max(user_results['icp_time'])}ms"
        kel_times = f"KEL TIME: avg={statistics.mean(user_results['kel_time'])}ms, median={statistics.median(user_results['kel_time'])}ms, min={min(user_results['kel_time'])}ms, max={max(user_results['kel_time'])}ms"
        icp_times_s = f"ICP TIME (SINGLE): avg={statistics.mean(user_results['icp_time_s'])}ms, median={statistics.median(user_results['icp_time_s'])}ms, min={min(user_results['icp_time_s'])}ms, max={max(user_results['icp_time_s'])}ms"
        kel_times_s = f"KEL TIME (SINGLE): avg={statistics.mean(user_results['kel_time_s'])}ms, median={statistics.median(user_results['kel_time_s'])}ms, min={min(user_results['kel_time_s'])}ms, max={max(user_results['kel_time_s'])}ms"
        rot_times_s = f"ROT TIME (SINGLE): avg={statistics.mean(user_results['rot_time_s'])}ms, median={statistics.median(user_results['rot_time_s'])}ms, min={min(user_results['rot_time_s'])}ms, max={max(user_results['rot_time_s'])}ms"

        plt.figtext(0.5, 0.01, icp_times, ha="center", fontsize=10)
        plt.figtext(0.5, -0.02, kel_times, ha="center", fontsize=10)
        plt.figtext(0.5, -0.06, icp_times_s, ha="center", fontsize=10)
        plt.figtext(0.5, -0.09, kel_times_s, ha="center", fontsize=10)
        plt.figtext(0.5, -0.12, rot_times_s, ha="center", fontsize=10)

    plt.savefig(os.path.join("experiments", "24"+DATA_TIME_STRING, f"{DATA_TIME_STRING}_{TOT_USER_INSTANCES*TOT_USERS_PER_USER_INSTANCE}_net.png"), dpi=150, bbox_inches='tight', pad_inches=0.3) 
    # if interactive:
    #     plt.show()


class df_with_name:
    def __init__(self, df, name) -> None:
        self.df = df
        self.name = name

def plot(all_objects, user_results, interactive):
    # files = glob.glob(os.path.join(TEMP_DIR,"performance",'*.log'))  # Change this path to your actual files' path
    # dataframes = [read_data(file) for file in files]
    dataframes = []
    for o in all_objects:
        name = ""
        if isinstance(o, WitnessInfo):
            name += "Witness"
        if isinstance(o, WatcherInfo):
            name += "Watcher"
        if isinstance(o, UInfo):
            name += "User"
        dataframes.append(df_with_name(read_data(os.path.join(TEMP_DIR, "performance", o.name+".log")), name))

    
    # Prompt user for columns to plot
    available_columns = ['CPU_Load', 'Memory', 'Memory_Bytes', 'Network_Tx', 'Network_Rx']
    # print("Available columns to plot:", available_columns)
    # columns_to_plot = ['']
    # if interactive:
    #     columns_to_plot = input("Enter columns to plot, separated by commas (default: 'CPU_Load', 'Memory'): ").split(',')
    
    # if columns_to_plot == ['']:  # Use default if no input
    #     columns_to_plot = ['CPU_Load', 'Memory']
    
    # columns_to_plot = [col.strip() for col in columns_to_plot if col.strip() in available_columns]
    
    # if not columns_to_plot:
    #     print("No valid columns selected. Plotting default 'CPU_Load', 'Memory'")
    #     columns_to_plot = ['CPU_Load', 'Memory']
    
    plot_data(dataframes, ['CPU_Load', 'Memory'], user_results, interactive)
    plot_data_traffic(dataframes, ['Network_Tx', 'Network_Rx'], user_results, interactive)
    plot_time_distributions((DATA_TIME_STRING, TOT_USER_INSTANCES*TOT_USERS_PER_USER_INSTANCE), user_results)

def init_notifications():
    url = "https://dev1.rail-suisse.ch/keri/SL9iQPv3eoQctEsqqTtobysmGJCeVAJRSBn8fAO5HVThkombleK6UoxZjHPEtFqP/start_experiment.php"
    headers = CaseInsensitiveDict()
    headers["Content-Type"] = "application/x-www-form-urlencoded"
    data = rf"experiment={DATA_TIME_STRING}"
    resp = requests.post(url, headers=headers, data=data)
    if resp.status_code != 200:
        print("Error: server")

def get_notifications():
    url = "https://dev1.rail-suisse.ch/keri/SL9iQPv3eoQctEsqqTtobysmGJCeVAJRSBn8fAO5HVThkombleK6UoxZjHPEtFqP/get.php"
    headers = CaseInsensitiveDict()
    headers["Content-Type"] = "application/x-www-form-urlencoded"
    data = f"experiment={DATA_TIME_STRING}&count=count6"
    resp = requests.post(url, headers=headers, data=data)
    if resp.status_code != 200:
        print("Error: server")
        return 0
    else:
        return (int(resp.text))

class Region:    
    def __init__(self, region_name, key, ami, secgroup, max_instances, user_hw=None, witness_hw=None, watcher_hw=None) -> None:
        self.region_name = region_name
        self.key = key
        self.ami = ami
        self.secgroup = secgroup
        self.max_instances = max_instances
        self.user_hw = user_hw
        self.witness_hw = witness_hw
        self.watcher_hw = watcher_hw
        self.client = initiate_ec2_session(self.region_name)
    
    def current_instances(self):
        ans = 0
        if self.user_hw is not None:
            for x in self.user_hw.keys():
                if x == 'c5a.2xlarge':
                    ans += self.user_hw[x]*8
                elif x == 't3.micro':
                    ans += self.user_hw[x]*2
                elif x == 'c5a.4xlarge':
                    ans += self.user_hw[x]*16
        if self.witness_hw is not None:
            for x in self.witness_hw.keys():
                if x == 'c5a.2xlarge':
                    ans += self.witness_hw[x]*8
                elif x == 't3.micro':
                    ans += self.witness_hw[x]*2
                elif x == 'c5a.4xlarge':
                    ans += self.witness_hw[x]*16
        if self.watcher_hw is not None:
            for x in self.watcher_hw.keys():
                if x == 'c5a.2xlarge':
                    ans += self.watcher_hw[x]*8
                elif x == 't3.micro':
                    ans += self.watcher_hw[x]*2
                elif x == 'c5a.4xlarge':
                    ans += self.watcher_hw[x]*16

        return ans

def check_values(regions):
    users = 0
    watchers = 0
    witnesses = 0
    for k in regions.keys():
        if regions[k].user_hw is not None:
            for i in regions[k].user_hw:
                users += regions[k].user_hw[i]
        if regions[k].witness_hw is not None:
            for i in regions[k].witness_hw:
                witnesses += regions[k].witness_hw[i]
        if regions[k].watcher_hw is not None:
            for i in regions[k].watcher_hw:
                watchers += regions[k].watcher_hw[i]
    
    if users != TOT_USER_INSTANCES+1:
        raise ArithmeticError(f"Required {TOT_USER_INSTANCES} users, but declared {users}")
    if watchers != TOT_WATCHERS:
        raise ArithmeticError(f"Required {TOT_WATCHERS} users, but declared {watchers}")
    if witnesses != TOT_WITNESS:
        raise ArithmeticError(f"Required {TOT_WITNESS} users, but declared {witnesses}")

def start_experiment(interactive=True):
    sanity_check_parameters()

    build_witness_watcher()
    build_tests()

    init_notifications()

    all_instances = []

    # max values: north-1=500, west3=300, west2=16, west1=96, central1=300

    users_to = TOT_USER_INSTANCES+1 # One is reserve instance, in case it does not start!
    wit_to = TOT_WITNESS
    wat_to = TOT_WATCHERS

    # regions = {
    #     'eu-north-1' : Region('eu-north-1', 'keri-eu-north-1', 'ami-0d3a2960fcac852bc', 'sg-010f4b91f1c363a94', 
    #                           user_hw={'t3.micro' : 2}, witness_hw={'t3.micro' : 2}, watcher_hw={'t3.micro' : 2}),
    #     # 'eu-west-3' : Region('eu-west-3', 'keri-eu-west-3', 'ami-052984d1804039ba8', 'sg-04c5d97fa9a0afe9d', 
    #     #                      user_hw={'t3.micro' : 8}, witness_hw={'c5a.2xlarge' : 4}, watcher_hw={'c5a.2xlarge' : 1}),
    #     # 'eu-west-2' : Region('eu-west-2', 'keri-eu-west-2', 'ami-06373f703eb245f45', 'sg-04486d968753b8a5e', 
    #     #                      user_hw={'t3.micro' : 6}),
    #     # 'eu-west-1' : Region('eu-west-1', 'keri-eu-west-1', 'ami-04fe22dfadec6f0b6', 'sg-0a69a2f3061367156', 
    #     #                      user_hw={'t3.micro' : 40}),
    #     # 'eu-central-1' : Region('eu-central-1', 'keri-eu-central-1', 'ami-09e647bf7a368e505', 'sg-0fdd4e8e7fe908e0d', 
    #     #                         user_hw={'t3.micro' : 8}, witness_hw={'c5a.2xlarge' : 4}, watcher_hw={'c5a.2xlarge' : 1})
    # }
    regions = {
        'eu-north-1' : Region('eu-north-1', 'keri-eu-north-1', 'ami-0d3a2960fcac852bc', 'sg-010f4b91f1c363a94', 500),
        'eu-west-3' : Region('eu-west-3', 'keri-eu-west-3', 'ami-052984d1804039ba8', 'sg-04c5d97fa9a0afe9d', 300),
        'eu-west-2' : Region('eu-west-2', 'keri-eu-west-2', 'ami-06373f703eb245f45', 'sg-04486d968753b8a5e', 16),
        'eu-west-1' : Region('eu-west-1', 'keri-eu-west-1', 'ami-04fe22dfadec6f0b6', 'sg-0a69a2f3061367156', 96),
        'eu-central-1' : Region('eu-central-1', 'keri-eu-central-1', 'ami-09e647bf7a368e505', 'sg-0fdd4e8e7fe908e0d', 300),
        'eu-central-2' : Region('eu-central-2', 'keri-eu-central-2', 'ami-0f5486c334d83fb8c', 'sg-0f6b05ff6f03374bf', 300),
        'eu-south-2' : Region('eu-south-2', 'keri-eu-south-2', 'ami-02b019cb5a1d6ca83', 'sg-0cce99b35c2aab6cc', 300),
        'eu-south-1' : Region('eu-south-1', 'keri-eu-south-1', 'ami-0dd563d88411245af', 'sg-0f628f193b87307c8', 300)
    }

    ### Auto ASSIGNMENT -> order of Wit, Wat, Users is important!
    # Assign witnesses
    while wit_to > 0:
        prev = wit_to
        for r in regions.keys():
            if wit_to <= 0:
                continue
            elif regions[r].current_instances() >= regions[r].max_instances:
                continue
            elif regions[r].witness_hw is None:
                regions[r].witness_hw = {'c5a.2xlarge' : 1}
                wit_to -= 1
            else:
                regions[r].witness_hw['c5a.2xlarge'] += 1
                wit_to -= 1
        if prev == wit_to:
            raise Exception("Capacity exceeded")
        
    # Assign watchers
    while wat_to > 0:
        prev = wat_to
        for r in regions.keys():
            if wat_to <= 0:
                continue
            elif regions[r].current_instances() >= regions[r].max_instances:
                continue
            elif regions[r].watcher_hw is None:
                regions[r].watcher_hw = {'c5a.2xlarge' : 1}
                wat_to -= 1
            else:
                regions[r].watcher_hw['c5a.2xlarge'] += 1
                wat_to -= 1
        if prev == wat_to:
            raise Exception("Capacity exceeded")
        
    # Assign users
    while users_to > 0:
        prev = users_to
        for r in regions.keys():
            if users_to <= 0:
                continue
            elif regions[r].current_instances() >= regions[r].max_instances:
                continue
            elif regions[r].user_hw is None:
                regions[r].user_hw = {'t3.micro' : 1}
                users_to -= 1
            else:
                regions[r].user_hw['t3.micro'] += 1
                users_to -= 1
        if prev == users_to:
            raise Exception("Capacity exceeded")
        
    # for r in regions.keys():
    #     print(r)
    #     print(regions[r].user_hw, regions[r].witness_hw, regions[r].watcher_hw)

    check_values(regions)

    try:
        # Spawn all the EC2 instances
        wit_instances = {}
        wat_instances = {}
        usr_instances = {}
        wit_offset = 0
        wat_offset = 0
        usr_offset = 0
        for k in regions.keys():
            wit_instances[k] = spawn_witness_instances(regions[k])
            wat_instances[k] = spawn_watcher_instances(regions[k])
            usr_instances[k] = spawn_users_instances(regions[k])

        witnesses = []
        for k in regions.keys():
            [new_witnesses, wit_offset] = start_witness_instances(wit_instances[k], all_instances, regions[k], wit_offset)
            witnesses += new_witnesses
        print('==> ALL WITNESSES are running!')
        create_wsconfigfile(witnesses, "witnessConfigs.json")
        
        watchers = []
        for k in regions.keys():
            [new_watchers, wat_offset] = start_watcher_instances(wat_instances[k], all_instances, regions[k], wat_offset)
            watchers += new_watchers
        print('==> ALL WATCHERS are running!')
        create_wsconfigfile(watchers, "watcherConfigs.json")

        users = []
        for k in regions.keys():
            [new_users, usr_offset] = start_user_instances(usr_instances[k], all_instances, regions[k], usr_offset)
            users += new_users
        print('==> ALL USERS are running!')
        create_nodesconfigfile(users, "nodesConfigs.json")

        print()
        print(f"{bcolors.WARNING}STARTING TEST WITH ISSUER in 3s{bcolors.ENDC}")
        print()
        time.sleep(3)
        issuer_retcode = start_issuer().wait()

        if issuer_retcode == 0:
            print("Collecting output after 300s...")
            for i in tqdm(range(300)):
                time.sleep(1)
                if get_notifications() >= TOT_USER_INSTANCES:
                    tqdm.write("All users are done. Continue")
                    break
        else:
            print(f"{bcolors.FAIL}Error during issuer execution. Collecting output{bcolors.ENDC}")

        collect_output(witnesses+watchers+users)

        print(f'Files: {TEMP_DIR}')
        user_results = {"tot" : TOT_USERS_PER_USER_INSTANCE*TOT_USER_INSTANCES, "success" : 0, "fail" : 0, "icp_time" : [], "kel_time" : [], "icp_time_s" : [], "kel_time_s" : [], "rot_time_s" : [],
                        "1" : [], "2" : [], "3" : [], "4" : [], "5" : [], "6" : [], 
                        "TOT_WITNESS" : TOT_WITNESS, 
                        "TOT_WATCHERS" : TOT_WATCHERS,
                        "TOT_USER_INSTANCES": TOT_USER_INSTANCES,
                        "TOT_USERS_PER_USER_INSTANCE" : TOT_USERS_PER_USER_INSTANCE,
                        "WITNESS_HW" : WITNESS_HW,
                        "WATCHER_HW" : WATCHER_HW,
                        "USER_HW" : USER_HW,
                        "USER_WITNESSES" : USER_WITNESSES,
                        "USER_WITNESSES_THREESHOLD" : USER_WITNESSES_THREESHOLD,
                        "USER_WATCHERS" : USER_WATCHERS,
                        "ISSUER_WITNESSES" : ISSUER_WITNESSES,
                        "ISSUER_WITNESSES_THREESHOLD" : ISSUER_WITNESSES_THREESHOLD,
                        "ISSUER_WATCHERS" : ISSUER_WATCHERS
        }
        print_execution_times(users, user_results)
        overview_color = bcolors.WARNING if user_results["success"] == user_results["tot"] else bcolors.FAIL
        print(f"{overview_color}In total: {user_results['tot']} Users, {user_results['success']} success, {user_results['fail']} fail, {user_results['tot']-user_results['success']-user_results['fail']} unknown{bcolors.ENDC}")
        plot(users+witnesses+watchers, user_results, interactive)
        if interactive:
            input("Enter to STOP the infrastructure")
    finally:
        terminate_instances(all_instances, regions, not interactive)

    if interactive:
        input(f"Click to delete temp dir {TEMP_DIR}")
        shutil.rmtree(TEMP_DIR)

if __name__ == '__main__':
    n = len(sys.argv)
    if n != 6:
        raise Exception("Usage: <TOT_WITNESSES> <TOT_WATCHERS> <TOT_USERS> <M_WITNESSES> <M_WATCHERS>")

    with open('private/secrets.json', 'r') as f:
        secrets = json.load(f)

    AWS_ACCESS_KEY_ID = secrets['AWS_ACCESS_KEY_ID']
    AWS_ACCESS_KEY_SECRET = secrets['AWS_ACCESS_KEY_SECRET']

    KERIOX_DIRECTORY = "/home/icn-temp/Documents/keriox/"
    TEST_DIRECTORY = "/home/icn-temp/Documents/2024_Lucas-Falardi_KERI-under-scrutiny/workspace/basic-kel"

    TOT_WITNESS = int(sys.argv[1])
    TOT_WATCHERS = int(sys.argv[2])
    TOT_USERS = int(sys.argv[3])


    TOT_USERS_PER_USER_INSTANCE = 10
    TOT_USER_INSTANCES = TOT_USERS // TOT_USERS_PER_USER_INSTANCE
    if TOT_USERS % TOT_USERS_PER_USER_INSTANCE != 0:
        exit(f"Tot user has to be a multiple of {TOT_USERS_PER_USER_INSTANCE}")
    WITNESS_HW = 'c5a.2xlarge'
    WATCHER_HW = 'c5a.2xlarge' #c5a.2xlarge
    USER_HW = 't3.micro'

    TEMP_DIR = tempfile.mkdtemp()
    os.mkdir(os.path.join(TEMP_DIR, "config"))
    print(f"Working in: {TEMP_DIR}")
    DATA_TIME_STRING = generate_date_time_string()
    print(f"#################### EXPERIMENT {DATA_TIME_STRING} #############################")
    print(sys.argv)
    KEY_PAIRS = parse_keypairs()

    USER_WITNESSES = int(sys.argv[4])
    USER_WITNESSES_THREESHOLD = USER_WITNESSES
    USER_WATCHERS = int(sys.argv[5])
    ISSUER_WITNESSES = TOT_WITNESS
    ISSUER_WITNESSES_THREESHOLD = TOT_WITNESS
    ISSUER_WATCHERS = TOT_WATCHERS # Necessary for sending OOBI

    start_experiment(interactive=False)