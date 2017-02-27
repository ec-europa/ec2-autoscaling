#!py

import pprint
import os
import logging
import time
import json
import requests
import binascii
import M2Crypto
import salt.utils.smtp as smtp
import salt.config as config
import salt.log
import boto.utils
import boto.ec2


""" Object for holding credentials and region for connecting to EC2 """
AWS_CREDENTIALS = {
    'access_key': None,
    'secret_key': None,
    'region': None,
}

""" Configuration for log file in seperate log file in salt dir """
LOG_FILENAME = '/var/log/salt/ec2-autoscale.out'
log = logging.getLogger('ec2-autoscale')
log.setLevel(logging.DEBUG)

# Add the log message handler to the logger
handler = logging.handlers.RotatingFileHandler(
              LOG_FILENAME, maxBytes=20000000, backupCount=5)

log.addHandler(handler)

""" Function to find the credentials to connect to EC2
    First check if there is a ec2_config section in the master config
    Second place to look for creds is the environment variables
"""
def _get_credentials():
    creds = AWS_CREDENTIALS.copy()

    # 1. Master config
    if '__opts__' in globals():
        conf = __opts__.get('ec2_config', {})
        aws = conf.get('aws', {})
        if aws.get('access_key') and aws.get('secret_key') and aws.get('region'):
            creds.update(aws)

    # 2. Get from environment
    access_key = os.environ.get('AWS_ACCESS_KEY') or os.environ.get('AWS_ACCESS_KEY_ID')
    secret_key = os.environ.get('AWS_SECRET_KEY') or os.environ.get('AWS_SECRET_ACCESS_KEY')
    if access_key and secret_key:
        creds.update(dict(access_key=access_key, secret_key=secret_key))

    return creds

""" Function to make a connection to EC2 and return this connection """
def _connect_ec2(creds):
    # Connect to EC2 and parse the Roles tags for this instance
    try:
        conn = boto.ec2.connect_to_region(
            creds['region'],
            aws_access_key_id=creds['access_key'],
            aws_secret_access_key=creds['secret_key'],
        )

        return conn
    except Exception, e:
        log.error("Could not get AWS connection: %s", e)
        return None

""" Return all tags for a specific Instance """
def _get_tags(conn, instance_id):
    try:
        tags = conn.get_all_tags(filters={'resource-type': 'instance',
                                          'resource-id': instance_id})

        return tags
    except Exception, e:
        log.error("Couldn't retrieve instance tags: %s", e)
        return None

""" Get an instance by instance-id """
def _get_instance(conn, instance_id):
    try:
        reservations = conn.get_all_instances(instance_ids=instance_id)
        instance = reservations[0].instances[0]

        return instance
    except Exception, e:
        log.error("Couldn't retrieve instance: %s", e)
        return None

""" Set a tag to a specific instance """
def _set_tag(conn, instance_id, name, value):
    try:
        reservations = conn.get_all_instances(instance_ids=instance_id)
        instance = reservations[0].instances[0]
        instance.add_tag(name, value)

        return 0
    except Exception, e:
        log.error("Couldn't retrieve instance-id: %s", e)
        return None

""" main function execute by the connection to the reactor """
def run():
    '''
    Run the reactor
    '''

    log.debug("Incomming request !!")

    sns = data['post']

    # If subscription is not jet confirmed, an email is sent
    if 'SubscribeURL' in sns:
        # This is just a subscription notification
        msg_kwargs = {
            'smtp.subject': 'EC2 Autoscale Subscription (via Salt Reactor)',
            'smtp.content': '{0}\r\n'.format(pprint.pformat(sns)),
        }
        smtp.send(msg_kwargs, __opts__)
        return {}

    url_check = sns['SigningCertURL'].replace('https://', '')
    url_comps = url_check.split('/')

    # Block request not comming from amazoneaws
    if not url_comps[0].endswith('.amazonaws.com'):
        # The expected URL does not seem to come from Amazon, do not try to
        # process it
        msg_kwargs = {
            'smtp.subject': 'EC2 Autoscale SigningCertURL Error (via Salt Reactor)',
            'smtp.content': (
                'There was an error with the EC2 SigningCertURL. '
                '\r\n{1} \r\n{2} \r\n'
                'Content received was:\r\n\r\n{0}\r\n').format(
                    pprint.pformat(sns), url_check, url_comps[0]
                ),
        }
        smtp.send(msg_kwargs, __opts__)
        return {}

    if not 'Subject' in sns:
        sns['Subject'] = ''

    pem_request = requests.request('GET', sns['SigningCertURL'])
    pem = pem_request.text

    str_to_sign = (
        'Message\n{Message}\n'
        'MessageId\n{MessageId}\n'
        'Subject\n{Subject}\n'
        'Timestamp\n{Timestamp}\n'
        'TopicArn\n{TopicArn}\n'
        'Type\n{Type}\n'
    ).format(**sns)

    cert = M2Crypto.X509.load_cert_string(str(pem))
    pubkey = cert.get_pubkey()
    pubkey.reset_context(md='sha1')
    pubkey.verify_init()
    pubkey.verify_update(str_to_sign.encode())

    decoded = binascii.a2b_base64(sns['Signature'])
    result = pubkey.verify_final(decoded)

    if result != 1:
        msg_kwargs = {
            'smtp.subject': 'EC2 Autoscale Signature Error (via Salt Reactor)',
            'smtp.content': (
                'There was an error with the EC2 Signature. '
                'Content received was:\r\n\r\n{0}\r\n').format(
                    pprint.pformat(sns)
                ),
        }
        smtp.send(msg_kwargs, __opts__)
        return {}

    message = json.loads(sns['Message'])
    instance_id = str(message['EC2InstanceId'])

    #SNS sent when a new server is spinning up
    if 'launch' in sns['Subject']:
        prefix = ""
        credentials = _get_credentials()
        conn = _connect_ec2(credentials)

        if conn:
            instance = _get_instance(conn, instance_id)

            if 'Prefix' in instance.tags:
                prefix = instance.tags['Prefix']

                _set_tag(conn, instance_id, 'Name', prefix + instance_id)
            else:
                log.error("No prefix tag found on instance !")

	    instance_name = str(prefix + instance_id)
        availability_zone = str(message['Details']['Availability Zone'])

        #Log in log file that an instance is created
        log.debug("Start logging Launch new instance !! " + instance_name)

        #Get the EC2 details from config and add some stuff like instance name and ID
        vm_ = __opts__.get('ec2.autoscale', {})
        vm_['reactor'] = True
        vm_['instances'] = instance_name
        vm_['instance_id'] = instance_id

        #Preparing the grains and minion info, please make a note when you declare them
        #as List or Array it is not working ! You need to declare them as Dictionary !
        minion = {}
        grains = {}

        #Add Availability zone to the grains (is used for instance with EFS where connecting
        #can be done zone depended
        grains.update({'availability_zone': availability_zone})

        #Loop over the grain info in config file
        if 'grains' in vm_['minion']:
            for key, value in vm_['minion']['grains'].iteritems():
		        grains.update({key: value})

        *Loop over the minion info in the config
        if 'minion' in vm_:
            for key, value in vm_['minion'].iteritems():
                if not key.startswith('grain'):
                    minion.update({key: value})

        #Add the grains to the minion config
        minion.update({'grains': grains})

        vm_list = []

        #Loop over the EC2 config and remove some stuff not needed by copying the rest to
        #a new array
        for key, value in vm_.iteritems():
            if not key.startswith('__') and not key.startswith('minion'):
                vm_list.append({key: value})

        #Also add the minion config with the grains to this array
        vm_list.append({'minion': minion})

        #debug info with the complete config used
        log.debug(vm_list)

        # Fire off an event to wait for the machine
        ret = {
            'ec2_autoscale_launch': {
                'runner.cloud.create': vm_list
            }
        }
    #SNS notification that gives you a termination notification
    elif 'termination' in sns['Subject']:
        credentials = _get_credentials()
        conn = _connect_ec2(credentials)
        Name = None

        #Get the name of the instance by instance-Id
        #We need this to remove it from the SALT database because we register it with name and not with id
        if conn:
            instance = _get_instance(conn, instance_id)

            if 'Name' in instance.tags:
                Name = str(instance.tags['Name'])

        #Debugging info that an instance is tirminated
        log.debug("Start logging Terminate new instance !! " + Name)

        #The actual event to remove the instance
        ret = {
            'ec2_autoscale_termination': {
                'wheel.key.delete': [
                    {'match': Name},
                ]
            }
        }

    return ret