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

AWS_CREDENTIALS = {
    'access_key': None,
    'secret_key': None,
    'region': None,
}

LOG_FILENAME = '/var/log/salt/ec2-autoscale.out'
log = logging.getLogger('ec2-autoscale')
log.setLevel(logging.DEBUG)

# Add the log message handler to the logger
handler = logging.handlers.RotatingFileHandler(
              LOG_FILENAME, maxBytes=20000000, backupCount=5)

log.addHandler(handler)

def _get_credentials():
    creds = AWS_CREDENTIALS.copy()

    # Master config
    if '__opts__' in globals():
        conf = __opts__.get('ec2_config', {})
        aws = conf.get('aws', {})
        if aws.get('access_key') and aws.get('secret_key') and aws.get('region'):
            creds.update(aws)

    # 3. Get from environment
    access_key = os.environ.get('AWS_ACCESS_KEY') or os.environ.get('AWS_ACCESS_KEY_ID')
    secret_key = os.environ.get('AWS_SECRET_KEY') or os.environ.get('AWS_SECRET_ACCESS_KEY')
    if access_key and secret_key:
        creds.update(dict(access_key=access_key, secret_key=secret_key))

    return creds

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

def _get_tags(conn, instance_id):
    try:
        tags = conn.get_all_tags(filters={'resource-type': 'instance',
                                          'resource-id': instance_id})

        return tags
    except Exception, e:
        log.error("Couldn't retrieve instance tags: %s", e)
        return None

def _get_instance(conn, instance_id):
    try:
        reservations = conn.get_all_instances(instance_ids=instance_id)
        instance = reservations[0].instances[0]

        return instance
    except Exception, e:
        log.error("Couldn't retrieve instance: %s", e)
        return None

def _set_tag(conn, instance_id, name, value):
    try:
        reservations = conn.get_all_instances(instance_ids=instance_id)
        instance = reservations[0].instances[0]
        instance.add_tag(name, value)

        return 0
    except Exception, e:
        log.error("Couldn't retrieve instance-id: %s", e)
        return None

def run():
    '''
    Run the reactor
    '''

    log.debug("Incomming request !!")

    sns = data['post']

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

    log.info(message)

    instance_id = str(message['EC2InstanceId'])

    if 'launch' in sns['Subject']:
        credentials = _get_credentials()
        prefix = ""
        conn = _connect_ec2(credentials)

        if conn:
            instance = _get_instance(conn, instance_id)

            if 'Prefix' in instance.tags:
                prefix = instance.tags['Prefix']
                _set_tag(conn, instance_id, 'Name', prefix + instance_id)
            else:
                log.error("No prefix tag found on instance !")

	    instance_name = str(prefix + instance_id)
        instance_image_id = instance.image_id

        log.debug("Start logging Launch new instance !! " + instance_name)

        availability_zone = str(message['Details']['Availability Zone'])

        vm_ = __opts__.get('ec2.autoscale', {})
        log.debug("read default part of autoscaling string !! " + str(vm_))

        vm_['reactor'] = True
        vm_['instances'] = instance_name
        vm_['instance_id'] = instance_id
	    vm_['image'] = str(instance_image_id)

        minion = {}
        grains = {}
        tags = {}
        roles = {}

        grains.update({'availability_zone': availability_zone})

        if 'grains' in vm_['minion']:
            for key, value in vm_['minion']['grains'].iteritems():
		grains.update({key: value})

        for key, value in instance.tags.iteritems():
            tags.update({key: value})

        grains.update({'Tags': tags})

        if 'Roles' in instance.tags:
            grains.update({'Roles': instance.tags['Roles'].split(',')})

        if 'minion' in vm_:
            for key, value in vm_['minion'].iteritems():
                if not key.startswith('grain'):
                    minion.update({key: value})

        minion.update({'grains': grains})

        vm_list = []

        for key, value in vm_.iteritems():
            if not key.startswith('__') and not key.startswith('minion'):
                vm_list.append({key: value})

        vm_list.append({'minion': minion})

        #log.info(vm_list)

        # Fire off an event to wait for the machine
        ret = {
            'ec2_autoscale_launch': {
                'runner.cloud.create': vm_list
            }
        }
    elif 'termination' in sns['Subject']:
        credentials = _get_credentials()

        conn = _connect_ec2(credentials)

        Name = None

        if conn:
            instance = _get_instance(conn, instance_id)

            if 'Name' in instance.tags:
                Name = str(instance.tags['Name'])

        log.debug("Start logging Terminate new instance !! " + Name)

        ret = {
            'ec2_autoscale_termination': {
                'wheel.key.delete': [
                    {'match': Name},
                ]
            }
        }

    log.info(ret)

    return ret