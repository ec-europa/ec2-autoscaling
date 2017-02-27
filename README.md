ec2-autoscale-reactor
=====================

This is a reactor formula, which allows the autoscaling feature in EC2 to
notify Salt when an instance is created, so that it may be automatically
bootstrapped and accepted by the Salt Master, or when an instance is deleted,
so that its key can be automatically removed from the Salt Master.

This Configuration is based on the EC2 autoscale config of SALTStack it selves.
git@github.com:saltstack-formulas/ec2-autoscale-reactor.git

Things added:
- Setting the instance name to a custom name based upon a prefix set in a tag on the autoscaling group
- Register the server into Salt by this name and not by instance-id
- adding a grain to the salt config with the Availability zone in it (This can be used for EFS for instance, connection that are zone depended)
- remove instance by name and not instance-id
   
Dependencies
------------
The following packages must be installed:

.. code-block:: yaml

    - Salt 2016.11.2
    
       salt-api
       python-boto.noarch
       zlib-devel
       libjpeg-turbo-devel.x86_64
       python-lxml.x86_64
       libxslt-devel
       libxml2-devel
       python-pip.noarch
       
       groupinstall 'Development Tools'
       
       python-devel
       libffi-devel
       python-requests.noarch


    
Master Configuration
--------------------
The following files need to be configured on the Salt Master:

.. code-block:: yaml

    - /etc/salt/master.d/smtp.conf
    - /etc/salt/master.d/reactor.conf
    - /etc/salt/master.d/ec2_config.conf
    - /etc/salt/cloud.providers.d/ec2-cloud-config.conf
    - /srv/reactor/ec2-autoscale.sls
    
All this files are included in this repo, Please make a note that you need to change all the <YOUR ...> fields

Also make a note that you need to enable the master.d include in the master config file 

.. code-block:: yaml

    ...
    default_include: master.d/*.conf
    ...

File Information
----------------

**/etc/salt/master.d/smtp.conf:**

.. code-block:: yaml

    smtp.from: <YOUR FROM ADDRESS>
    smtp.to: <YOUR TO ADDRESS>
    smtp.host: <YOURT SMTP SERVER>

This config is used to send the emails like for instance the subscription notification

**/etc/salt/master.d/ec2_config.conf:**

.. code-block:: yaml

    ec2_config:
      aws:
        access_key: <YOUR ACCESS KEY>
        secret_key: <YOUR SECRET KEY>
        region: <YOUR REGION>
        
This config settings are used for the ECS boto stuff for getting instance information and setting and reading tags
The problem is that we have a double configuration in cloud.providers.d for the actual events, these are done by salt-cloud.

**/etc/salt/master.d/reactor.conf**

.. code-block yaml

    external_auth:
      pam:
        myuser:
          - .*
          - '@runner'
          - '@wheel'
    
    rest_cherrypy:
      port: 9000
      host: 0.0.0.0
      webhook_url: /hook
      webhook_disable_auth: True
      disable_ssl: True
    
    reactor:
      - 'salt/netapi/hook/ec2/autoscale':
        - '/srv/reactor/ec2-autoscale.sls'
    
    ec2.autoscale:
      provider: ec2-cloud-config
      ssh_username: ec2-user
      grains:
        company: <YOUR COMPANY>
      minion:
        master: <YOUR MASTER IP ADDRESS>
        startup_states: highstate
        grains:
          Project: <YOUR PROJECT NAME>
          
This file contains the information to enable salt-api and register the reactor on it
Also contain the ec2.autoscale information used to fire the events for registering and unregistering

**/etc/salt/cloud.providers.d/ecs-cloud-config.conf**


.. code-block yaml

    ec2-cloud-config:
      # Set up the location of the salt master
      #
      minion:
        master: <YOUR MASTER IP ADDRESS>
    
      # Set up grains information, which will be common for all nodes
      # using this provider
      grains:
        node_type: broker
        release: 1.0.1
    
      # Specify whether to use public or private IP for deploy script.
      #
      # Valid options are:
      #     private_ips - The salt-cloud command is run inside the EC2
      #     public_ips - The salt-cloud command is run outside of EC2
      #
      ssh_interface: private_ips
    
      # Optionally configure the Windows credential validation number of
      # retries and delay between retries.  This defaults to 10 retries
      # with a one second delay betwee retries
      win_deploy_auth_retries: 10
      win_deploy_auth_retry_delay: 1
    
      # Set the EC2 access credentials (see below)
      #
      id: <YOUR ACCESS KEY>
      key: <YOUR SECRET KEY>
    
      # Make sure this key is owned by root with permissions 0400.
      #
      private_key: /etc/salt/keys/<YOUR KEY TO ACCESS THE AWS SERVERS>.pem
      keyname: <KEY NAME>
    #  securitygroup: sg-96c73ef0
    
      # Optionally configure default region
      # Use salt-cloud --list-locations <provider> to obtain valid regions
      #
      location: eu-west-1
    
      # Configure which user to use to run the deploy script. This setting is
      # dependent upon the AMI that is used to deploy. It is usually safer to
      # configure this individually in a profile, than globally. Typical users
      # are:
      #
      # Amazon Linux -> ec2-user
      # RHEL         -> ec2-user
      # CentOS       -> ec2-user
      # Ubuntu       -> ubuntu
      #
      ssh_username: ec2-user
    
      # Optionally add an IAM profile
      #iam_profile: 'arn:aws:iam::123456789012:instance-profile/ExampleInstanceProfile'
    
      driver: ec2
      
This is the EC2 configuration used to handle the event firing.

This reactor will examine the web hook received from EC2 and check its
authenticity. If issues are encountered, such as an invalid signature, or the
certificates being located outside of Amazon, a notification will be sent to
the user via email. Mail config can be done in the file smtp.conf


Finally, some extra settings must be set up to point the reactor to the
necessary Salt Cloud provider setting. Any additional settings to be used on
the target minion, that are not configured in the provider configuration
Config point to salt-cloud done in reactor.conf. Cloud config done in ec2-cloud-config.conf

EC2 Configuration
-----------------
The following must be configured in the EC2 account to be used:

.. code-block:: yaml

    - SNS HTTP Notification
    - Launch Configuration
    - Autoscaling Group
    
SNS HTTP(S) Notification
------------------------

In order to notify the reactor that an instance is being autoscaled up or down,
AWS SNS must be configured with the URL to send the notification webhook to.
Both HTTP and HTTPS are available, but it is highly recommended that HTTPS is
used.

From the AWS Console, select SNS (Push Notification Service). This will take
you to the SNS dashboard.

Click the button to Create New Topic. Enter a Topic Name, and a human-readable
Display Name, and select the Create Topic button. This will take you to the
Topic Details area.

Inside the Topic Details, click the button to Create Subscription. Select HTTP
or HTTPS as appropriate, and enter the URL to your Salt API server as the
endpoint. Assuming it is set up at ``http://saltmaster.example.com/``, the
endpoint will look like:

.. code-block:: yaml

    http://saltmaster.example.com/hook/ec2/autoscale

In this URL, ``/hook`` notifies Salt API that a webhook is being used, and
``/ec2/autoscale`` will be used to tag the event that the reactor uses to
process it. The tag that will be created by this URL will be

.. code-block:: yaml

    salt/netapi/hook/ec2/autoscale

Clicking the Subscribe button will cause a subscription notification to be sent
immediately to the endpoint. If the Master configuration is correct, the
reactor will forward the subscription notication to the configured email
address(es). This message will contain a subscribe URL which, when visited,
will activate the Subscription.

If the Salt Master is not properly configured, the endpoint can be re-entered,
and another subscription notifcation will be sent. It should be noted that once
configured, a subscription may not be deleted via the web interface until the
subscribe URL has been visited and confirmed.


Launch Configuration
--------------------
In order to start autoscaling instances, EC2 requires a launch configuration to
be set. This defines the EC2-specific variables (AMI, disks, etc.) that will be
used to spin up new instances.

From the AWS Console, select EC2 (Virtual Servers in the Cloud), which will
lead to the EC2 Management Console. From there, select Launch Configurations
from the left-hand menu.

Click the Create Launch Configuration button. Follow the wizard to select the
appropriate AMI and configuration to use. At the Review screen, click the
Create Launch Configuration button to save.


Autoscaling Group
-----------------
Once a launch configuration is defined, an autoscaling group may be configured
which defines variables such as the minimum and maximum number of instances,
and under what circumstances to add and remove instances.

From the AWS Console, select Auto Scaling Groups from the left-hand menu. Click
the Create Auto Scaling Group button. Select the option to "Create an Auto
Scaling group from an existing launch configuration". Select the Launch
Configuration, and click Next Step.

Follow the wizard to the "Configure Notifications" screen. Click the "Add
Notification" button and select the notification that was configured on SNS.
Complete the wizard as normal.


Basic Usage
-----------
Once the Salt Master and AWS have been configured, the reactor will manage
itself. When the autoscaler adds a new instance, Salt Cloud will be notified to
wait for it to become available, and bootstrap it with Salt. Its key will be
automatically accepted, and if the minion configuration includes the appropriate
startup state, then the minion will configure itself, and go to work.

When the autoscaler spins down a machine, the Wheel system inside of Salt will
be notified to delete its key from the master. This causes instances to be
completely autonomous, both in setup and tear-down.

Caveats
-------
As instances will be launched and destroyed automatically by EC2, they will not
have the opportunity to be configured with user-definable names. In the basic 
example of this reactor, the instance-id is used to register it. We extend it with 
a Prefix tag that can be used to add infront of the instance id for better naming 
conventions and possibilities of deploying a correct SALT stack. Also is the 
availability zone added into a grain, this can be used in the salt state to check  
the availabioty zone of the machine and deploy correct url's to for instance EFS 
endpoints .

