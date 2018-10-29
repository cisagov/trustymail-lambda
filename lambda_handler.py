# import json
import logging

import dns

# from boto3 import client as boto3_client

from trustymail.domain import Domain
from trustymail.trustymail import mx_scan

# This Lambda function expects the following environment variables to be
# defined:
# 1. queue_url - The url of the SQS queue containing the events to be
# processed
# 2. elasticsearch_url - A URL corresponding to an AWS Elasticsearch
# instance, including the index where the DMARC aggregate reports
# should be written
# 3. elasticsearch_region - The AWS region where the Elasticsearch
# instance is located

# The file where any domains identified from the DMARC aggregate reports should
# be saved.
DOMAINS = None

# The file where DMARC aggregate reports should be saved.
REPORTS = None

# Whether or not to delete the objects from the S3 bucket once they are
# successfully processed
DELETE = True

# The XSD file against which the DMARC aggregate reports are to be be verified
SCHEMA = 'dmarc/rua_mod.xsd'

# The Dmarcian API token
TOKEN = None

# In the case of AWS Lambda, the root logger is used BEFORE our Lambda handler
# runs, and this creates a default handler that goes to the console.  Once
# logging has been configured, calling logging.basicConfig() has no effect.  We
# can get around this by removing any root handlers (if present) before calling
# logging.basicConfig().  This unconfigures logging and allows --debug to
# affect the logging level that appears in the CloudWatch logs.
#
# See
# https://stackoverflow.com/questions/1943747/python-logging-before-you-run-logging-basicconfig
# and
# https://stackoverflow.com/questions/37703609/using-python-logging-with-aws-lambda
# for more details.
root = logging.getLogger()
if root.handlers:
    for handler in root.handlers:
        root.removeHandler(handler)

        # Set up logging
        log_level = logging.WARNING
        logging.basicConfig(format='%(asctime)-15s %(levelname)s %(message)s',
                            level=log_level)

# Boto3 clients for SQS, S3, and Lambda.  We make these static so they can be
# reused if the Lambda function is called again on the same host.
# sqs_client = boto3_client('sqs')
# s3_client = boto3_client('s3')
# lambda_client = boto3_client('lambda')


def handler(event, context):
    """
    Handler for all Lambda events
    """
    logging.info('AWS Event was: {}'.format(event))

    # Extract some variables from the event dictionary
    # body = json.loads(event['Body'])
    # domain = body['domain']

    #
    # Perform the scan
    #

    # Our resolver
    #
    # Note that it uses the system configuration in /etc/resolv.conf
    # if no DNS hostnames are specified.
    resolver = dns.resolver.Resolver(configure=False)
    # This is a setting that controls whether we retry DNS servers if
    # we receive a SERVFAIL response from them.  We set this to False
    # because, unless the reason for the SERVFAIL is truly temporary
    # and resolves before trustymail finishes scanning the domain,
    # this can obscure the potentially informative SERVFAIL error as a
    # DNS timeout because of the way dns.resolver.query() is written.
    # See
    # http://www.dnspython.org/docs/1.14.0/dns.resolver-pysrc.html#Resolver.query.
    resolver.retry_servfail = False
    # Set some timeouts.  The timeout should be less than or equal to
    # the lifetime, but longer than the time a DNS server takes to
    # return a SERVFAIL (since otherwise it's possible to get a DNS
    # timeout when you should be getting a SERVFAIL.)  See
    # http://www.dnspython.org/docs/1.14.0/dns.resolver-pysrc.html#Resolver.query
    # and
    # http://www.dnspython.org/docs/1.14.0/dns.resolver-pysrc.html#Resolver._compute_timeout.
    resolver.timeout = float(30)
    resolver.lifetime = float(30)
    # If the user passed in DNS hostnames to query against then use them
    resolver.nameservers = [
        '8.8.8.8',
        '8.8.4.4'
    ]
    domain = Domain('dhs.gov', 30, 30, None, {25}, True,
                    ['8.8.8.8', '8.8.4.4'])
    mx_scan(resolver, domain)

    # logging.debug('Response from do_it() is {}'.format(returnVal))
