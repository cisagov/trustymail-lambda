import logging

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
        log_level = logging.DEBUG
        logging.basicConfig(format='%(asctime)-15s %(levelname)s %(message)s',
                            level=log_level)

# The default ports to check when scanning for SMTP servers
DEFAULT_SMTP_PORTS = '25,465,587'

# The default scan types to run
DEFAULT_SCAN_TYPES = {
    'mx': True,
    'starttls': True,
    'spf': True,
    'dmarc': True
}


def handler(event, context):
    """
    Handler for all Lambda events
    """
    logging.info('AWS Event was: {}'.format(event))

    # Extract some variables from the event dictionary
    domain_name = event['domain_name']
    timeout = int(event.get('timeout', 30))
    smtp_timeout = int(event.get('smtp_timeout', 5))
    smtp_localhost = event.get('smtp_localhost', None)
    smtp_ports = {int(port) for port in
                  event.get('smtp_ports', DEFAULT_SMTP_PORTS).split(',')}
    no_smtp_cache = bool(event.get('no_smtp_cache', False))
    scan_types = event.get('scan_types', DEFAULT_SCAN_TYPES)
    dns_hostnames = event.get('dns_hostnames', None)
    if dns_hostnames is not None:
        dns_hostnames = dns_hostnames.split(',')

    # Perform the scan
    import trustymail
    # Monkey patching trustymail to make it cache the PSL where we
    # want, and to make the PSL cache read-only.
    trustymail.PublicSuffixListFilename = 'cache/public-suffix-list.txt'
    trustymail.PublicSuffixListReadOnly = True
    from trustymail.trustymail import scan
    domain = scan(domain_name, timeout, smtp_timeout, smtp_localhost,
                  smtp_ports, not no_smtp_cache, scan_types, dns_hostnames)

    logging.debug('Response from scan() is {}'.format(domain))
