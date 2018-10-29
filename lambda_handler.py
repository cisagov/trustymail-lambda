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
DEFAULT_SMTP_PORTS = {25, 465, 587}

# The default scan types to run
DEFAULT_SCAN_TYPES = {
    'mx': True,
    'starttls': True,
    'spf': True,
    'dmarc': True
}


def handler(event, context):
    """Handler for all Lambda events

    The event parameter is a dictionary containing the following keys
    and value types:
    * `domain_name` - A string containing the domain to be scanned.
      For example, "dhs.gov".
    * timeout - An integer denoting the DNS lookup timeout in seconds.
      If omitted then the default value of 30 is used.
    * smtp_timeout - An integer denoting the SMTP connection timeout
      in seconds.  If omitted then the default value of 5 is used.
    * smtp_localhost - A string containing the host name to use when
      connecting to SMTP servers.  If omitted then the fully-qualified
      domain name of the Lambda host is used.
    * smtp_ports - A list of integers, each of which is a port on
      which to look for SMTP servers.  If omitted then the default
      list containing 25, 465, and 587 is used.
    * scan_types - A dictionary consisting of the required keys "mx",
      "starttls", "spf", and "dmarc".  The corresponding values are
      booleans indicating whether or not the scan type is to be
      performed.  If omitted then all scan types are performed.
    * dns_hostnames - A list of strings, each corresponding to a DNS
      server.  For example, to use Google DNS use the value
      "['8.8.8.8', '8.8.4.4']".  If omitted then the DNS configuration
      of the Lambda host ("/etc/resolv.conf") is used.

    Parameters
    ----------
    event : dict
        A dictionary containing the scan parameters, as described
        above.

    context : LambdaContext
        The context for the Lambda function.  See the corresponding
        AWS documentation for more details:
        https://docs.aws.amazon.com/lambda/latest/dg/python-context-object.html

    Returns
    -------
    OrderedDict
        An OrderedDict specifying the fields of the
        trustymail.domain.Domain object resulting from the scan
        activity.
    """
    logging.info('AWS Event was: {}'.format(event))

    # Extract some variables from the event dictionary
    domain_name = event['domain_name']
    timeout = event.get('timeout', 30)
    smtp_timeout = event.get('smtp_timeout', 5)
    smtp_localhost = event.get('smtp_localhost', None)
    smtp_ports = event.get('smtp_ports', DEFAULT_SMTP_PORTS)
    scan_types = event.get('scan_types', DEFAULT_SCAN_TYPES)
    dns_hostnames = event.get('dns_hostnames', None)

    # Perform the scan
    import trustymail
    # Monkey patching trustymail to make it cache the PSL where we
    # want, and to make the PSL cache read-only.
    trustymail.PublicSuffixListFilename = 'cache/public-suffix-list.txt'
    trustymail.PublicSuffixListReadOnly = True
    from trustymail.trustymail import scan
    domain = scan(domain_name, timeout, smtp_timeout, smtp_localhost,
                  smtp_ports, True, scan_types, dns_hostnames)

    return domain.generate_results()
