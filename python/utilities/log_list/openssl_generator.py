'''
Generates a list of CT logs for use by OpenSSL.
It is in OpenSSL CONF format and the schema is documented here:
https://github.com/openssl/openssl/blob/OpenSSL_1_1_0/doc/crypto/CTLOG_STORE_new.pod
'''

def _log_id(log):
    # Use log URL as its ID because it should be unique and is probably
    # shorter and more readable in a comma-separated list than the log
    # description.
    return log["url"].replace(",", "")

def _openssl_list(items):
    '''
    Strip commas from any items used in a list in the OpenSSL CONF format,
    becayse they would be interpreted as delimiters.
    '''
    return ", ".join(x.replace(",", "") for x in items)

def _enabled_logs_conf(logs):
    return "enabled_logs = %s\n" % (
        _openssl_list(_log_id(log) for log in logs)
    )

def _log_conf(log):
    return (
        "[%(id)s]\n"
        "description = %(description)s\n"
        "key = %(key)s\n" % {
            "id": _log_id(log),
            "description": log["description"],
            "key": log["key"],
    })

def generate_openssl_conf(json_log_list, output_path):
    '''Given a log list read from JSON, writes an OpenSSL log list to a file'''
    with open(output_path, "w") as output:
        logs = json_log_list["logs"]
        log_confs = (_log_conf(log) for log in logs)

        output.write(_enabled_logs_conf(logs) + "\n")
        output.write("\n".join(log_confs))
