#!/usr/bin/env python
"""Parse and print the list of logs, after validating signature."""
from __future__ import print_function

import base64
import hashlib
import json
import os
import sys
import time

from absl import app
from absl import flags as gflags
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
import jsonschema

from cpp_generator import generate_cpp_header
from java_generator import generate_java_source
from openssl_generator import generate_openssl_conf

FLAGS = gflags.FLAGS

gflags.DEFINE_string("log_list", None, "Logs list file to parse and print.")
gflags.DEFINE_string("signature", None, "Signature file over the list of logs.")
gflags.DEFINE_string("signer_key", None, "Public key of the log list signer.")
gflags.DEFINE_string("log_list_schema", None,
                     "JSON schema for the list of logs.")
gflags.DEFINE_string("header_output", None,
                     "If specified, generates C++ code for Chromium.")
gflags.DEFINE_string("java_output", None,
                     "If specified, generates Java code.")
gflags.DEFINE_string("java_class", "org.conscrypt.ct.KnownLogs",
                     "Fully qualified name of the generated class.")
gflags.DEFINE_string("openssl_output", None,
                     "If specified, generates a CONF file for OpenSSL.")
gflags.DEFINE_boolean("skip_signature_check", None,
                      "Skip signature check (only validate schema).")


def is_log_list_valid(json_log_list, schema_file):
    try:
        jsonschema.validate(
            json_log_list,
            json.load(open(schema_file, "rb")))
        return True
    except jsonschema.exceptions.ValidationError as e:
        print(e)
        return False
    return False


def is_signature_valid(log_list_data, signature_file, public_key_file):
    pubkey_pem = open(public_key_file, "rb").read()
    pubkey = serialization.load_pem_public_key(pubkey_pem, backend=default_backend())
    try:
        pubkey.verify(
            open(signature_file, "rb").read(),
            log_list_data,
            padding.PKCS1v15(),
            hashes.SHA256())
        return True
    except InvalidSignature:
        return False


def print_formatted_log_list(json_log_list):
    operator_id_to_name = dict(
        [(o["id"], o["name"]) for o in json_log_list["operators"]])

    for log_info in json_log_list["logs"]:
        print("%s:" % log_info["description"])
        log_operators = [
            operator_id_to_name[i].encode("utf-8")
            for i in log_info["operated_by"]]
        print("  Operated by %s and has MMD of %f hours" % (
            ", ".join(log_operators),
            log_info["maximum_merge_delay"] / (60.0 ** 2)))
        print("  At: %s" % (log_info["url"]))
        key = base64.decodestring(log_info["key"])
        hasher = hashlib.sha256()
        hasher.update(key)
        key_hash = hasher.digest()
        print("  Key ID: %s" % (base64.encodestring(key_hash)), end=' ')
        if "final_sth" in log_info:
            final_sth = log_info["final_sth"]
            print("  Log is frozen as of %s, final tree size %d" % (
                time.asctime(time.gmtime(final_sth["timestamp"] / 1000.0)),
                final_sth["tree_size"]))
        print("-" * 80)


def main(_unused_argv):
    with open(FLAGS.log_list, "rb") as f:
        json_data = f.read()

    if not FLAGS.skip_signature_check:
        if not FLAGS.signature:
            raise app.UsageError("ERROR: --signature flag not set.")
        if not FLAGS.signer_key:
            raise app.UsageError("ERROR: --signer_key flag not set.")
        if not is_signature_valid(json_data, FLAGS.signature, FLAGS.signer_key):
            raise app.UsageError(
                "ERROR: Signature over list of logs is not valid.")

    parsed_json = json.loads(json_data)
    if not FLAGS.log_list_schema:
        raise app.UsageError("ERROR: --log_list_schema flag not set.")
    if not is_log_list_valid(parsed_json, FLAGS.log_list_schema):
        raise app.UsageError(
            "ERROR: Log list is signed but does not conform to the schema.", 2)
    if FLAGS.header_output:
        generate_cpp_header(parsed_json, FLAGS.header_output)
    if FLAGS.java_output:
        generate_java_source(parsed_json, FLAGS.java_output, FLAGS.java_class)
    if FLAGS.openssl_output:
        generate_openssl_conf(parsed_json, FLAGS.openssl_output)

    if not FLAGS.header_output and \
       not FLAGS.java_output and \
       not FLAGS.openssl_output:
        print_formatted_log_list(parsed_json)


if __name__ == "__main__":
    gflags.mark_flags_as_required(["log_list", "log_list_schema"])
    gflags.mark_flags_as_mutual_exclusive(["signature", "skip_signature_check"],
                                          required=True)
    app.run(main)
