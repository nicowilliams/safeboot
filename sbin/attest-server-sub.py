"""
Quote and Eventlog validating Attestation Server.

This is a python flask server implementing a single API end-point. This is launched
(for compatibility's sake) from sbin/attest-server. See the comments there for more
explanation about the functionality.
"""
import flask
from flask import request, abort, send_file
import subprocess
import os, sys
from stat import *
from markupsafe import escape
from werkzeug.utils import secure_filename
import tempfile
import logging
import yaml
import hashlib

# hard code the hashing algorithm used
alg = 'sha256'

# This subroutine is the meat in the sandwich. Its only argument is a path to
# the input tarball (the "quotefile") that was received from the attesting
# host/client, and it returns a 2-tuple of status code and response tarball (as
# a byte array, not a path) for returning to the host/client. This function is
# called by the flask-handling code further down, which extracts the input
# tarball from the http request and returns the output tarball in the http
# response.

def attest_verify(quote_file):
	# verify that the Endorsment Key came from an authorized TPM,
	# that the quote is signed by a valid Attestation Key
	sub = subprocess.run(["./sbin/tpm2-attest", "verify", quote_file ],
		stdout=subprocess.PIPE,
		stderr=sys.stderr,
	)

	quote_valid = sub.returncode == 0

	# The output contains YAML formatted hash of the EK and the PCRs
	quote = yaml.safe_load(sub.stdout)
	if 'ekhash' in quote:
		ekhash = quote['ekhash']
	else:
		quote_valid = False
		ekhash = "UNKNOWN"

	with open("/tmp/quote.yaml", "w") as y:
		y.write(str(quote))

	# Validate that the every computed PCR in the eventlog
	# matches a quoted PCRs.
	# This makes no statements about the validitiy of the
	# event log, only that it is consistent with the quote.
	# Other PCRs may have values, which is the responsibility
	# of the verifier to check.
	if alg not in quote['pcrs']:
		logging.warning(f"{ekhash=}: quote does not have hash {alg}")
	quote_pcrs = quote['pcrs'][alg]

	# XXX We need a way to configure whether the eventlog is optional
	if quote['eventlog-pcrs'] != None:
		eventlog_pcrs = quote['eventlog-pcrs'][alg]

		for pcr_index in eventlog_pcrs:
			eventlog_pcr = eventlog_pcrs[pcr_index]

			if pcr_index in quote_pcrs:
				quote_pcr = quote_pcrs[pcr_index]
				if quote_pcr != eventlog_pcr:
					logging.warning(f"{ekhash=}: {pcr_index=} {quote_pcr=} != {eventlog_pcr=}")
					quote_valid = False
				else:
					logging.info(f"{ekhash=}: {pcr_index=} {quote_pcr=} good")

	if quote_valid:
		logging.info(f"{ekhash=}: so far so good")
	else:
		logging.warning(f"{ekhash=}: not good at all")

	# the quote, eventlog and PCRS are consistent, so ask the verifier to
	# process the eventlog and decide if the eventlog meets policy for
	# this ekhash.
	sub = subprocess.run(["./sbin/attest-verify", "verify", str(quote_valid)],
		input=bytes(str(quote), encoding="utf-8"),
		stdout=subprocess.PIPE,
		stderr=sys.stderr,
	)

	if sub.returncode != 0:
		return (403, "ATTEST_VERIFY FAILED")

	# read the (binary) response from the sub process stdout
	response = sub.stdout

	result = subprocess.run(["./sbin/tpm2-attest", "seal", quote_file, ],
		input=response,
		capture_output=True
	)

	if result.returncode != 0:
		return (403, "ATTEST_SEAL FAILED")

	return (200, result.stdout)

# The flask details;

app = flask.Flask(__name__)
app.config["DEBUG"] = True

@app.route('/', methods=['GET'])
def home_get():
    return { "error": "GET request, but this service only supports POST" }

@app.route('/', methods=['POST'])
def home_post():
    if 'quote' not in request.files:
        abort(500)
    f = request.files['quote']
    # Create a temporary directory for the quote file, and make it world
    # readable+executable. (This gets garbage collected after we're done, as do
    # any files we put in there.) We may priv-sep the python API from the
    # underlying safeboot routines at some point, by running the latter behind
    # sudo as another user, so this ensures it would be able to read the quote
    # file.
    tf = tempfile.TemporaryDirectory()
    s = os.stat(tf.name)
    os.chmod(tf.name, s.st_mode | S_IROTH | S_IXOTH)
    # Sanitize the user-supplied filename, append it to the temp directory
    # path, and save the quote file.
    p = os.path.join(tf.name, secure_filename(f.filename))
    f.save(p)
    # Pass the saved quote file (by path) to the attestation code
    rcode, rbody = attest_verify(p)
    if (rcode != 200):
        return { "error": "attestation failed" }
    # Put the output in a file in the temp directory and send it.
    p = os.path.join(tf.name, 'output')
    ofd = os.open(p, os.O_RDWR | os.O_CREAT)
    os.write(ofd, rbody)
    os.close(ofd)
    return send_file(p)

if __name__ == "__main__":
    app.run()
