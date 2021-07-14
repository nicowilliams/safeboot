#!/bin/bash

. /hcp/enrollsvc/common.sh

expect_root

echo "Running 'enrollsvc-repl' service (git-daemon)"

GITDAEMON=${HCP_RUN_ENROLL_GITDAEMON:=/usr/lib/git-core/git-daemon}
GITDAEMON_FLAGS=${HCP_RUN_ENROLL_GITDAEMON_FLAGS:=--reuseaddr --verbose --listen=0.0.0.0 --port=9418}

TO_RUN="$GITDAEMON \
	--base-path=$HCP_ENROLLSVC_STATE_PREFIX \
	$GITDAEMON_FLAGS \
	$REPO_PATH"

echo "Running (as $DB_USER): $TO_RUN"
drop_privs_db $TO_RUN
