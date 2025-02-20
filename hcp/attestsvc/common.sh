# This file is modeled heavily on hcp/enrollsvc/common.sh so please consult
# that for explanatory matter. (When the same comments apply here, they are
# removed.)

set -e

if [[ `whoami` != "root" ]]; then
	if [[ -z "$HCP_ENVIRONMENT_SET" ]]; then
		echo "Running in reduced non-root environment (sudo probably)." >&2
		cat /etc/environment >&2
		source /etc/environment
	fi
fi

if [[ -z "$HCP_VER" ]]; then
	echo "Error, HCP_VER (\"$HCP_VER\") must be set" >&2
	exit 1
fi
if [[ -z "$HCP_ATTESTSVC_STATE_PREFIX" || ! -d "$HCP_ATTESTSVC_STATE_PREFIX" ]]; then
	echo "Error, HCP_ATTESTSVC_STATE_PREFIX (\"$HCP_ATTESTSVC_STATE_PREFIX\") is not a valid path" >&2
	exit 1
fi
if [[ -z "$HCP_USER" || ! -d "/home/$HCP_USER" ]]; then
	echo "Error, HCP_USER (\"$HCP_USER\") is not a valid user" >&2
	exit 1
fi
if [[ -z "$HCP_ATTESTSVC_REMOTE_REPO" ]]; then
	echo "Error, HCP_ATTESTSVC_REMOTE_REPO (\"$HCP_ATTESTSVC_REMOTE_REPO\") must be set" >&2
	exit 1
fi
if [[ -z "$HCP_ATTESTSVC_UPDATE_TIMER" ]]; then
	echo "Error, HCP_ATTESTSVC_UPDATE_TIMER (\"$HCP_ATTESTSVC_UPDATE_TIMER\") must be set" >&2
	exit 1
fi

if [[ ! -d "/safeboot/sbin" ]]; then
	echo "Error, /safeboot/sbin is not present" >&2
	exit 1
fi
export PATH=$PATH:/safeboot/sbin
echo "Adding /safeboot/sbin to PATH" >&2

if [[ -d "/install/bin" ]]; then
	export PATH=$PATH:/install/bin
	echo "Adding /install/sbin to PATH" >&2
fi

if [[ -d "/install/lib" ]]; then
	export LD_LIBRARY_PATH=/install/lib:$LD_LIBRARY_PATH
	echo "Adding /install/lib to LD_LIBRARY_PATH" >&2
	if [[ -d /install/lib/python3/dist-packages ]]; then
		export PYTHONPATH=/install/lib/python3/dist-packages:$PYTHONPATH
		echo "Adding /install/lib/python3/dist-packages to PYTHONPATH" >&2
	fi
fi

if [[ `whoami` == "root" ]]; then
	echo "# HCP settings, put here so that non-root environments" >> /etc/environment
	echo "# always get known-good values." >> /etc/environment
	echo "HCP_VER=$HCP_VER" >> /etc/environment
	echo "HCP_USER=$HCP_USER" >> /etc/environment
	echo "HCP_ATTESTSVC_STATE_PREFIX=$HCP_ATTESTSVC_STATE_PREFIX" >> /etc/environment
	echo "HCP_ATTESTSVC_REMOTE_REPO=$HCP_ATTESTSVC_REMOTE_REPO" >> /etc/environment
	echo "HCP_ATTESTSVC_UPDATE_TIMER=$HCP_ATTESTSVC_UPDATE_TIMER" >> /etc/environment
	echo "SAFEBOOT_UWSGI=$SAFEBOOT_UWSGI" >> /etc/environment
	echo "SAFEBOOT_UWSGI_FLAGS=$SAFEBOOT_UWSGI_FLAGS" >> /etc/environment
	echo "SAFEBOOT_UWSGI_PORT=$SAFEBOOT_UWSGI_PORT" >> /etc/environment
	echo "SAFEBOOT_UWSGI_OPTIONS=$SAFEBOOT_UWSGI_OPTIONS" >> /etc/environment
	echo "HCP_ENVIRONMENT_SET=1" >> /etc/environment
fi

# Print the base configuration
echo "Running '$0'" >&2
echo "                     HCP_VER=$HCP_VER" >&2
echo "                    HCP_USER=$HCP_USER" >&2
echo "  HCP_ATTESTSVC_STATE_PREFIX=$HCP_ATTESTSVC_STATE_PREFIX" >&2
echo "   HCP_ATTESTSVC_REMOTE_REPO=$HCP_ATTESTSVC_REMOTE_REPO" >&2
echo "  HCP_ATTESTSVC_UPDATE_TIMER=$HCP_ATTESTSVC_UPDATE_TIMER" >&2
echo "              SAFEBOOT_UWSGI=$SAFEBOOT_UWSGI" >&2
echo "        SAFEBOOT_UWSGI_FLAGS=$SAFEBOOT_UWSGI_FLAGS" >&2
echo "         SAFEBOOT_UWSGI_PORT=$SAFEBOOT_UWSGI_PORT" >&2
echo "      SAFEBOOT_UWSGI_OPTIONS=$SAFEBOOT_UWSGI_OPTIONS" >&2

# Basic functions

function expect_root {
	if [[ `whoami` != "root" ]]; then
		echo "Error, running as \"`whoami`\" rather than \"root\"" >&2
		exit 1
	fi
}

function expect_hcp_user {
	if [[ `whoami` != "$HCP_USER" ]]; then
		echo "Error, running as \"`whoami`\" rather than \"$HCP_USER\"" >&2
		exit 1
	fi
}

function drop_privs_hcp {
	su -c "$*" - $HCP_USER
}
