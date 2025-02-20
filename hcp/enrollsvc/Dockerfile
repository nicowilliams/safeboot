RUN apt-get install -y git
RUN apt-get install -y python3 python3-flask jq procmail
RUN apt-get install -y file time sudo
RUN apt-get install -y uwsgi-plugin-python3

# Security note: there are some subtleties about environment values that aren't
# visible here but are worth knowing about. See common.sh for the gritty
# details.

ARG DB_USER
RUN useradd -m -s /bin/bash $DB_USER
ENV DB_USER=$DB_USER

ARG FLASK_USER
RUN useradd -m -s /bin/bash $FLASK_USER
ENV FLASK_USER=$FLASK_USER

# The following puts a sudo configuration into place for FLASK_USER to be able
# to invoke (only) the 4 /hcp/op_<verb>.sh scripts as DB_USER.

RUN echo "# sudo rules for enrollsvc-mgmt" > /etc/sudoers.d/hcp
RUN echo "Cmnd_Alias HCP = /hcp/enrollsvc/op_add.sh,/hcp/enrollsvc/op_delete.sh,/hcp/enrollsvc/op_find.sh,/hcp/enrollsvc/op_query.sh" >> /etc/sudoers.d/hcp
RUN echo "Defaults !lecture" >> /etc/sudoers.d/hcp
RUN echo "Defaults !authenticate" >> /etc/sudoers.d/hcp
RUN echo "$FLASK_USER ALL = ($DB_USER) HCP" >> /etc/sudoers.d/hcp

# We have constraints to support older Debian versions whose 'git' packages
# assume "master" as a default branch name and don't honor attempts to override
# that via the "defaultBranch" configuration setting. If more recent distro
# versions change their defaults (e.g. to "main"), we know that such versions
# will also honor this configuration setting to override such defaults. So in
# the interests of maximum interoperability we go with "master", whilst
# acknowledging that this goes against coding guidelines in many environments.
# If you have no such legacy distro constraints and wish to (or must) adhere to
# revised naming conventions, please alter this setting accordingly.

RUN git config --system init.defaultBranch master

# Updates to the enrollment database take the form of git commits, which must
# have a user name and email address. The following suffices in general, but
# modify it to your heart's content; it is of no immediate consequence to
# anything else in the HCP architecture. (That said, you may have or want
# higher-layer interpretations, from an operational perspective. E.g. if the
# distinct repos from multiple regions/sites are being mirrored and inspected
# for more than backup/restore purposes, perhaps the identity in the commits is
# used to disambiguate them?)

RUN su -c "git config --global user.email 'do-not-reply@nowhere.special'" - $DB_USER
RUN su -c "git config --global user.name 'Host Cryptographic Provisioning (HCP)'" - $DB_USER

# The build system derives a build Dockerfile from this source Dockerfile, and
# appends tarball-injection logic when it does so. Hence this comment!
