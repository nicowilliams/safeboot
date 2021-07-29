# We need some upstream stuff
RUN apt-get install -y python3-yaml python3-distutils python3-cryptography
RUN apt-get install -y file

# /hcp already exists, but we have things for /safeboot and /etc too.
RUN mkdir /safeboot
RUN mkdir /safeboot/sbin
RUN mkdir /safeboot/tests
RUN mkdir /safeboot/initramfs
RUN mkdir /safeboot/initramfs/hooks
RUN mkdir /safeboot/initramfs/scripts
RUN mkdir /etc/safeboot

COPY install.tar.gz /
RUN chmod 644 /install.tar.gz
RUN cd / && tar zxf install.tar.gz && rm install.tar.gz

# We need local two scripts and the safeboot stuff
COPY run_client.sh /hcp/
COPY safeboot-xtra/* /etc/safeboot/
COPY safeboot-sbin/* /safeboot/sbin/
COPY safeboot-tests/* /safeboot/tests/
COPY safeboot-initramfs/scripts/* /safeboot/initramfs/scripts/
COPY safeboot-initramfs/hooks/* /safeboot/initramfs/hooks/
COPY safeboot-initramfs/bootscript /safeboot/initramfs/
COPY safeboot-initramfs/busybox.config /safeboot/initramfs/
COPY safeboot-initramfs/cmdline.txt /safeboot/initramfs/
COPY safeboot-initramfs/config.sh /safeboot/initramfs/
COPY safeboot-initramfs/dev.cpio /safeboot/initramfs/
COPY safeboot-initramfs/files.txt /safeboot/initramfs/
COPY safeboot-initramfs/init /safeboot/initramfs/
COPY safeboot-initramfs/linux.config /safeboot/initramfs/
COPY safeboot-initramfs/udhcpc.sh /safeboot/initramfs/

RUN chmod 755 /hcp/run_client.sh
RUN chmod 644 /etc/safeboot/*
RUN chmod 755 /safeboot/sbin/*
RUN chmod 755 /safeboot/tests/*
RUN chmod 755 /safeboot/tests/dmverity-failure
RUN chmod 755 /safeboot/tests/test-enroll.sh
RUN chmod 755 /safeboot/tests/test-verify.sh
RUN chmod 755 /safeboot/initramfs/bootscript
RUN chmod 755 /safeboot/initramfs/config.sh
RUN chmod 755 /safeboot/initramfs/udhcpc.sh
RUN chmod 755 /safeboot/initramfs/init
RUN chmod 755 /safeboot/initramfs/scripts/*
RUN chmod 755 /safeboot/initramfs/hooks/*
