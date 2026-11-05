FROM node:22.23.1-bookworm-slim@sha256:6c74791e557ce11fc957704f6d4fe134a7bc8d6f5ca4403205b2966bd488f6b3
RUN printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d \
    && apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends libsecret-tools gnome-keyring dbus \
    && mkdir -p /opt/verification \
    && dpkg-query -W -f='${Package}\t${Version}\n' > /opt/verification/dpkg-versions.tsv \
    && rm -rf /var/lib/apt/lists/*
COPY package/ /opt/dsh-pap/
COPY runtime_modules/ /opt/dsh-pap/node_modules/
COPY source/ /opt/dsh-pap/source/
COPY verify.mjs /opt/verification/verify.mjs
RUN chmod -R a-w /opt/dsh-pap /opt/verification
WORKDIR /opt/verification
ENTRYPOINT ["node", "/opt/verification/verify.mjs"]
