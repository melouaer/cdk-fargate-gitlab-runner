# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of this
# software and associated documentation files (the "Software"), to deal in the Software
# without restriction, including without limitation the rights to use, copy, modify,
# merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
# INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
# PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
# HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#
ARG CHECKOV_VERSION=2.0.606
FROM bridgecrew/checkov:$CHECKOV_VERSION

RUN apk update

RUN apk add --no-cache tini

# --------------------------------------------------------------------------
# Install and configure sshd.
# https://docs.docker.com/engine/examples/running_ssh_service for reference.
# --------------------------------------------------------------------------

# utils
RUN apk add openssh && \ 
    apk add nano && \
    apk add curl && \
    apk add jq


#Enable ssh login
RUN apk add openrc && rc-update add sshd \
    && sed -i '/^#Port 22/s/^#//' /etc/ssh/sshd_config \
    && sed -i '/^#PasswordAuthentication/s/^#//' /etc/ssh/sshd_config \
    && sed -i '/^#PermitEmptyPasswords no/s/^#PermitEmptyPasswords no/PermitEmptyPasswords yes/' /etc/ssh/sshd_config \
    && sed -i '/^#PermitRootLogin prohibit-password/s/^#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config \
    && echo "root:Docker!" | chpasswd

RUN passwd -d root

EXPOSE 22

# ----------------------------------------
# Install GitLab CI required dependencies.
# ----------------------------------------
ARG GITLAB_RUNNER_VERSION=v14.5.0

RUN curl -Lo /usr/sbin/gitlab-runner https://gitlab-runner-downloads.s3.amazonaws.com/${GITLAB_RUNNER_VERSION}/binaries/gitlab-runner-linux-amd64 && \
    chmod +x /usr/sbin/gitlab-runner
    # Test if the downloaded file was indeed a binary and not, for example,
    # an HTML page representing S3's internal server error message or something
    # like that.

RUN apk add bash ca-certificates git git-lfs && \
    git lfs install --skip-repo

# -------------------------------------------------------------------------------------
# Execute a startup script.
# https://success.docker.com/article/use-a-script-to-initialize-stateful-container-data
# for reference.
# -------------------------------------------------------------------------------------
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

RUN chmod +x /usr/local/bin/docker-entrypoint.sh

ENTRYPOINT ["/sbin/tini", "--", "/usr/local/bin/docker-entrypoint.sh"]