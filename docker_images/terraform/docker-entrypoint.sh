#!/bin/sh
storeAWSTemporarySecurityCredentials() {
  # Skip AWS credentials processing if their relative URI is not present.
  [ -z "$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI" ] && return
  # Create a folder to store AWS settings if it does not exist.
  USER_AWS_SETTINGS_FOLDER=~/.aws
  [ ! -d "$USER_AWS_SETTINGS_FOLDER" ] && mkdir -p $USER_AWS_SETTINGS_FOLDER
  # Query the unique security credentials generated for the task.
  # https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-iam-roles.html
  AWS_CREDENTIALS=$(curl 169.254.170.2${AWS_CONTAINER_CREDENTIALS_RELATIVE_URI})
  # Read the `AccessKeyId`, `SecretAccessKey`, and `Token` values.
  AWS_ACCESS_KEY_ID=$(echo $AWS_CREDENTIALS | jq '.AccessKeyId' --raw-output)
  AWS_SECRET_ACCESS_KEY=$(echo $AWS_CREDENTIALS | jq '.SecretAccessKey' --raw-output)
  AWS_SESSION_TOKEN=$(echo $AWS_CREDENTIALS | jq '.Token' --raw-output)
  # Create a file to store the temporary credentials on behalf of the user.
  USER_AWS_CREDENTIALS_FILE=${USER_AWS_SETTINGS_FOLDER}/credentials
  touch $USER_AWS_CREDENTIALS_FILE
  # Set the temporary credentials to the default AWS profile.
  #
  # S3 note: if you want to sign your requests using temporary security
  # credentials, the corresponding security token must be included.
  # https://docs.aws.amazon.com/AmazonS3/latest/dev/RESTAuthentication.html#UsingTemporarySecurityCredentials
  echo '[default]' > $USER_AWS_CREDENTIALS_FILE
  echo "aws_access_key_id=${AWS_ACCESS_KEY_ID}" >> $USER_AWS_CREDENTIALS_FILE
  echo "aws_secret_access_key=${AWS_SECRET_ACCESS_KEY}" >> $USER_AWS_CREDENTIALS_FILE
  echo "aws_session_token=${AWS_SESSION_TOKEN}" >> $USER_AWS_CREDENTIALS_FILE
}
setUpSSH() {
  # Block the container to start without an SSH public key.
  if [ -z "$SSH_PUBLIC_KEY" ]; then
    echo 'Need your SSH public key as the SSH_PUBLIC_KEY environment variable.'
    exit 1
  fi
  # Create a folder to store user's SSH keys if it does not exist.
  USER_SSH_KEYS_FOLDER=~/.ssh
  [ ! -d "$USER_SSH_KEYS_FOLDER" ] && mkdir -p $USER_SSH_KEYS_FOLDER
  # Copy contents from the `SSH_PUBLIC_KEY` environment variable
  # to the `${USER_SSH_KEYS_FOLDER}/authorized_keys` file.
  echo $SSH_PUBLIC_KEY > ${USER_SSH_KEYS_FOLDER}/authorized_keys
  # Clear the `SSH_PUBLIC_KEY` environment variable.
  unset SSH_PUBLIC_KEY
  ssh-keygen -A
  # Start the SSH daemon.
  /usr/sbin/sshd -D -e
}
storeAWSTemporarySecurityCredentials
setUpSSH