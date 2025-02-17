#!/bin/bash

# -----------------------------------------------------------------------------
# Important: this scripts depends on some predefined environment variables:
# - GITLAB_REGISTRATION_TOKEN (required): registration token for your project
# - GITLAB_URL (optional): the URL to the GitLab instance (defaults to https://gitlab.com)
# - RUNNER_TAG_LIST (optional): comma separated list of tags for the runner
# - FARGATE_CLUSTER (required): the AWS Fargate cluster name
# - FARGATE_REGION (required): the AWS region where the task should be started
# - FARGATE_SUBNET (required): the AWS subnet where the task should be started
# - FARGATE_SECURITY_GROUP (required): the AWS security group where the task
#   should be started
# - FARGATE_TASK_DEFINITION (required): the task definition used for the task
# -----------------------------------------------------------------------------

# Default to https://gitlab.com if the GitLab URL was not specified
export GITLAB_URL=${GITLAB_URL:=https://gitlab.com}

###############################################################################
# Remove the Runner from the list of runners of the project identified by the
# authentication token.
#
# Arguments:
#   $1 - Authorization token obtained after registering the runner in the
#        project
###############################################################################
unregister_runner() {
    curl --request DELETE "${GITLAB_URL}/api/v4/runners" --form "token=$1"
}

###############################################################################
# Register the Runner in the desired project, identified by the registration
# token of that project.
#
# The function populates the "auth_token" variable with the authentication
# token for the registered Runner.
#
# Arguments:
#   $1 - Registration token
#   $2 - List of tags for the Runner, separated by comma
###############################################################################
register_runner() {

    runner_identification="RUNNER_$(date +%s)"

    # Uses the environment variable "GITLAB_REGISTRATION_TOKEN" to register the runner

    result_json=$(
        curl --request POST "${GITLAB_URL}/api/v4/runners" \
            --form "token=$1" \
            --form "description=${runner_identification}" \
            --form "tag_list=$2"
    )

    # Read the authentication token

    auth_token=$(echo $result_json | jq -r '.token')

    # Recreate the runner config.toml based on our template

    export RUNNER_NAME=$runner_identification
    export RUNNER_AUTH_TOKEN=$auth_token
    envsubst < /tmp/config_runner_template.toml > /etc/gitlab-runner/config.toml
}

###############################################################################
# Create the Fargate driver TOML configuration file based on a template
# that is persisted in the repository. It uses the environment variables
# passed to the container to set the correct values in that file.
#
# Globals:
#   - FARGATE_CLUSTER
#   - FARGATE_REGION
#   - FARGATE_SUBNET
#   - FARGATE_SECURITY_GROUP
#   - FARGATE_TASK_DEFINITION
###############################################################################
create_driver_config() {
    envsubst < /tmp/config_driver_template.toml > /etc/gitlab-runner/config_driver.toml
}

###############################################################################
# Configure ECS Cluster Capacity Provider
#
# Globals:
#   - FARGATE_CLUSTER
###############################################################################
configure_ecs_capacity_provider() {
    aws ecs put-cluster-capacity-providers \
        --cluster "${FARGATE_CLUSTER}"  \
        --capacity-providers FARGATE FARGATE_SPOT \
        --default-capacity-provider-strategy \
        capacityProvider=FARGATE,weight=1,base=1 \
        capacityProvider=FARGATE_SPOT,weight=10
}

configure_ecs_capacity_provider

create_driver_config

register_runner ${GITLAB_REGISTRATION_TOKEN} ${RUNNER_TAG_LIST}

# Gitlab runner run will block the script until a docker stop is emited
gitlab-runner run

unregister_runner ${auth_token}
