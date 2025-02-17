#
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
from typing import Protocol
import json
from jinja2 import Template
from aws_cdk import core as cdk
from aws_cdk.aws_ec2 import InitCommand, SubnetType
import os
import sys
from aws_cdk import (
    core,
    aws_ec2 as ec2,
    aws_iam as iam,
    aws_ssm as ssm,
    aws_ecs as ecs,
    aws_s3 as s3,
    core,
)


class TaskDefinitionStack(cdk.Stack):
    def __init__(
        self, scope: cdk.Construct, construct_id: str, env, props, **kwargs
    ) -> None:
        super().__init__(scope, construct_id, env=env, **kwargs)
        try:
            self.fargate_execution_role = iam.Role(
                self,
                "GitlabExecutionRole",
                assumed_by=iam.ServicePrincipal("ecs-tasks.amazonaws.com"),
                managed_policies=[
                    iam.ManagedPolicy.from_aws_managed_policy_name(
                        "service-role/AmazonECSTaskExecutionRolePolicy"
                    )
                ],
            )

            self.fargate_task_role = iam.Role(
                self,
                "GitlabTaskRole",
                assumed_by=iam.ServicePrincipal("ecs-tasks.amazonaws.com"),
                managed_policies=[
                    iam.ManagedPolicy.from_aws_managed_policy_name(
                        "AmazonEC2ContainerRegistryReadOnly"
                    )
                ],
            )

            try:
                task_policies_template = f'./docker_images/{props.get("docker_image_name")}/task_role_policies.j2'
                with open(task_policies_template) as f:
                    j2_template = Template(f.read())
                rendered_template = j2_template.render(
                    region=self.region, account=self.account
                )
                task_policies = json.loads(rendered_template)
                self.fargate_task_role_policies = iam.Policy(
                    self,
                    "taskPolicy",
                    document=iam.PolicyDocument.from_json(task_policies),
                )
                self.fargate_task_role.attach_inline_policy(
                    self.fargate_task_role_policies
                )
            except IOError:
                print("No task policies template provided.")

            # Add Fargate task definition
            default_docker_image = ecs.ContainerImage.from_asset(
                directory=f'./docker_images/{props.get("docker_image_name")}',
            )

            port_mappings = [ecs.PortMapping(container_port=22)]

            self.fargate_task_definition = ecs.TaskDefinition(
                self,
                "fargateExecutorTaskDefinition",
                compatibility=ecs.Compatibility.FARGATE,
                family=props.get("docker_image_name"),
                cpu=props.get("task_definition_cpu"),
                memory_mib=props.get("task_definition_memory"),
                network_mode=ecs.NetworkMode.AWS_VPC,
                task_role=self.fargate_task_role,
                execution_role=self.fargate_execution_role,
            )
            self.fargate_task_definition.add_container(
                "fargateExecutorContainer",
                image=default_docker_image,
                container_name="ci-coordinator",
                port_mappings=port_mappings,
                logging=ecs.LogDrivers.aws_logs(stream_prefix="fargate"),
            )
            self.fargate_task_definition.apply_removal_policy(cdk.RemovalPolicy.RETAIN)
            self.output_props = props.copy()
            self.output_props["fargate_task_definition"] = self.fargate_task_definition

        except:
            print("Unexpected error:", sys.exc_info()[0])
            raise

    @property
    def outputs(self):
        return self.output
