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
from aws_cdk import core as cdk
from aws_cdk.aws_ec2 import InitCommand, SubnetType
import os
import sys
from aws_cdk import (
    core,
    aws_ec2 as ec2,
    aws_iam as iam,
    aws_ecs as ecs,
    aws_s3 as s3,
    aws_secretsmanager as secretsmanager,
    core,
)


class GitlabCiFargateRunnerStack(cdk.Stack):
    def __init__(
        self, scope: cdk.Construct, construct_id: str, env, props, **kwargs
    ) -> None:
        super().__init__(scope, construct_id, env=env, **kwargs)
        # Lookup for VPC
        self.vpc = ec2.Vpc.from_lookup(self, "VPC", vpc_id=props.get("VpcId"))
        try:
            cachebucket = s3.Bucket(
                self,
                "gitlabrunnercachebucket",
                block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
                encryption=s3.BucketEncryption.S3_MANAGED,
                removal_policy=core.RemovalPolicy.DESTROY,
                enforce_ssl=True,
            )
            self.cache_bucket = cachebucket

            self.sg_runner = ec2.SecurityGroup(
                self, "gitlabRunnerSg", vpc=self.vpc, allow_all_outbound=False
            )
            self.sg_runner.add_ingress_rule(
                peer=self.sg_runner, connection=ec2.Port.tcp(22)
            )
            self.sg_runner.add_egress_rule(
                peer=self.sg_runner, connection=ec2.Port.tcp(22)
            )
            self.sg_runner.add_egress_rule(
                peer=ec2.Peer.any_ipv4(), connection=ec2.Port.tcp(443)
            )

            # Add ECS Cluster
            self.fargate_cluster = ecs.Cluster(
                self,
                f"{self.stack_name}-cluster",
                cluster_name=f"{self.stack_name}-cluster",
                enable_fargate_capacity_providers=True,
                container_insights=True,
                vpc=self.vpc,
            )
            self.fargate_cluster.enable_fargate_capacity_providers()
            self.fargate_cluster.add_capacity_provider(provider="FARGATE")

            # fargate driver Execution role policies
            self.fargate_task_role_policies = {
                "fargateRunnerTaskPolicies": iam.PolicyDocument(
                    statements=[
                        iam.PolicyStatement(
                            effect=iam.Effect.ALLOW,
                            actions=["secretsmanager:GetSecretValue"],
                            resources=[
                                f"arn:aws:secretsmanager:{self.region}:{self.account}:secret:"
                                f"{props.get('gitlab_runner_token_secret_name')}*"
                            ],
                        ),
                        iam.PolicyStatement(
                            effect=iam.Effect.ALLOW,
                            actions=[
                                "s3:PutObject",
                                "s3:GetObjectVersion",
                                "s3:GetObject",
                                "s3:DeleteObject",
                            ],
                            resources=[f"{self.cache_bucket.bucket_arn}/*"],
                        ),
                    ]
                )
            }
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
                "GitlabRunnerTaskRole",
                assumed_by=iam.ServicePrincipal("ecs-tasks.amazonaws.com"),
                managed_policies=[
                    iam.ManagedPolicy.from_aws_managed_policy_name(
                        "AmazonECS_FullAccess"
                    )
                ],
                inline_policies=self.fargate_task_role_policies,
            )

            # Add Fargate task definition
            default_docker_image = ecs.ContainerImage.from_asset(
                directory="./docker_fargate_driver",
            )

            port_mappings = [ecs.PortMapping(container_port=22)]

            runner_environment = {
                "FARGATE_CLUSTER": f"{self.stack_name}-cluster",
                "FARGATE_REGION": self.region,
                "FARGATE_SECURITY_GROUP": self.sg_runner.security_group_id,
                # "FARGATE_SUBNET": subnet_id,
                "RUNNER_TAG_LIST": props.get("runner_tags"),
                "CACHE_BUCKET": self.cache_bucket.bucket_name,
                "CACHE_BUCKET_REGION": self.region,
            }
            runner_secret = secretsmanager.Secret.from_secret_name_v2(
                self,
                "gitlabRegistrationToken",
                props.get("gitlab_runner_token_secret_name"),
            )
            runner_secrets = {
                "GITLAB_REGISTRATION_TOKEN": ecs.Secret.from_secrets_manager(
                    runner_secret, "token"
                )
            }

            self.fargate_task_definitions = {}
            self.fargate_services = {}

            for az in ["a", "b"]:
                subnet_id = ""
                vpc_subnets = self.vpc.select_subnets(
                    subnet_type=ec2.SubnetType.PRIVATE,
                    availability_zones=[f"{self.region}{az}"],
                )
                subnet_ids = vpc_subnets.subnet_ids
                if subnet_ids:
                    subnet_id = subnet_ids[0]
                runner_environment.update({"FARGATE_SUBNET": subnet_id})

                self.fargate_task_definitions[az] = ecs.TaskDefinition(
                    self,
                    f"fargateDriverTaskDefinitionAz{az}",
                    compatibility=ecs.Compatibility.FARGATE,
                    family="gitlab-fargate-driver",
                    cpu=props.get("runner_cpu"),
                    memory_mib=props.get("runner_memory"),
                    network_mode=ecs.NetworkMode.AWS_VPC,
                    task_role=self.fargate_task_role,
                    execution_role=self.fargate_execution_role,
                )
                self.fargate_task_definitions[az].add_container(
                    f"fargateDriverContainerAz{az}",
                    image=default_docker_image,
                    port_mappings=port_mappings,
                    logging=ecs.LogDrivers.aws_logs(stream_prefix="fargate"),
                    environment=runner_environment,
                    secrets=runner_secrets,
                )
                self.fargate_task_definitions[az].apply_removal_policy(
                    cdk.RemovalPolicy.RETAIN
                )
                # ECS Service definition
                subnets = ec2.SubnetSelection(subnets=vpc_subnets.subnets)
                self.fargate_services[az] = ecs.FargateService(
                    self,
                    f"gitlabRunnerServiceAz{az}",
                    cluster=self.fargate_cluster,
                    task_definition=self.fargate_task_definitions[az],
                    desired_count=1,
                    security_groups=[self.sg_runner],
                    vpc_subnets=subnets,
                )

                # Setup AutoScaling policy
                scaling = self.fargate_services[az].auto_scale_task_count(
                    max_capacity=2
                )
                scaling.scale_on_cpu_utilization(
                    f"CpuScalingAz{az}",
                    target_utilization_percent=70,
                    scale_in_cooldown=cdk.Duration.seconds(60),
                    scale_out_cooldown=cdk.Duration.seconds(60),
                )

            self.output_props = props.copy()
            self.output_props["vpc"] = self.vpc
            self.output_props[
                "fargate_task_definitions"
            ] = self.fargate_task_definitions
            self.output_props["fargate_services"] = self.fargate_services
        except:
            print("Unexpected error:", sys.exc_info()[0])
            raise

    @property
    def outputs(self):
        return self.output_props
