#!/usr/bin/env bash

__waitFor() {
    [[ $# -ne 1 ]] && { echo "Usage: $0 $FUNCNAME FUNCTION [DURATION]"; return 1; }
    local fun=$1
    local duration=${2-100}
    for i in $(seq 1 ${duration}); do
        ${fun}
        local ret=$?
        [ ${ret} -eq 7 ] && { >&2 echo -n "."; sleep 3; } # Connect failure
        [ ${ret} -eq 28 ] && { >&2 echo -n "_"; sleep 3; } # Request timeout
        [ ${ret} -eq 0 ] && return 0
        [ ${ret} -eq 1 ] && return 1
    done
    return 1
}

tag() {
    [[ $# -ne 2 ]] && { >&2 echo "Usage: $0 $FUNCNAME RESOURCE_ID SYSTEM_ID"; return 1; }
    local resourceId=$1
    local systemId=$2
    addSystemIdTag ${resourceId} ${systemId}
    addNameTag ${resourceId} ${systemId}
}

addSystemIdTag() {
    [[ $# -ne 2 ]] && { >&2 echo "Usage: $0 $FUNCNAME RESOURCE_ID SYSTEM_ID"; return 1; }
    local resourceId=$1
    local systemId=$2
    output=$(aws ec2 create-tags --resources ${resourceId} --tags Key=SystemId,Value=${systemId}) || return 1
}

addNameTag() {
    [[ $# -ne 2 ]] && { >&2 echo "Usage: $0 $FUNCNAME RESOURCE_ID NAME"; return 1; }
    local resourceId=$1
    local name=$2
    output=$(aws ec2 create-tags --resources ${resourceId} --tags Key=Name,Value=${name}) || return 1
}

tagFilter() {
    [[ $# -ne 2 ]] && { >&2 echo "Usage: $0 $FUNCNAME NAME VALUE"; return 1; }
    local name=$1
    local value=$2
    echo "Name=tag-key,Values=${name} Name=tag-value,Values=${value}"
}

nameFilter() {
    [[ $# -ne 1 ]] && { >&2 echo "Usage: $0 $FUNCNAME NAME"; return 1; }
    name=$1
    tagFilter Name ${name}
}

instanceFilter() {
    [[ $# -ne 2 ]] && { >&2 echo "Usage: $0 $FUNCNAME SYSTEM_ID INSTANCE_NAME"; return 1; }
    local systemId instanceName
    systemId=$1
    instanceName=$2
    echo "$(vpcFilter ${systemId}) $(nameFilter ${instanceName})"
}

runningFilter() {
    echo "Name=instance-state-name,Values=running"
}

nodeName() {
    [[ $# -ne 2 ]] && { >&2 echo "Usage: $0 $FUNCNAME SYSTEM_ID NODE_NUMBER"; return 1; }
    system_id=$1
    node_number=$2
    echo "${system_id}-node${node_number}"
}

vpcId() {
    [[ $# -ne 1 ]] && { >&2 echo "Usage: $0 $FUNCNAME SYSTEM_ID"; return 1; }
    local systemId=$1
    local id
    [[ ${systemId} == vpc-* ]] && {
        id=${systemId}
    } || {
        output=$(aws ec2 describe-vpcs --filters $(tagFilter SystemId ${systemId})) || return 1
        id=$(echo ${output} | jq -er ".Vpcs[].VpcId") || return 1
    }
    echo "${id}"
}

vpcFilter() {
    [[ $# -ne 1 ]] && { >&2 echo "Usage: $0 $FUNCNAME SYSTEM_ID"; return 1; }
    system_id=$1
    echo "Name=vpc-id,Values=$(vpcId ${system_id})"
}

imageId() {
    [[ $# -ne 1 ]] && { >&2 echo "Usage: $0 $FUNCNAME NAME"; return 1; }
    local name=${1}
    [[ ${name} == ami-* ]] && {
        id=${name}
    } || {
        local output
        output=$(aws ec2 describe-images --filters Name=name,Values=${name}) || return 1
        id=$(echo ${output} | jq -er ".Images[].ImageId") || { >&2 echo "Error extracting id from response ${output}"; return 1; }
    }
    echo -n ${id}
}

subnetId() {
    [[ $# -ne 2 ]] && { >&2 echo "Usage: $0 $FUNCNAME SYSTEM_ID NAME"; return 1; }
    local id systemId name
    systemId=${1}
    name=${2}
    vpcId=$(vpcId ${systemId})
    [[ ${name} == subnet-* ]] && {
        id=${name}
    } || {
        local output
        output=$(aws ec2 describe-subnets --filters $(nameFilter ${name}) Name=vpc-id,Values=${vpcId})
        id=$(echo ${output} | jq -er ".Subnets[].SubnetId") || { >&2 echo "Error extracting id from response ${output}"; return 1; }
    }
    echo -n ${id}
}

instanceId() {
    [[ $# -ne 2 ]] && { >&2 echo "Usage: $0 $FUNCNAME SYSTEM_ID INSTANCE_NAME"; return 1; }
    local systemId instanceName output id
    systemId=$1
    instanceName=$2
    output=$(aws ec2 describe-instances --filters $(instanceFilter ${systemId} ${instanceName})) || return 1
    id=$(echo ${output} | jq -er ".Reservations[].Instances[].InstanceId" | paste -s -d ' ' -) || return 1
    echo ${id}
}

networkInterfaceId() {
    [[ $# -ne 2 ]] && { >&2 echo "Usage: $0 $FUNCNAME SYSTEM_ID INSTANCE_NAME"; return 1; }
    local systemId instanceName output instanceId id
    systemId=$1
    instanceName=$2
    output=$(aws ec2 describe-instances --filters $(instanceFilter ${systemId} ${instanceName})) || return 1
    id=$(echo ${output} | jq -er ".Reservations[].Instances[].NetworkInterfaces[].NetworkInterfaceId") || return 1
    echo ${id}
}

describeVpcs() {
    [[ $# -ne 0 ]] && { >&2 echo "Usage: $0 $FUNCNAME"; return 1; }
    aws ec2 describe-vpcs | jq -rc '.Vpcs[] | { Id:.VpcId, Name:(if .Tags != null then (.Tags[] | select(.Key=="Name") | .Value) else "N/A" end), Cidr:.CidrBlock }'
}

describeInstances() {
    [[ $# -ne 0 ]] && { >&2 echo "Usage: $0 $FUNCNAME"; return 1; }
    aws ec2 describe-instances | jq -c '.Reservations[].Instances[] | { Id:.InstanceId, State:.State.Name, Image:.ImageId, Name:(if .Tags != null then (.Tags[] | select(.Key=="Name") | .Value) else "N/A" end), Vpc:.VpcId, Subnet:.SubnetId, PublicIp:.PublicIpAddress, PrivateIp:.PrivateIpAddress } '
}

describeInstance() {
    [[ $# -ne 1 ]] && { >&2 echo "Usage: $0 $FUNCNAME INSTANCE_ID"; return 1; }
    local instanceId=$1
    aws ec2 describe-instances --instance-ids ${instanceId} | jq '.'
}

describeSubnets() {
    [[ $# -ne 0 ]] && { >&2 echo "Usage: $0 $FUNCNAME"; return 1; }
    aws ec2 describe-subnets | jq -c '.Subnets[] | { Id:.SubnetId, Cidr:.CidrBlock, Name:(if .Tags != null then (.Tags[] | select(.Key=="Name") | .Value) else "N/A" end), Vpc:.VpcId }'
}

disableSourceDestinationCheck() {
    [[ $# -ne 2 ]] && { >&2 echo "Usage: $0 $FUNCNAME SYSTEM_ID INSTANCE_NAME"; return 1; }
    local systemId instanceName networkInterfaceId
    systemId=$1
    instanceName=$2
    networkInterfaceId=$(networkInterfaceId ${systemId} ${instanceName}) || return 1
    >/dev/null aws ec2 modify-network-interface-attribute --network-interface-id ${networkInterfaceId} --no-source-dest-check || return 1
}

listSsmAssociationForInstance() {
    [[ $# -eq 1 ]] || { >&2 echo "Usage: $0 $FUNCNAME INSTANCE_ID"; return 1; }
    local instanceId=$1
    aws ssm list-associations --association-filter-list key=InstanceId,value=${instanceId}
}

consoleOutput() {
    [[ $# -eq 1 ]] || { >&2 echo "Usage: $0 $FUNCNAME INSTANCE_ID"; return 1; }
    local instanceId=$1
    aws ec2 get-console-output --instance-id ${instanceId} | jq -r .Output
}

launchWindowsServer2016() {
    [[ $# -ge 3 ]] || { >&2 echo "Usage: $0 $FUNCNAME SYSTEM_ID NAME SUBNET_NAME [IAM_INSTANCE_PROFILE]"; return 1; }
    local systemId=${1}
    local name=${2}
    local subnetName=${3}
    local iamInstanceProfile=${4}
    securityGroupId=$(createSecurityGroup ${systemId} "${name}.${subnetName}" \
        "IpProtocol=TCP,FromPort=3389,ToPort=3389,IpRanges=[{CidrIp=0.0.0.0/0}]") || return 1
    launchInstance ${systemId} ${name} "ami-f97e8f80" ${subnetName} "t2.micro" ${securityGroupId} ${iamInstanceProfile}
}

launchInstance() {
    [[ $# -ge 6 ]] || { >&2 echo "Usage: $0 $FUNCNAME SYSTEM_ID NAME IMAGE_NAME SUBNET_NAME INSTANCE_TYPE SECURITY_GROUP_ID [IAM_INSTANCE_PROFILE [USER_DATA]]"; return 1; }
    local systemId=${1}
    local name=${2}
    local imageName=${3}
    local subnetName=${4}
    local instanceType=${5}
    local securityGroupId=${6}
    local iamInstanceProfile=${7}
    local userData=${8}
    local imageId subnetId keyName output id
    imageId=$(imageId ${imageName}) || { >&2 echo "Image ${imageName} not found"; return 1; }
    subnetId=$(subnetId ${systemId} ${subnetName})
    keyName=$(createKeyPair ${systemId} ${name}) || { >&2 echo "Failed to create key pair"; return 1; }
    output=$(aws ec2 run-instances \
	    --image-id ${imageId} \
	    --security-group-ids ${securityGroupId} \
	    --instance-type ${instanceType} \
	    --subnet-id ${subnetId} \
	    --iam-instance-profile Name=${iamInstanceProfile} \
	    --key-name ${keyName} \
	    --associate-public-ip-address \
	    ) || return 1
	id=$(echo ${output} | jq -er ".Instances[].InstanceId") || { >&2 echo "Error extracting id from response ${output}"; return 1; }
    addNameTag ${id} ${name} || { >&2 echo "Failed to add name tag"; return 1; }
    echo ${id}
}

createVpc() {
    [[ $# -ne 1 ]] && { >&2 echo "Usage: $0 $FUNCNAME SYSTEM_ID [CIDR_BLOCK]"; return 1; }
    local system_id=$1
    local cidrBlock=${2-"10.0.0.0/16"}
    output=$(aws ec2 create-vpc --cidr-block ${cidrBlock}) || return 1
    id=$(echo ${output} | jq -er ".Vpc.VpcId") || { >&2 echo "Error extracting id from response ${output}"; return 1; }
    >/dev/null aws ec2 modify-vpc-attribute --vpc-id ${id} --enable-dns-hostnames "{\"Value\":true}" || { >&2 echo "Failed to enable DNS hostnames on VPC"; return 1; }
    tag ${id} ${system_id}
    echo ${id}
}

deleteVpc() {
    [[ $# -ne 1 ]] && { >&2 echo "Usage: $0 $FUNCNAME SYSTEM_ID"; return 1; }
    local id systemId output
    systemId=$1
    id=$(vpcId ${systemId})
    if [ ! -z ${id} ]; then
        >/dev/null aws ec2 delete-vpc --vpc-id=${id} || return 1
        echo "Deleted VPC ${id} "
    fi
}

addDefaultRouteToInstanceTarget() {
    [[ $# -eq 3 ]] || { >&2 echo "Usage: $0 $FUNCNAME SYSTEM_ID DESTINATION_CIDR NAT_INSTANCE_NAME"; return 1; }
    local systemId destinationCidr natInstanceName routeTableId natInstanceId output
    systemId=$1
    destinationCidr=$2
    natInstanceName=$3
    routeTableId=$(mainRouteTableId ${systemId}) || return 1
    natInstanceId=$(instanceId ${systemId} ${natInstanceName}) || return 1
    >/dev/null aws ec2 create-route --route-table-id ${routeTableId} --destination-cidr-block ${destinationCidr} --instance-id ${natInstanceId} || return 1
}

mainRouteTableId() {
    [[ $# -eq 1 ]] || { >&2 echo "Usage: $0 $FUNCNAME SYSTEM_ID"; return 1; }
    local systemId id output
    systemId=${1}
    output=$(aws ec2 describe-route-tables --filters Name=association.main,Values=true $(vpcFilter ${systemId})) || return 1
    id=$(echo ${output} | jq -er ".RouteTables[].RouteTableId") || { >&2 echo "Error extracting id from response ${output}"; return 1; }
    echo ${id}
}

createRouteTable() {
    [[ $# -eq 2 ]] || { >&2 echo "Usage: $0 $FUNCNAME SYSTEM_ID NAME"; return 1; }
    local systemId name id output vpcId
    systemId=${1}
    name=${2}
    vpcId=$(vpcId ${systemId}) || {  >&2 echo "Unknown system ${systemId}"; return 1; }
    output=$(aws ec2 create-route-table --vpc-id ${vpcId}) || return 1
    id=$(echo ${output} | jq -er ".RouteTable.RouteTableId") || { >&2 echo "Error extracting id from response ${output}"; return 1; }
    addNameTag ${id} ${name} || { >&2 echo "Failed to set name tag"; return 1; }
    echo -n ${id}
}

createPublicSubnet() {
    [[ $# -lt 1 ]] && { >&2 echo "Usage: $0 $FUNCNAME SYSTEM_ID [CIDR_BLOCK] [NAME]"; return 1; }
    local id output vpcId igwId systemId cidrBlock name
    systemId=${1}
    cidrBlock=${2-"10.0.0.0/16"}
    name=${3-"${systemId}-${cidrBlock}"}
    id=$(createSubnet $@) || return 1
    output=$(aws ec2 modify-subnet-attribute --subnet-id ${id} --map-public-ip-on-launch) || return 1
    vpcId=$(vpcId ${systemId}) || {  >&2 echo "Unknown system ${systemId}"; return 1; }
    routeTableId=$(createRouteTable ${systemId} ${name}-RouteTable) || return 1
    igwId=$(igwId ${systemId}) || { >&2 echo "No Internet gateway found"; return 1; }
    output=$(aws ec2 create-route --route-table-id ${routeTableId} --destination-cidr-block 0.0.0.0/0 --gateway-id ${igwId}) || { >&2 "Failed to create route"; return 1; }
    output=$(aws ec2 associate-route-table --route-table-id ${routeTableId} --subnet-id ${id}) || return 1
    echo ${id}
}

createSubnet() {
    [[ $# -lt 1 ]] && { >&2 echo "Usage: $0 $FUNCNAME SYSTEM_ID [CIDR_BLOCK] [NAME]"; return 1; }
    local systemId cidrBlock name vpcId output id
    systemId=$1
    cidrBlock=${2-"10.0.0.0/16"}
    name=${3-"${systemId}-${cidrBlock}"}
    vpcId=$(vpcId ${systemId}) || {  >&2 echo "Unknown system ${systemId}"; return 1; }
    output=$(aws ec2 create-subnet --vpc-id $(vpcId ${systemId}) --cidr-block ${cidrBlock}) || return 1
    id=$(echo ${output} | jq -er ".Subnet.SubnetId") || return 1
    addNameTag ${id} ${name}
    echo ${id}
}

deleteSubnets() {
    [[ $# -ne 1 ]] && { >&2 echo "Usage: $0 $FUNCNAME SYSTEM_ID"; return 1; }
    local systemId=$1
    output=$(aws ec2 describe-subnets --filters $(vpcFilter ${systemId})) || return 1
    ids=$(echo ${output} | jq -r ".Subnets[].SubnetId")
    for id in ${ids}; do
        aws ec2 delete-subnet --subnet-id=${id} || return 1
    done
}

igwId() {
    [[ $# -ne 1 ]] && { >&2 echo "Usage: $0 $FUNCNAME SYSTEM_ID"; return 1; }
    local systemId vpcId id output
    systemId=$1
    vpcId=$(vpcId ${systemId}) || return
    output=$(aws ec2 describe-internet-gateways --filters Name=attachment.vpc-id,Values=${vpcId}) || return 1
    id=$(echo ${output} | jq -r ".InternetGateways[].InternetGatewayId")
    echo ${id}
}

createInternetGateway() {
    [[ $# -ne 1 ]] && { >&2 echo "Usage: $0 $FUNCNAME SYSTEM_ID"; return 1; }
    local system_id=$1
    output=$(aws ec2 create-internet-gateway) || return 1
    id=$(echo ${output} | jq -er ".InternetGateway.InternetGatewayId") || return 1
    tag ${id} ${system_id}
    output=$(aws ec2 attach-internet-gateway --internet-gateway-id ${id} --vpc-id $(vpcId ${system_id})) || { >&2 echo "Failed to attach Internet gateway to VPC"; return 1; }
}

deleteInternetGateway() {
    [[ $# -ne 1 ]] && { >&2 echo "Usage: $0 $FUNCNAME SYSTEM_ID"; return 1; }
    local systemId start output id vpcId
    systemId=$1
    id=$(igwId ${systemId})
    if [ ! -z ${id} ]; then
        vpcId=$(vpcId ${systemId})
        >/dev/null aws ec2 detach-internet-gateway --internet-gateway-id ${id} --vpc-id ${vpcId} || return 1
        >/dev/null aws ec2 delete-internet-gateway --internet-gateway-id ${id} || return 1
        echo "Deleted ${id}"
    fi
}

createSecurityGroup() {
    [[ $# -ne 3 ]] && { >&2 echo "Usage: $0 $FUNCNAME SYSTEM_ID NAME INGRESS_PERMISSIONS"; return 1; }
    local systemId name ingressPermissions output id
    systemId=$1
    name=$2
    ingressPermissions=$3
    output=$(aws ec2 create-security-group --vpc-id $(vpcId ${systemId}) --group-name ${name} --description "Security group for system ${systemId}") || return 1
    id=$(echo ${output} | jq -er ".GroupId") ||  { >&2 echo "Failed to extract id from response ${output}"; return 1; }
    >/dev/null aws ec2 authorize-security-group-ingress --group-id ${id} --ip-permissions ${ingressPermissions} \
        || { >&2 echo "Failed to add rules to security group"; return 1; }
    echo ${id}
}

deleteSecurityGroups() {
    [[ $# -ne 1 ]] && { >&2 echo "Usage: $0 $FUNCNAME SYSTEM_ID"; return 1; }
    systemId=$1
    output=$(aws ec2 describe-security-groups --filters $(vpcFilter ${systemId})) || return 1
    ids=$(echo ${output} | jq -r ".SecurityGroups[].GroupId")
    for id in ${ids}; do
        aws ec2 delete-security-group --group-id ${id} && echo "Deleted security group ${id}"
    done
}

deleteRouteTables() {
    [[ $# -ne 1 ]] && { >&2 echo "Usage: $0 $FUNCNAME SYSTEM_ID"; return 1; }
    local systemId ids output
    systemId=${1}
    output=$(aws ec2 describe-route-tables --filters $(vpcFilter ${systemId})) || return 1
    ids=$(echo ${output} | jq -r ".RouteTables[].RouteTableId")
    for id in ${ids}; do
        aws ec2 delete-route-table --route-table-id ${id} && echo "Deleted route table ${id}"
    done
}

terminateInstance() {
    [[ $# -ne 2 ]] && { >&2 echo "Usage: $0 $FUNCNAME SYSTEM_ID NAME"; return 1; }
    local systemId name id
    systemId=$1
    name=$2
    id=$(findInstance ${systemId} ${name}) || return 1
    >/dev/null aws ec2 terminate-instances --instance-ids ${id} || return 1
    echo "Terminated instance ${id}"
}

stopInstance() {
    [[ $# -ne 2 ]] && { >&2 echo "Usage: $0 $FUNCNAME SYSTEM_ID NAME"; return 1; }
    local systemId name ids
    systemId=$1
    name=$2
    ids=$(findInstance ${systemId} ${name}) || return 1
    >/dev/null aws ec2 stop-instances --instance-ids ${ids} || return 1
    echo ${ids}
}

startInstance() {
    [[ $# -ne 2 ]] && { >&2 echo "Usage: $0 $FUNCNAME SYSTEM_ID NAME"; return 1; }
    local systemId name ids
    systemId=$1
    name=$2
    ids=$(findInstance ${systemId} ${name}) || return 1
    >/dev/null aws ec2 start-instances --instance-ids ${ids} || return 1
    echo ${ids}
}

findInstance() {
    [[ $# -ne 2 ]] && { >&2 echo "Usage: $0 $FUNCNAME SYSTEM_ID NAME"; return 1; }
    local systemId name output id
    systemId=$1
    name=$2
    output=$(aws ec2 describe-instances --filter $(vpcFilter ${systemId}) $(nameFilter ${name})) || return 1
    id=$(echo ${output} | jq -er ".Reservations[].Instances[].InstanceId") || return 1
    echo ${id}
}

terminateRunningInstances() {
    [[ $# -ne 1 ]] && { >&2 echo "Usage: $0 $FUNCNAME SYSTEM_ID"; return 1; }
    local systemId output ids
    systemId=${1}
    output=$(aws ec2 describe-instances --filter $(vpcFilter ${systemId}) $(runningFilter)) || return 1
    ids=$(echo ${output} | jq -er ".Reservations[].Instances[].InstanceId" | paste -s -d ' ' -) || return 1
    if [ ! -z "${ids}" ]; then
        echo -n "(${ids}) "
        output=$(aws ec2 terminate-instances --instance-ids ${ids}) || return 1
    fi
}

isInstanceRunning() {
    [[ $# -ne 2 ]] && { >&2 echo "Usage: $0 $FUNCNAME SYSTEM_ID NAME"; return 1; }
    local systemId name output id
    systemId=$1
    name=$2
    output=$(aws ec2 describe-instances --filter $(instanceFilter ${systemId} ${name})) || return 1
    echo ${output} | >/dev/null jq -er ".Reservations[].Instances[].InstanceId" || return 1
    echo ${output} | >/dev/null jq -er 'select(.Reservations[].Instances[].State.Name | contains("terminated"))' && return 1
    echo ${output} | >/dev/null jq -er 'select(.Reservations[].Instances[].State.Name | contains("shutting-down"))' && return 1
    echo ${output} | >/dev/null jq -er 'select(.Reservations[].Instances[].State.Name | contains("running"))' && return 0
    return 7
}

isInstanceTerminated() {
    [[ $# -ne 2 ]] && { >&2 echo "Usage: $0 $FUNCNAME SYSTEM_ID NAME"; return 1; }
    local systemId name output id
    systemId=$1
    name=$2
    output=$(aws ec2 describe-instances --filter $(instanceFilter ${systemId} ${name})) || return 1
    echo ${output} | >/dev/null jq -er ".Reservations[].Instances[].InstanceId" || return 1
    echo ${output} | >/dev/null jq -er 'select(.Reservations[].Instances[].State.Name | contains("running"))' && return 1
    echo ${output} | >/dev/null jq -er 'select(.Reservations[].Instances[].State.Name | contains("terminated"))' && { echo "Instance ${name} is terminated"; return 0; }
    return 7
}

isInstanceTerminatedOrNonExisting() {
    [[ $# -ne 1 ]] && { >&2 echo "Usage: $0 $FUNCNAME INSTANCE_ID"; return 1; }
    local instanceId=$1
    local output
    output=$(2>&1 aws ec2 describe-instances --instance-ids ${instanceId})
    local rc=$?
    [ ${rc} -eq 255 ] && echo ${output} | grep -q "InvalidInstanceID.NotFound" && return 0
    [ ! ${rc} -eq 0 ] && return 1
    [ "$(echo ${output} | jq -r ".Reservations[].Instances[].State.Name")" == "terminated" ] && return 0
    [ "$(echo ${output} | jq -r ".Reservations[].Instances[].State.Name")" == "running" ] && return 28
    [ "$(echo ${output} | jq -r ".Reservations[].Instances[].State.Name")" == "shutting-down" ] && return 28
    [ "$(echo ${output} | jq -r ".Reservations[].Instances[].State.Name")" == "stopping" ] && return 28
    return 1
}

waitForInstancesToTerminate() {
    [[ $# -ne 1 ]] && { >&2 echo "Usage: $0 $FUNCNAME SYSTEM_ID"; return 1; }
    system_id=$1
    ids=all
    while [[ "${ids}" != "" ]]; do
        output=$(aws ec2 describe-instances --filter $(tagFilter SystemId ${system_id}) Name=instance-state-name,Values=pending,running,shutting-down,stopping,stopped) || { >&2 echo "Failed to find EC2 instances"; return 1; }
        ids=$(echo ${output} | jq -r ".Reservations[].Instances[].InstanceId" | paste -s -d ' ' -)
        if [ ! -z "${ids}" ]; then
            echo -n "(${ids}) "
            sleep 3
        fi
    done
}

createKeyPair() {
    [[ $# -ne 2 ]] && { >&2 echo "Usage: $0 $FUNCNAME SYSTEM_ID NAME"; return 1; }
    local systemId name file
    systemId=$1
    name=$2
    file=$(keyFile ${systemId} ${name})
    mkdir -p $(dirname ${file})
    aws ec2 create-key-pair --key-name ${name}.${systemId} --query 'KeyMaterial' --output text > ${file} || return 1
    chmod 0400 ${file}
    echo ${name}.${systemId}
}

deleteKeyPair() {
    [[ $# -ne 1 ]] && { >&2 echo "Usage: $0 $FUNCNAME SYSTEM_ID NAME"; return 1; }
    local systemId name file
    systemId=$1
    name=$2
    aws ec2 delete-key-pair --key-name ${name} || return 1
    file=$(keyFile ${name})
    rm -f ${file} || return 1
}

keyFile() {
    [[ $# -ne 2 ]] && { >&2 echo "Usage: $0 $FUNCNAME SYSTEM_ID NAME"; return 1; }
    local systemId name
    systemId=$1
    name=$2
    mkdir -p "$HOME/.aws/systems/${systemId}"
    echo "$HOME/.aws/systems/${systemId}/key_${name}"
}

login() {
    [[ $# -lt 2 ]] && { echo "Usage: $0 $FUNCNAME SYSTEM_ID INSTANCE_NAME [COMMAND]"; return 1; }
    local systemId instanceName ipAddress
    systemId=${1}
    instanceName=${2}
    ipAddress=$(findPublicIp ${systemId} ${instanceName}) || { >&2 echo "Public IP address not found"; return 1; }
    shift 2
    local sshCommand
    sshCommand="ssh -A -o 'StrictHostKeyChecking no' -i $(keyFile ${systemId} ${instanceName}) ec2-user@${ipAddress} $@"
    local i
    eval ${sshCommand}
}

copyKeyToJumpHost() {
    [[ $# -lt 2 ]] && { echo "Usage: $0 $FUNCNAME SYSTEM_ID INSTANCE_NAME"; return 1; }
    local systemId instanceName ipAddress
    systemId=${1}
    instanceName=${2}
    ipAddress=$(findPublicIp ${systemId} JumpHost) || { >&2 echo "Public IP address not found"; return 1; }
    scp -o "StrictHostKeyChecking no" -i $(keyFile ${systemId} JumpHost) $(keyFile ${systemId} ${instanceName}) ec2-user@${ipAddress}:.ssh/
}

findPublicIp() {
    [[ $# -ne 2 ]] && { >&2 echo "Usage: $0 $FUNCNAME SYSTEM_ID INSTANCE_NAME"; return 1; }
    local systemId instanceName output ipAddress
    systemId=$1
    instanceName=$2
    output=$(aws ec2 describe-instances --filter $(nameFilter ${instanceName}) $(vpcFilter ${systemId}) $(runningFilter)) || { >&2 echo "Failed to describe instance ${instanceName}"; return 1; }
    ipAddress=$(echo ${output} | jq -er ".Reservations[].Instances[].PublicIpAddress") || return 1
    echo -n ${ipAddress}
}

createNatInstance() {
    [[ $# -ne 2 ]] && { >&2 echo "Usage: $0 $FUNCNAME SYSTEM_ID CIDR"; return 1; }
    local systemId cidr securityGroupId instanceName
    systemId=$1
    cidr=$2
    securityGroupId=$(createSecurityGroup ${systemId} NatSG "\
            IpProtocol=TCP,FromPort=80,ToPort=80,IpRanges=[{CidrIp=${cidr}}] \
            IpProtocol=TCP,FromPort=443,ToPort=443,IpRanges=[{CidrIp=${cidr}}] \
            ") || return 1
    instanceName="NatHost"
    launchInstance ${systemId} ${instanceName} amzn-ami-vpc-nat-hvm-2016.09.1.20170119-x86_64-ebs PublicZone t2.nano ${securityGroupId} || return 1
    disableSourceDestinationCheck ${systemId} ${instanceName}
    __waitFor "isInstanceRunning ${systemId} ${instanceName}"
    addDefaultRouteToInstanceTarget ${systemId} 0.0.0.0/0 ${instanceName}
}

createNatGateway() {
    [[ $# -ne 2 ]] && { >&2 echo "Usage: $0 $FUNCNAME SYSTEM_ID SUBNET_NAME"; return 1; }
    local systemId subnetName subnetId allocationId natGatewayId routeTableId
    systemId=$1
    subnetName=$2
    subnetId=$(subnetId ${systemId} ${subnetName})
    allocationId=$(aws ec2 allocate-address --domain vpc | jq -er ".AllocationId") || return 1
    natGatewayId=$(aws ec2 create-nat-gateway --subnet-id ${subnetId} --allocation-id ${allocationId} | jq -er ".NatGateway.NatGatewayId") || return 1
    routeTableId=$(mainRouteTableId ${systemId}) || return 1
    >/dev/null aws ec2 create-route --route-table-id ${routeTableId} --destination-cidr-block 0.0.0.0/0 --gateway-id ${natGatewayId} || return 1
}

createSystem() {
    [[ $# -ne 1 ]] && { >&2 echo "Usage: $0 $FUNCNAME SYSTEM_ID"; return 1; }
    local systemId
    systemId=$1
    createVpc ${systemId} || return 1
    createInternetGateway ${systemId} || return 2
    createPublicSubnet ${systemId} 10.0.1.0/24 PublicZone || return 3
    createSubnet ${systemId} 10.0.2.0/24 ApplicationZone || return 4
    jumpSecurityGroupId=$(createSecurityGroup ${systemId} JumpSG "\
            IpProtocol=TCP,FromPort=22,ToPort=22,IpRanges=[{CidrIp=0.0.0.0/0}] \
            ") || return 5
    launchInstance ${systemId} JumpHost amzn-ami-hvm-2016.09.1.20170119-x86_64-gp2 PublicZone t2.nano ${jumpSecurityGroupId} || return 6
    createNatInstance ${systemId} 10.0.2.0/24 || return 7
    #createNatGateway ${systemId} PublicZone || return 7
    applicationSecurityGroupId=$(createSecurityGroup ${systemId} ApplicationSG "\
            IpProtocol=TCP,FromPort=22,ToPort=22,IpRanges=[{CidrIp=0.0.0.0/0}] \
            ") || return 8
    launchInstance ${systemId} ApplicationHost amzn-ami-hvm-2016.09.1.20170119-x86_64-gp2 ApplicationZone t2.nano ${applicationSecurityGroupId} || return 9
}

deleteSystem() {
    [[ $# -ne 1 ]] && { >&2 echo "Usage: $0 $FUNCNAME SYSTEM_ID"; return 1; }
    local systemId
    systemId=$1
    terminateInstance ${systemId} JumpHost
    terminateInstance ${systemId} ApplicationHost
    terminateInstance ${systemId} NatHost
    __waitFor "isInstanceTerminated ${systemId} JumpHost"
    __waitFor "isInstanceTerminated ${systemId} ApplicationHost"
    __waitFor "isInstanceTerminated ${systemId} NatHost"
    deleteInternetGateway ${systemId}
    deleteRouteTables ${systemId}
    deleteSubnets ${systemId}
    deleteSecurityGroups ${systemId}
    deleteVpc ${systemId}
}
