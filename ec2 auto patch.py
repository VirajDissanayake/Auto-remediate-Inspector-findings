import json
import boto3

ssm = boto3.client('ssm')
inspector = boto3.client('inspector')

def lambda_handler(event, context):
    print(json.dumps(event))
    message = event['Records'][0]['Sns']['Message']
    eventType = json.loads(message)['event']
    
    if eventType != "FINDING_REPORTED":
        return 1
        
    findingArn = json.loads(message)['finding']
    response = inspector.describe_findings(
        findingArns=[findingArn], locale='EN_US')
    assetType = response['findings'][0]['assetType']
    
    if assetType == "ec2-instance":
        InstanceId = response['findings'][0]['assetAttributes']['agentId']
        if response['findings'][0]['recommendation'] != "No remediation needed.":
            remediate(InstanceId)
        
def remediate(id):
    response = ssm.send_command(
        InstanceIds=[
            id
        ],
        DocumentName='AWS-RunPatchBaseline',
        Parameters={
            'Operation': [
                'Install'
            ]
        }
    )
    print(response)
