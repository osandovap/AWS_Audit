import sys
import boto3
from botocore.exceptions import ClientError

if len(sys.argv) < 2:
    exit("Por favor proveer los parametros necesarios: tipo_check \nDetalles:\ntipo_check=(Resumen, Todos, 1-16)\n")

tipo_check = sys.argv[1]

ec2 = boto3.client('ec2')
iam = boto3.client('iam')
s3 = boto3.client('s3')
rds = boto3.client('rds')

path_reporte = "/home/tfmaudit/Downloads/Reporte_audit.json"

def generar_reporte_resumen_aws():
    with open(path_reporte, 'w') as f:
        f.write('-------------------------------------------- REPORTE GENERADO (RESUMEN) --------------------------------------------\n')
        print('\nConsultando Buckets S3...\n')
        response = s3.list_buckets()
        f.write('\nS3 BUCKETS:\n')
        for bucket in response['Buckets']:
            f.write(str(bucket['Name'])+'\n')
        print('Consultando EC2 security_groups...\n')
        response = ec2.describe_security_groups()
        f.write('\nEC2 SECURITY GROUPS:\n'+str(response).replace("{'Description':","\n  {'Description':").replace("], 'ResponseMetadata':","\n],'ResponseMetadata':").replace("}}","}\n}")+'\n')
        print('Consultando EC2 instances...\n')
        response = ec2.describe_instances()
        f.write('\nEC2 INSTANCES:\n')
        for reservation in response['Reservations']:
            for instance in reservation['Instances']:
                f.write(str(instance)+'\n')
        print('Consultando IAM User Detail List...\n')
        response = iam.get_account_authorization_details(Filter=['User'])['UserDetailList']
        f.write('\nIAM USER DETAIL LIST:\n')
        for user_detail in response:
            policyName = []
            policyArn = []
            for policy in user_detail['AttachedManagedPolicies']:
                policyName.append(policy['PolicyName'])
                policyArn.append(policy['PolicyArn'])
                f.write('User: {0}\nUserId: {1}\n PolicyName: {2}\n PolicyArn: {3}\n'.format(user_detail['UserName'],user_detail['UserId'],policyName,policyArn))

def generar_reporte_check_Todos():
    print('\nTodos los Checks Pendiente..\n')

def listar_buckets_s3_check_1():
    with open(path_reporte, 'w') as f:
        print('\nCheck No 1 - Consultando lista de buckets S3..\n')
        f.write('-------------------------------------------- REPORTE GENERADO (listar S3 Buckets) --------------------------------------------\n')
        response = s3.list_buckets()
        f.write('\nS3 BUCKETS LIST:\n')
        for bucket in response['Buckets']:
            f.write(bucket['Name'])

def listar_s3_buckets_publicos_check_2():
    with open(path_reporte, 'w') as f:
        print('\nCheck No 2 - Consultando lista de buckets S3 Publicos..\n')
        f.write('-------------------------------------------- REPORTE GENERADO (listar S3 Buckets Publicos) --------------------------------------------\n')
        response = s3.list_buckets()
        f.write('\nS3 BUCKETS LIST:\n')
        for bucket in response['Buckets']:
            response1 = s3.get_public_access_block(Bucket=bucket['Name'])
            if (str(response1['PublicAccessBlockConfiguration']['BlockPublicAcls'])=='False' and str(response1['PublicAccessBlockConfiguration']['BlockPublicPolicy'])=='False'):
                f.write(str(bucket['Name'])+'\n')

def listar_sg_all_allow_check_3():
    with open(path_reporte, 'w') as f:
        print('\nCheck No 3 - Security Groups Check todos los puertos abiertos..\n')
        f.write('-------------------------------------------- REPORTE GENERADO (SECURITY GROUPS - TODO EL TRAFICO ABIERTO) --------------------------------------------\n')
        response = ec2.describe_security_groups()
        f.write('\nEC2 SECURITY GROUPS:\n')
        for sec_group in response['SecurityGroups']:
            for ippermissions in sec_group['IpPermissions']:
                if (ippermissions['IpProtocol']=='-1' or sec_group['GroupName']=='default'):
                    f.write(str(sec_group)+'\n')
                        
def listar_sg_puerto_3389_check_4():
    with open(path_reporte, 'w') as f:
        print('\nCheck No 4 - Consultando Security Groups con puerto 3389 abierto..\n')
        f.write('-------------------------------------------- REPORTE GENERADO (SECURITY GROUPS - PUERTO 3389 ABIERTO) --------------------------------------------\n')
        response = ec2.describe_security_groups()
        f.write('\nEC2 SECURITY GROUPS:\n')
        for sec_group in response['SecurityGroups']:
            for ippermissions in sec_group['IpPermissions']:
                if 'FromPort' in ippermissions:
                    if(str(ippermissions['FromPort'])=='3389' and str(ippermissions['ToPort'])=='3389'):
                        f.write(str(sec_group)+'\n')

def listar_sg_puerto_22_check_5():
    with open(path_reporte, 'w') as f:
        print('\nCheck No 5 - Consultando Security Groups con puerto 22 abierto..\n')
        f.write('-------------------------------------------- REPORTE GENERADO (SECURITY GROUPS - PUERTO 22 ABIERTO) --------------------------------------------\n')
        response = ec2.describe_security_groups()
        f.write('\nEC2 SECURITY GROUPS:\n')
        for sec_group in response['SecurityGroups']:
            for ippermissions in sec_group['IpPermissions']:
                if 'FromPort' in ippermissions:
                    if(str(ippermissions['FromPort'])=='22' and str(ippermissions['ToPort'])=='22'):
                        f.write(str(sec_group)+'\n')

def listar_sg_puerto_80_check_6():
    with open(path_reporte, 'w') as f:
        print('\nCheck No 6 - Consultando Security Groups con puerto 80 abierto..\n')
        f.write('-------------------------------------------- REPORTE GENERADO (SECURITY GROUPS - PUERTO 80 ABIERTO) --------------------------------------------\n')
        response = ec2.describe_security_groups()
        f.write('\nEC2 SECURITY GROUPS:\n')
        for sec_group in response['SecurityGroups']:
            for ippermissions in sec_group['IpPermissions']:
                if 'FromPort' in ippermissions:
                    if(str(ippermissions['FromPort'])=='80' and str(ippermissions['ToPort'])=='80'):
                        f.write(str(sec_group)+'\n')

def listar_sg_puerto_443_check_7():
    with open(path_reporte, 'w') as f:
        print('\nCheck No 7 - Consultando Security Groups con puerto 443 abierto..\n')
        f.write('-------------------------------------------- REPORTE GENERADO (SECURITY GROUPS - PUERTO 443 ABIERTO) --------------------------------------------\n')
        response = ec2.describe_security_groups()
        f.write('\nEC2 SECURITY GROUPS:\n')
        for sec_group in response['SecurityGroups']:
            for ippermissions in sec_group['IpPermissions']:
                if 'FromPort' in ippermissions:
                    if(str(ippermissions['FromPort'])=='443' and str(ippermissions['ToPort'])=='443'):
                        f.write(str(sec_group)+'\n')

def listar_instancias_ec2_check_8():
    with open(path_reporte, 'w') as f:
        print('\nCheck No 8 - Consultando instancias EC2..\n')
        f.write('-------------------------------------------- REPORTE GENERADO (Listar Instancias EC2) --------------------------------------------\n')
        response = ec2.describe_instances()
        f.write('\nEC2 listar instancias:\n')
        for reservation in response['Reservations']:
            for instance in reservation['Instances']:
                f.write(str(instance)+'\n')

def listar_instancias_db_check_9():
     with open(path_reporte, 'w') as f:
        print('\nCheck No 9 - Consultando DBS..\n')
        f.write('-------------------------------------------- REPORTE GENERADO (Listar Bases de datos) --------------------------------------------\n')
        response = rds.describe_db_instances()
        f.write('\nRDS describir db:\n')
        for database in response['DBInstances']:
                f.write(str(database['DBInstanceIdentifier'])+'\n')

def listar_dbs_no_encrypted_check_10():
     with open(path_reporte, 'w') as f:
        print('\nCheck No 10 - Consultando DBS no cifradas..\n')
        f.write('-------------------------------------------- REPORTE GENERADO (Listar Bases de datos no cifradas) --------------------------------------------\n')
        response = rds.describe_db_instances()
        f.write('\nRDS listar db no Cifradas:\n')
        for database in response['DBInstances']:
            if database['StorageEncrypted'] == False:
                f.write(str(database['DBInstanceIdentifier'])+'\n')

def listar_usuarios_iam_check_11():
     with open(path_reporte, 'w') as f:
        print('\nCheck No 11 - Consultando usuarios IAM..\n')
        f.write('-------------------------------------------- REPORTE GENERADO (Lista de usuarios IAM) --------------------------------------------\n')
        response = iam.get_account_authorization_details(Filter=['User'])['UserDetailList']
        f.write('\nIAM USER DETAIL LIST:\n')
        for user_detail in response:
            policyName = []
            policyArn = []
            for policy in user_detail['AttachedManagedPolicies']:
                policyName.append(policy['PolicyName'])
                policyArn.append(policy['PolicyArn'])
                f.write('User: {0}\nUserId: {1}\n PolicyName: {2}\n PolicyArn: {3}\n'.format(user_detail['UserName'],user_detail['UserId'],policyName,policyArn))

def listar_usuarios_iam_full_admin_check_12():
    with open(path_reporte, 'w') as f:
        print('\nCheck No 12 - Consultando IAM Users con Full Admin role..\n')
        f.write('-------------------------------------------- REPORTE GENERADO (IAM USERS - FULL ADMIN ROLE) --------------------------------------------\n')
        response = iam.get_account_authorization_details(Filter=['User'])['UserDetailList']
        f.write('\nIAM USER DETAIL LIST:\n')
        for user_detail in response:
            policyName = []
            policyArn = []
            for policy in user_detail['AttachedManagedPolicies']:
                if(str(policy['PolicyName'])=='Full-Admin'):
                    policyName.append(policy['PolicyName'])
                    policyArn.append(policy['PolicyArn'])
                    f.write('User: {0}\nUserId: {1}\n PolicyName: {2}\n PolicyArn: {3}\n'.format(user_detail['UserName'],user_detail['UserId'],policyName,policyArn))

def listar_usuarios_iam_root_check_13():
    with open(path_reporte, 'w') as f:
        print('\nCheck No 13 - Consultando IAM Users con UserName root..\n')
        f.write('-------------------------------------------- REPORTE GENERADO (IAM USERS - ROOT USERNAME) --------------------------------------------\n')
        response = iam.get_account_authorization_details(Filter=['User'])['UserDetailList']
        f.write('\nIAM USER DETAIL LIST:\n')
        for user_detail in response:
            policyName = []
            policyArn = []
            for policy in user_detail['AttachedManagedPolicies']:
                if(str(user_detail['UserName'])=='root'):
                    policyName.append(policy['PolicyName'])
                    policyArn.append(policy['PolicyArn'])
                    f.write('User: {0}\nUserId: {1}\n PolicyName: {2}\n PolicyArn: {3}\n'.format(user_detail['UserName'],user_detail['UserId'],policyName,policyArn))

def listar_usuarios_iam_mfa_deshabilitado_check_14():
    with open(path_reporte, 'w') as f:
        print('\nCheck No 14 - Consultando usuarios IAM con MFA deshabilitado..\n')
        f.write('-------------------------------------------- REPORTE GENERADO (IAM USERS - MFA Deshabilitado) --------------------------------------------\n')
        response = iam.list_users()
        f.write('\nIAM USER DETAIL LIST:\n')
        userVirtualMfa = iam.list_virtual_mfa_devices()
        for user in response['Users']:
            userMfa = iam.list_mfa_devices(UserName=user['UserName'])
            virtualEnabled = []
            for uname in userMfa['MFADevices']:
                virtualEnabled.append(uname['UserName'])

            if len(userMfa['MFADevices']) == 0 :
                if user['UserName'] not in virtualEnabled:
                    f.write('User: {0}\nUserId: {1}\n'.format(user['UserName'],user['UserId']))
                    
def generar_reporte_check_15():
    with open(path_reporte, 'w') as f:
        print('\nCheck No 15 - Consultando IAM Users con EC2 ReadOnly Role..\n')

def generar_reporte_check_16():
    with open(path_reporte, 'w') as f:
        print('\nCheck No 16 - Consultando IAM Users con EC2 ReadOnly Role..\n')

try:
    if(tipo_check == 'Resumen'):
        generar_reporte_resumen_aws()
    if(tipo_check == 'Todos'):
        generar_reporte_check_Todos()
    if(tipo_check == '1'):
        listar_buckets_s3_check_1()
    if(tipo_check == '2'):
        listar_s3_buckets_publicos_check_2()
    if(tipo_check == '3'):
        listar_sg_all_allow_check_3()
    if(tipo_check == '4'):
        listar_sg_puerto_3389_check_4()
    if(tipo_check == '5'):
        listar_sg_puerto_22_check_5()
    if(tipo_check == '6'):
        listar_sg_puerto_80_check_6()
    if(tipo_check == '7'):
        listar_sg_puerto_443_check_7()
    if(tipo_check == '8'):
        listar_instancias_ec2_check_8()
    if(tipo_check == '9'):
        listar_instancias_db_check_9()
    if(tipo_check == '10'):
        listar_dbs_no_encrypted_check_10() 
    if(tipo_check == '11'):
        listar_usuarios_iam_check_11()
    if(tipo_check == '12'):
        listar_usuarios_iam_full_admin_check_12()
    if(tipo_check == '13'):
        listar_usuarios_iam_root_check_13()
    if(tipo_check == '14'):
        listar_usuarios_iam_mfa_deshabilitado_check_14()
    if(tipo_check == '15'):
        generar_reporte_check_15()#pendiente
    if(tipo_check == '16'):
        generar_reporte_check_16()#pendiente

    print('Reporte Generado.\n')
except ClientError as e:
    print('error: '+str(e))




