# AWS_Audit
Auditar Servicios AWS


Inicio rápido

A través del siguiente código, se puede obtener información de algunos servicios configurados en AWS, se puede ejecutar a traves de SSH utilizando un usuario que tenga permisos de auditoria en el ambiente AWS.

# El código esta creado para los siguientes servicios:
EC2
IAM
S3
DB

# Generar reportes:
Utilizando las siguiente instrucciones se obtienen diferentes reportes:

generar_reporte_resumen_aws --> Reporte Completo

listar_buckets_s3

listar_s3_buckets_publicos

listar_sg_all_allow

listar_sg_puerto_3389

listar_sg_puerto_22

listar_sg_puerto_80

listar_sg_puerto_443

listar_instancias_ec2

listar_instancias_db

listar_dbs_no_encrypted

listar_usuarios_iam

listar_usuarios_iam_full_admin

listar_usuarios_iam_root

listar_usuarios_iam_mfa_deshabilitado

listar_s3_buckets_no_encrypted

# Herramientas utilizadas:
Python
boto3 
VSC
AWS

Actualmente, solo se permite obtener información de los servicios mencionados anteriormente. Proporcionaremos nuevo codigo para otros servicios de AWS en el futuro.

Licencia
Para el uso de esta licencia solo deben mencionar al creador del cdigo (Orlando Sandoval).

contribuyendo
¡Gracias por tu interés en contribuir con el proyecto! Consulte las pautas de contribución para obtener más información.

© 2022 GitHub, Inc.
Términos
Privacidad
Seguridad
Estado
Documentos
Póngase en contacto con GitHub
Precios
API
Capacitación
Blog
Acerca de
