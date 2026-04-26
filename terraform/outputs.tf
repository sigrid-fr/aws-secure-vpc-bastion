###############################################################
# OUTPUTS
###############################################################

output "vpc_id" {
  description = "ID da VPC criada"
  value       = aws_vpc.main.id
}

output "vpc_cidr" {
  description = "CIDR block da VPC"
  value       = aws_vpc.main.cidr_block
}

output "public_subnet_ids" {
  description = "IDs das subnets públicas"
  value       = aws_subnet.public[*].id
}

output "private_subnet_ids" {
  description = "IDs das subnets privadas"
  value       = aws_subnet.private[*].id
}

output "bastion_public_ip" {
  description = "IP público do bastion host (EIP)"
  value       = aws_eip.bastion.public_ip
}

output "bastion_private_ip" {
  description = "IP privado do bastion host"
  value       = aws_instance.bastion.private_ip
}

output "private_app_ip" {
  description = "IP privado da instância de aplicação"
  value       = aws_instance.private_app.private_ip
}

output "ssh_command_bastion" {
  description = "Comando para conectar ao bastion via SSH"
  value       = "ssh -i keys/${local.name_prefix}-bastion.pem ec2-user@${aws_eip.bastion.public_ip}"
}

output "ssh_command_private" {
  description = "Comando para conectar à instância privada via ProxyJump"
  value       = "ssh -i keys/${local.name_prefix}-bastion.pem -J ec2-user@${aws_eip.bastion.public_ip} ec2-user@${aws_instance.private_app.private_ip}"
}

output "flow_logs_group" {
  description = "Nome do CloudWatch Log Group dos VPC Flow Logs"
  value       = aws_cloudwatch_log_group.flow_log.name
}

output "allowed_ssh_ip" {
  description = "IP que tem permissão de SSH no bastion"
  value       = local.my_ip_cidr
  sensitive   = false
}

output "security_groups" {
  description = "IDs dos security groups criados"
  value = {
    bastion           = aws_security_group.bastion.id
    private_instances = aws_security_group.private_instances.id
    alb               = aws_security_group.alb.id
  }
}

output "cost_estimate_note" {
  description = "Nota sobre estimativa de custo mensal (us-east-1)"
  value       = "Custo estimado: ~$15-20/mês (2x t3.micro + EIP + Flow Logs). Use 'infracost breakdown --path .' para detalhes."
}
