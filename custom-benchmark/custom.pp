# Possible severity levels for the controls
#  "critical","high","medium","low"

control "wafv2_web_acl_logging_enabled" {
    title       = "Logging should be enabled on AWS WAFv2 regional and global web access control list (ACLs)"
    description = "To help with logging and monitoring within your environment, enable AWS WAF (V2) logging on regional and global web ACLs."
    query       = query.wafv2_web_acl_logging_enabled
    severity    = "low"
  }
  
  
  query "wafv2_web_acl_logging_enabled" {
    sql = <<-EOQ
      select
        arn as resource,
        case
          when logging_configuration is null then 'alarm'
          else 'ok'
        end as status,
        case
          when logging_configuration is null then title || ' logging disabled.'
          else title || ' logging enabled.'
        end as reason
      from
        aws_wafv2_web_acl;
    EOQ
  }
  
  
  control "wafv2_web_acl_rule_attached" {
    title       = "A WAFV2 web ACL should have at least one rule or rule group"
    description = "This control checks whether a WAFV2 web access control list (web ACL) contains at least one WAF rule or WAF rule group. The control fails if a web ACL does not contain any WAF rules or rule groups."
    query       = query.wafv2_web_acl_rule_attached
    severity    = "high"
    }
  
  
  # Non-Config rule query
  
  query "wafv2_web_acl_rule_attached" {
    sql = <<-EOQ
with rule_group_count as (
  select
    arn,
    count(*) as rule_group_count
  from
    aws_wafv2_web_acl,
    jsonb_array_elements(rules) as r
  where
    r -> 'Statement' -> 'RuleGroupReferenceStatement' ->> 'ARN' is not null
  group by
    arn
)
select
  a.arn as resource,
  case
    when rules is null
    or jsonb_array_length(rules) = 0 then 'alarm'
    else 'ok'
  end as status,
  case
    when rules is null
    or jsonb_array_length(rules) = 0 then title || ' has no attached rules.'
    else title || ' has ' || c.rule_group_count || ' rule group(s) and ' || (jsonb_array_length(rules) - c.rule_group_count) || ' rule(s) attached.'
  end as reason,
  region,
  account_id
from
  aws_wafv2_web_acl as a
  left join rule_group_count as c on c.arn = a.arn;
    EOQ
  }
  
  query "alb_attached_to_waf" {
    sql = <<-EOQ
    with wafv2_with_alb as (
      select
        jsonb_array_elements_text(waf.associated_resources) as arn
      from
        aws_wafv2_web_acl as waf
    )
      select alb.arn as resource, 
      case 
        when alb.arn =  temp.arn then 'ok'
      else 'alarm'
      end as status,
      case 
        when alb.arn =  temp.arn then title || ' has associated WAF'
        else title || ' is not associated with WAF.'
      end as reason,
      region,
      account_id

    from aws_ec2_application_load_balancer as alb
      left join wafv2_with_alb  as temp on alb.arn =  temp.arn
    where "scheme" = 'internet-facing';
    EOQ
  }


  control "alb_attached_to_waf" { 
    title       = "Public facing ALB are protected by AWS Web Application Firewall v2 (AWS WAFv2)"
    description = "Ensure public facing ALB are protected by AWS Web Application Firewall v2 "
    query       = query.alb_attached_to_waf
    severity    = "medium"
    }
  
#

  control "autoscaling_group_multiple_az_configured" { 
    title       = "EC2 auto scaling groups should cover multiple availability zones"
    description = "This control checks whether an AWS EC2 Auto Scaling group spans multiple availability zones. The control fails if an auto scaling group does not span multiple availability zones."
    query       = query.autoscaling_group_multiple_az_configured
    severity    = "high"
    }

  query "autoscaling_group_multiple_az_configured" {
    sql = <<-EOQ
    select
  autoscaling_group_arn as resource,
  case
    when jsonb_array_length(availability_zones) > 1 then 'ok'
    else 'alarm'
  end as status,
  title || ' has ' || jsonb_array_length(availability_zones) || ' availability zone(s).' as reason,
  region,
  account_id
from
  aws_ec2_autoscaling_group;
    EOQ
  }

#

  control "s3_bucket_versioning_and_lifecycle_policy_enabled" { 
    title       = "S3 buckets should have lifecycle policies configured"
    description = "This control checks if AWS Simple Storage Service (AWS S3) version enabled buckets have lifecycle policy configured. This rule fails if AWS S3 lifecycle policy is not enabled"
    query       = query.s3_bucket_versioning_and_lifecycle_policy_enabled
    severity    = "high"
    }

  query "s3_bucket_versioning_and_lifecycle_policy_enabled" {
    sql = <<-EOQ
    with lifecycle_rules_enabled as (
  select
    arn
  from
    aws_s3_bucket,
    jsonb_array_elements(lifecycle_rules) as r
  where
    r ->> 'Status' = 'Enabled'
)
select
  b.arn as resource,
  case
    when not versioning_enabled then 'alarm'
    when versioning_enabled
    and r.arn is not null then 'ok'
    else 'alarm'
  end as status,
  case
    when not versioning_enabled then name || ' versioning diabled.'
    when versioning_enabled
    and r.arn is not null then name || ' lifecycle policy configured.'
    else name || ' lifecycle policy not configured.'
  end as reason,
  b.region,
  b.account_id
from
  aws_s3_bucket as b
  left join lifecycle_rules_enabled as r on r.arn = b.arn;
    EOQ
  }

#

  benchmark "new_custom_benchmark" {
    title       = "Architecture"
    description = "Architecture Guardrails"
    children = [
      control.wafv2_web_acl_logging_enabled,
      control.alb_attached_to_waf,
      control.wafv2_web_acl_rule_attached,
      control.autoscaling_group_multiple_az_configured,
      control.s3_bucket_versioning_and_lifecycle_policy_enabled
    ] 
 }
