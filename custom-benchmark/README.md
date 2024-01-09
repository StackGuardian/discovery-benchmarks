# custom-benchmark
Example of a Custom Benchmark for stackguardian.io platform

These example benchmark is providing 5 self-created architecture checks. 
These can be added in app.stackguardian.io. 
The benchmark checks are: 

- Logging should be enabled on AWS WAFv2 regional and global web access control list (ACLs)
- A WAFV2 web ACL should have at least one rule or rule group
- Public facing ALB are protected by AWS Web Application Firewall v2 (AWS WAFv2)
- EC2 auto scaling groups should cover multiple availability zones
- S3 buckets should have lifecycle policies configured
