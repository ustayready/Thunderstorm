package aws

// No exposure-probe fetchers are registered for the vpc service.
//
// Skipped read_api sites:
//
//   DescribeVpnConnections (aws-vpc-vpn-customer-gateway-configuration):
//     Requires a vpn-connection-id, which is a sub-resource not enumerated by
//     the aws:vpc:vpc inventory (id_field: vpc_id). Cannot drive from the VPC
//     primary identifier alone.
//
//   DescribeVpcEndpoints (aws-vpc-vpc-endpoint-policy-config):
//     Requires a vpc-endpoint-id, which is a sub-resource not enumerated by
//     the aws:vpc:vpc inventory (id_field: vpc_id). Cannot drive from the VPC
//     primary identifier alone.
//
//   DescribeTags (aws-vpc-resource-tags-value-config):
//     This is the EC2 ec2:DescribeTags operation (same API surface). It is
//     already registered in probe_ec2.go for aws:ec2:instance. Registering it
//     again here would silently overwrite that entry in the shared
//     exposureFetchers map (map key = operation string), causing data loss for
//     the ec2 service. Skipped to preserve the existing registration.
//
//   aws-vpc-traffic-mirror-packet-payload:
//     access_mode is indirect_destination, not read_api. Not a read-API probe.
