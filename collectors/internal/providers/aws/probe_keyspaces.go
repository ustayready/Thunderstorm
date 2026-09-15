package aws

// Exposure probes for Amazon Keyspaces.
//
// Skipped operations:
//   - ListTagsForResource (aws-keyspaces-table-tags-value-config):
//     The site requires a table-level ARN (resourceArn: <table-arn>), but the
//     Keyspaces manifest only enumerates aws:keyspaces:keyspace resources. No
//     table ARN is available in the inventory item, so this fetcher cannot be
//     driven from the primary resource without a sub-resource lookup.
//   - CQL SELECT (aws-keyspaces-table-row-data-plane):
//     access_mode is data_plane, not read_api — excluded per probe rules.
