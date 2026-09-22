/**
 * Single source of truth for "which ioc_items rows does this exact file hash
 * belong to via a proven file-artifact alias".
 *
 * Shared by the IOC Search DSL (`md5|sha1|sha256 equals`, full-hash
 * `ioc contains|equals`) and the exact lookup paths (MCP lookup_ioc /
 * bulk_lookup_iocs / get_ioc_context) so search and lookup can never disagree on
 * logical-file identity.
 *
 * Semantics: the artifact that owns the exact (hash_type, normalized value) —
 * followed through a merge tombstone to its survivor — and every IOC linked to
 * that artifact. Only proven exact hashes in file_artifact_hashes qualify; there
 * is no fuzzy/partial matching here.
 *
 * Returns a SELECT yielding (ioc_observable_type, ioc_item_id). Callers pass SQL
 * expressions for the hash type and value: a whitelisted literal + bind
 * placeholder (search builder) or correlated columns (batched LATERAL lookup).
 * Never pass user text as `hashTypeSql`.
 *
 * @param {string} hashTypeSql SQL expression for the hash type ('md5'|'sha1'|'sha256')
 * @param {string} hashValueSql SQL expression for the lowercased hex value
 * @returns {string}
 */
export function artifactAliasIocMembershipSql(hashTypeSql, hashValueSql) {
  return `SELECT fal.ioc_observable_type, fal.ioc_item_id
        FROM file_artifact_hashes h
        JOIN file_artifacts hfa ON hfa.id = h.artifact_id
        JOIN file_artifact_ioc_links fal
          ON fal.artifact_id = COALESCE(
               CASE
                 WHEN hfa.status = 'merged' AND hfa.merged_into_artifact_id IS NOT NULL
                   THEN hfa.merged_into_artifact_id
                 ELSE hfa.id
               END,
               hfa.id
             )
       WHERE h.hash_type = ${hashTypeSql} AND h.normalized_hash_value = ${hashValueSql}`;
}
