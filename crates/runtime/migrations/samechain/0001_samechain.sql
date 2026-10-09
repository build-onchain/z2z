CREATE TABLE ops (
    op_id bytea PRIMARY KEY CHECK (octet_length(op_id) = 32),
    deployment_digest bytea NOT NULL CHECK (octet_length(deployment_digest) = 32),
    operation smallint NOT NULL CHECK (operation BETWEEN 0 AND 4),
    role smallint NOT NULL CHECK (role IN (0, 1)),
    packet_digest bytea NOT NULL CHECK (octet_length(packet_digest) = 32),
    program_vkey bytea NOT NULL CHECK (octet_length(program_vkey) = 32),
    journal_digest bytea NOT NULL CHECK (octet_length(journal_digest) = 32),
    expiry numeric(20, 0) NOT NULL CHECK (expiry > 0),
    required_nf_count smallint NOT NULL CHECK (required_nf_count BETWEEN 0 AND 2),
    required_nf0 bytea NULL CHECK (required_nf0 IS NULL OR octet_length(required_nf0) = 32),
    required_nf1 bytea NULL CHECK (required_nf1 IS NULL OR octet_length(required_nf1) = 32),
    binding_digest bytea NOT NULL CHECK (octet_length(binding_digest) = 32),
    release_digest bytea NULL CHECK (release_digest IS NULL OR octet_length(release_digest) = 32),
    state smallint NOT NULL CHECK (state IN (0, 1)),
    version bigint NOT NULL,
    writer_generation bigint NOT NULL,
    CHECK ((state = 0 AND release_digest IS NULL) OR (state = 1 AND release_digest IS NOT NULL)),
    CHECK ((required_nf_count = 0 AND required_nf0 IS NULL AND required_nf1 IS NULL)
        OR (required_nf_count = 1 AND required_nf0 IS NOT NULL AND required_nf1 IS NULL)
        OR (required_nf_count = 2 AND required_nf0 IS NOT NULL AND required_nf1 IS NOT NULL))
);
