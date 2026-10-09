CREATE TABLE quotes (
    owner_scope BYTEA NOT NULL CHECK (octet_length(owner_scope) = 32),
    session_id BYTEA NOT NULL CHECK (octet_length(session_id) = 32),
    quote_id BYTEA NOT NULL CHECK (octet_length(quote_id) = 32),
    local_role SMALLINT NOT NULL CHECK (local_role IN (0, 1)),
    initiator_coord_key BYTEA NOT NULL CHECK (octet_length(initiator_coord_key) = 32),
    responder_coord_key BYTEA NOT NULL CHECK (octet_length(responder_coord_key) = 32),
    chain_context BYTEA NOT NULL CHECK (octet_length(chain_context) = 32),
    deployment_context BYTEA NOT NULL CHECK (octet_length(deployment_context) = 32),
    s_offer_id BYTEA NOT NULL CHECK (octet_length(s_offer_id) = 32),
    u_trade_intent_id BYTEA NOT NULL CHECK (octet_length(u_trade_intent_id) = 32),
    challenge_i BYTEA NOT NULL CHECK (octet_length(challenge_i) = 32),
    challenge_r BYTEA NOT NULL CHECK (octet_length(challenge_r) = 32),
    proposal_seq BIGINT NOT NULL CHECK (proposal_seq BETWEEN 1 AND 4294967295),
    user_acceptance_seq BIGINT NOT NULL CHECK (user_acceptance_seq BETWEEN 1 AND 4294967295),
    solver_acceptance_seq BIGINT NOT NULL CHECK (solver_acceptance_seq BETWEEN 1 AND 4294967295),
    q_digest BYTEA NOT NULL CHECK (octet_length(q_digest) = 32),
    proposal_hash BYTEA NOT NULL CHECK (octet_length(proposal_hash) = 32),
    user_acceptance_hash BYTEA NULL CHECK (user_acceptance_hash IS NULL OR octet_length(user_acceptance_hash) = 32),
    solver_acceptance_hash BYTEA NULL CHECK (solver_acceptance_hash IS NULL OR octet_length(solver_acceptance_hash) = 32),
    agreement_digest BYTEA NULL CHECK (agreement_digest IS NULL OR octet_length(agreement_digest) = 32),
    phase SMALLINT NOT NULL CHECK (phase BETWEEN 0 AND 2),
    capsule_digest BYTEA NOT NULL CHECK (octet_length(capsule_digest) = 32),
    stopped BOOLEAN NOT NULL DEFAULT FALSE,
    version BIGINT NOT NULL CHECK (version > 0),
    writer_generation BIGINT NOT NULL CHECK (writer_generation > 0),
    PRIMARY KEY (owner_scope, session_id, quote_id, local_role),
    CHECK ((phase = 0 AND user_acceptance_hash IS NULL AND solver_acceptance_hash IS NULL AND agreement_digest IS NULL)
        OR (phase = 1 AND user_acceptance_hash IS NOT NULL AND solver_acceptance_hash IS NULL AND agreement_digest IS NULL)
        OR (phase = 2 AND user_acceptance_hash IS NOT NULL AND solver_acceptance_hash IS NOT NULL AND agreement_digest IS NOT NULL))
);

CREATE TABLE trades (
    owner_scope BYTEA NOT NULL CHECK (octet_length(owner_scope) = 32),
    session_id BYTEA NOT NULL CHECK (octet_length(session_id) = 32),
    quote_id BYTEA NOT NULL CHECK (octet_length(quote_id) = 32),
    local_role SMALLINT NOT NULL CHECK (local_role IN (0, 1)),
    op_id BYTEA NOT NULL CHECK (octet_length(op_id) = 32),
    context_digest BYTEA NOT NULL CHECK (octet_length(context_digest) = 32),
    deployment_digest BYTEA NOT NULL CHECK (octet_length(deployment_digest) = 32),
    stable_j_tag BYTEA NOT NULL CHECK (octet_length(stable_j_tag) = 32),
    payload_digest BYTEA NOT NULL CHECK (octet_length(payload_digest) = 32),
    action SMALLINT NOT NULL CHECK (action > 0),
    state SMALLINT NOT NULL CHECK (state BETWEEN 0 AND 3),
    capsule_digest BYTEA NULL CHECK (capsule_digest IS NULL OR octet_length(capsule_digest) = 32),
    tx_hash BYTEA NULL CHECK (tx_hash IS NULL OR octet_length(tx_hash) = 32),
    version BIGINT NOT NULL CHECK (version > 0),
    writer_generation BIGINT NOT NULL CHECK (writer_generation > 0),
    PRIMARY KEY (owner_scope, session_id, quote_id, local_role, op_id),
    FOREIGN KEY (owner_scope, session_id, quote_id, local_role)
        REFERENCES quotes (owner_scope, session_id, quote_id, local_role),
    CHECK ((state = 0 AND capsule_digest IS NULL AND tx_hash IS NULL)
        OR (state = 1 AND capsule_digest IS NOT NULL AND tx_hash IS NULL)
        OR (state = 2 AND capsule_digest IS NOT NULL AND tx_hash IS NOT NULL)
        OR (state = 3 AND capsule_digest IS NOT NULL))
);

CREATE TABLE releases (
    owner_scope BYTEA NOT NULL CHECK (octet_length(owner_scope) = 32),
    session_id BYTEA NOT NULL CHECK (octet_length(session_id) = 32),
    quote_id BYTEA NOT NULL CHECK (octet_length(quote_id) = 32),
    local_role SMALLINT NOT NULL CHECK (local_role IN (0, 1)),
    op_id BYTEA NOT NULL CHECK (octet_length(op_id) = 32),
    capsule_digest BYTEA NOT NULL CHECK (octet_length(capsule_digest) = 32),
    version BIGINT NOT NULL CHECK (version > 0),
    PRIMARY KEY (owner_scope, session_id, quote_id, local_role, op_id),
    FOREIGN KEY (owner_scope, session_id, quote_id, local_role, op_id)
        REFERENCES trades (owner_scope, session_id, quote_id, local_role, op_id)
);

CREATE TABLE reservations (
    owner_scope BYTEA NOT NULL CHECK (octet_length(owner_scope) = 32),
    deployment_digest BYTEA NOT NULL CHECK (octet_length(deployment_digest) = 32),
    stable_j_tag BYTEA NOT NULL CHECK (octet_length(stable_j_tag) = 32),
    action SMALLINT NOT NULL CHECK (action > 0),
    op_id BYTEA NOT NULL CHECK (octet_length(op_id) = 32),
    session_id BYTEA NOT NULL CHECK (octet_length(session_id) = 32),
    quote_id BYTEA NOT NULL CHECK (octet_length(quote_id) = 32),
    local_role SMALLINT NOT NULL CHECK (local_role IN (0, 1)),
    PRIMARY KEY (owner_scope, deployment_digest, stable_j_tag, action),
    FOREIGN KEY (owner_scope, session_id, quote_id, local_role, op_id)
        REFERENCES trades (owner_scope, session_id, quote_id, local_role, op_id)
);
