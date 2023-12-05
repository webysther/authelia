CREATE TABLE IF NOT EXISTS one_time_code (
    id SERIAL CONSTRAINT one_time_code_pkey PRIMARY KEY,
	public_id CHAR(36) NOT NULL,
    signature VARCHAR(128) NOT NULL,
    issued TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    issued_ip VARCHAR(39) NOT NULL,
	expires TIMESTAMP WITH TIME ZONE NOT NULL,
    username VARCHAR(100) NOT NULL,
	intent VARCHAR(100) NOT NULL,
    consumed TIMESTAMP WITH TIME ZONE NULL DEFAULT NULL,
    consumed_ip VARCHAR(39) NULL DEFAULT NULL,
    revoked TIMESTAMP WITH TIME ZONE NULL DEFAULT NULL,
	revoked_ip VARCHAR(39) NULL DEFAULT NULL,
	code BYTEA NOT NULL
);

CREATE UNIQUE INDEX one_time_code_lookup_key ON one_time_code (signature, username);
CREATE INDEX one_time_code_lookup ON one_time_code (signature, username);
