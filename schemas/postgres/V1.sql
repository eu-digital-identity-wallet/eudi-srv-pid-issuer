CREATE TABLE issued_credential
(
    id                              BIGSERIAL PRIMARY KEY,
    format                          VARCHAR(255)             NOT NULL,
    type                            VARCHAR(255)             NOT NULL,
    issued_at                       TIMESTAMP WITH TIME ZONE NOT NULL,
    expires_at                      TIMESTAMP WITH TIME ZONE NOT NULL,
    notification_id                 VARCHAR(255),
    status_list_uri                 VARCHAR(2048),
    status_list_index               BIGINT,
    client_status_list_uri          VARCHAR(2048)            NOT NULL,
    client_status_list_index        BIGINT                   NOT NULL,
    key_storage_status_list_uri     VARCHAR(2048)            NOT NULL,
    key_storage_status_list_index   BIGINT                   NOT NULL
);

CREATE INDEX idx_issued_credential_notification_id ON issued_credential (notification_id);
CREATE INDEX idx_issued_credential_expires_at ON issued_credential (expires_at);
