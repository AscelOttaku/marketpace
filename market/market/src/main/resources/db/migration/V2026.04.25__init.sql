CREATE TABLE users
(
    id         BIGSERIAL PRIMARY KEY,

    name       VARCHAR(100) NOT NULL,
    surname    VARCHAR(100),
    patronymic VARCHAR(100),

    msisdn     VARCHAR(20)  NOT NULL,
    email      VARCHAR(255) NOT NULL,
    password   VARCHAR(255) NOT NULL,
    role       varchar(100),

    CONSTRAINT chk_role_check
        CHECK (role in ('USER'))
);

CREATE TABLE account
(
    id         BIGSERIAL PRIMARY KEY,

    balance    NUMERIC(19, 2) NOT NULL DEFAULT 0,
    user_id    BIGINT         NOT NULL UNIQUE,
    status     VARCHAR(30)    NOT NULL DEFAULT 'ACTIVE',

    created_at TIMESTAMP      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP      NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_account_user
        FOREIGN KEY (user_id)
            REFERENCES users (id)
            ON DELETE CASCADE,

    CONSTRAINT chk_account_balance_not_negative
        CHECK (balance >= 0),

    CONSTRAINT chk_account_status
        CHECK (status IN ('ACTIVE', 'BLOCKED'))
);

CREATE TABLE buyer
(
    id         BIGSERIAL PRIMARY KEY,

    user_id    BIGINT    NOT NULL UNIQUE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_buyer_user
        FOREIGN KEY (user_id)
            REFERENCES users (id)
            ON DELETE CASCADE
);

CREATE TABLE product
(
    id          BIGSERIAL PRIMARY KEY,

    name        VARCHAR(255)   NOT NULL,
    description TEXT,

    price       NUMERIC(19, 2) NOT NULL,
    user_id     BIGINT         NOT NULL,

    img         BYTEA,
    status      VARCHAR(30)    NOT NULL DEFAULT 'ACTIVE',

    buyer_id    BIGINT,
    quantity    INT            NOT NULL DEFAULT 1,

    CONSTRAINT fk_product_user
        FOREIGN KEY (user_id)
            REFERENCES users (id)
            ON DELETE CASCADE,

    CONSTRAINT fk_product_buyer
        FOREIGN KEY (buyer_id)
            REFERENCES buyer (id)
            ON DELETE SET NULL,

    CONSTRAINT chk_product_price_not_negative
        CHECK (price >= 0),

    CONSTRAINT chk_product_quantity_not_negative
        CHECK (quantity >= 0),

    CONSTRAINT chk_product_status
        CHECK (status IN ('ACTIVE', 'SOLD', 'BLOCKED', 'DELETED'))
);