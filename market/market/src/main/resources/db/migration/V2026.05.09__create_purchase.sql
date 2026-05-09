CREATE TABLE purchase
(
    id         BIGSERIAL PRIMARY KEY,

    product_id BIGINT         NOT NULL,
    user_id    BIGINT         NOT NULL,

    price      NUMERIC(19, 2) NOT NULL,
    status     VARCHAR(30)    NOT NULL DEFAULT 'NEW',

    created_at TIMESTAMP      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP      NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_purchase_product
        FOREIGN KEY (product_id)
            REFERENCES product (id)
            ON DELETE RESTRICT,

    CONSTRAINT fk_purchase_user
        FOREIGN KEY (user_id)
            REFERENCES users (id)
            ON DELETE RESTRICT,

    CONSTRAINT chk_purchase_price_not_negative
        CHECK (price >= 0),

    CONSTRAINT chk_purchase_status
        CHECK (status IN ('NEW', 'SUCCESS', 'CANCELED'))
);