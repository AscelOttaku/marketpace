CREATE TABLE catalog
(
    id         BIGSERIAL PRIMARY KEY,
    name       VARCHAR(100) NOT NULL,
    created_at TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT uq_catalog_name UNIQUE (name),

    CONSTRAINT chk_catalog_name
        CHECK (name IN (
                        'ELECTRONICS',
                        'CLOTHES',
                        'FOOD',
                        'BOOKS',
                        'BEAUTY',
                        'SPORT',
                        'HOME',
                        'TOYS',
                        'AUTO',
                        'OTHER'
            ))
);

CREATE INDEX idx_catalog_name
    ON catalog (name);

INSERT INTO catalog (name)
VALUES ('OTHER')
ON CONFLICT (name) DO NOTHING;

ALTER TABLE product
    ADD COLUMN catalog_id BIGINT;

UPDATE product
SET catalog_id = (SELECT id FROM catalog WHERE name = 'OTHER')
WHERE catalog_id IS NULL;

ALTER TABLE product
    ALTER COLUMN catalog_id SET NOT NULL;

ALTER TABLE product
    ADD CONSTRAINT fk_product_catalog
        FOREIGN KEY (catalog_id)
            REFERENCES catalog (id)
            ON DELETE RESTRICT;

CREATE INDEX idx_product_catalog_id
    ON product (catalog_id);