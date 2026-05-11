CREATE OR REPLACE FUNCTION product_update_func() RETURNS TRIGGER AS
$$
BEGIN
    IF NEW.quantity <= 0 THEN
        NEW.status = 'SOLD';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE TRIGGER product_save_trigger
    BEFORE UPDATE OF quantity
    ON product
    FOR EACH ROW
EXECUTE PROCEDURE product_update_func();