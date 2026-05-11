package com.market.helper.objectmodifier.impl;

import com.market.helper.objectmodifier.ProductObjectModifier;
import com.market.model.Product;
import org.springframework.stereotype.Component;

@Component
public class ProductObjectModifierImpl implements ProductObjectModifier {

    @Override
    public Product applyMinusQuantity(Product product,
                                      Integer quantity) {
        product.setQuantity(product.getQuantity() - quantity);
        return product;
    }
}
