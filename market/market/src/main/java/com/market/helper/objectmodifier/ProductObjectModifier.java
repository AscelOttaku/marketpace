package com.market.helper.objectmodifier;

import com.market.model.Product;

public interface ProductObjectModifier {
    Product applyMinusQuantity(Product product,
                               Integer quantity);
}
