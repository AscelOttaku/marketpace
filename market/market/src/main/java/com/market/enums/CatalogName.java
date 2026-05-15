package com.market.enums;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum CatalogName {
    ELECTRONICS("Электроника"),
    CLOTHES("Одежда"),
    FOOD("Продукты питания"),
    BOOKS("Книги"),
    BEAUTY("Красота и здоровье"),
    SPORT("Спорт"),
    HOME("Дом"),
    TOYS("Игрушки"),
    AUTO("Авто"),
    OTHER("Другое");

    private final String name;
}