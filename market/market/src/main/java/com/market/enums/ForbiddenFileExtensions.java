package com.market.enums;

import lombok.Getter;

@Getter
public enum ForbiddenFileExtensions {
    VIDEO("video/"), AUDIO("audio/");

    private final String extension;

    ForbiddenFileExtensions(String extension) {
        this.extension = extension;
    }
}
