package com.market.helper.other;


import com.market.dto.response.common.PagingContent;
import org.springframework.data.domain.Page;

public class PagingContentWrapper {

    private PagingContentWrapper() {
    }

    public static <T> PagingContent<T> wrapPagingContent(Page<T> content) {
        return PagingContent.<T>builder()
                .content(content.getContent())
                .page(content.getNumber())
                .size(content.getSize())
                .totalPages(content.getTotalPages())
                .totalElements(content.getTotalElements())
                .hasNextPage(content.hasNext())
                .hasPreviousPage(content.hasPrevious())
                .build();
    }
}
