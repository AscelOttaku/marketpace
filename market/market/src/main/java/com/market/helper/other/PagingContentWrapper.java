package com.market.helper.other;


import com.market.dto.response.common.PagingContent;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class PagingContentWrapper {

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
