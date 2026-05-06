package com.market.config.common;

import lombok.extern.slf4j.Slf4j;
import okhttp3.OkHttpClient;
import org.modelmapper.ModelMapper;
import org.modelmapper.convention.MatchingStrategies;
import org.springframework.context.MessageSource;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.support.ReloadableResourceBundleMessageSource;

import java.net.Proxy;
import java.util.concurrent.TimeUnit;

@Slf4j
@Configuration
public class CommonConfig {

    @Bean
    public MessageSource messageSource() {
        var messageSource = new ReloadableResourceBundleMessageSource();
        messageSource.setBasename("classpath:messages");
        messageSource.setDefaultEncoding("UTF-8");
        return messageSource;
    }

    @Bean
    public ModelMapper modelMapper() {
        ModelMapper modelMapper = new ModelMapper();
        modelMapper.getConfiguration()
                .setMatchingStrategy(MatchingStrategies.STRICT)
                .setSkipNullEnabled(true);
        return modelMapper;
    }

    @Bean
    public OkHttpClient client() {
        return new OkHttpClient.Builder()
                .readTimeout(20, TimeUnit.SECONDS)
                .writeTimeout(20, TimeUnit.SECONDS)
                .connectTimeout(20, TimeUnit.SECONDS)
                .proxy(Proxy.NO_PROXY)
                .addInterceptor(chain -> {
                    var request = chain.request();
                    log.info("Incoming request: {}, method: {}", request.url(), request.method());

                    var requestBody = request.body();
                    if (requestBody != null) {
                        var buffer = new okio.Buffer();
                        requestBody.writeTo(buffer);
                        var body = buffer.readUtf8();
                        if (body.startsWith("{") || body.startsWith("["))
                            log.info("Request body: {}", body);
                    }

                    var response = chain.proceed(request);
                    log.info("Response: {}", response.code());
                    return response;
                })
                .build();
    }
}
