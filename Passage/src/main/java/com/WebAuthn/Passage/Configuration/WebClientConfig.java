package com.WebAuthn.Passage.Configuration;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.client.reactive.ClientHttpConnector;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.web.reactive.function.client.WebClient;

import reactor.netty.http.client.HttpClient;
import reactor.netty.transport.ProxyProvider;

@Configuration
public class WebClientConfig {

    @Value("${PASSAGE_APP_ID}")
    private String passageAppId;

    @Bean
    public WebClient webClientPassage() {

        // Uncomment this section and the connector below to use a proxy
        // HttpClient httpClient = HttpClient.create()
        // .proxy(proxy -> proxy.type(ProxyProvider.Proxy.HTTP)
        // .host("localhost")
        // .port(5559));
        // ClientHttpConnector httpConnector = new
        // ReactorClientHttpConnector(httpClient);

        return WebClient.builder()
                // .clientConnector(httpConnector)
                .baseUrl("https://auth.passage.id/v1/apps/" + passageAppId)
                .defaultHeaders(httpHeaders -> {
                    httpHeaders.add(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);
                })
                .build();
    }
}
