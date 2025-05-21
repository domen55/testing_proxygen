/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <proxygen/httpserver/HTTPTransactionHandlerAdaptor.h>
#include "FizzContext.h"
#include "H2Server.h"

#include <folly/experimental/io/IoUringEventBaseLocal.h>
#include <folly/system/HardwareConcurrency.h>
#include <algorithm>

std::shared_ptr<folly::IOThreadPoolExecutorBase> getDefaultIOUringExecutor(bool enableThreadIdCollection);
namespace quic::samples {

using namespace proxygen;

H2Server::SampleHandlerFactory::SampleHandlerFactory(
    HTTPTransactionHandlerProvider httpTransactionHandlerProvider)
    : httpTransactionHandlerProvider_(
          std::move(httpTransactionHandlerProvider)) {
}

void H2Server::SampleHandlerFactory::onServerStart(
    folly::EventBase* /*evb*/) noexcept {
}

void H2Server::SampleHandlerFactory::onServerStop() noexcept {
}

RequestHandler* H2Server::SampleHandlerFactory::onRequest(
    RequestHandler*, HTTPMessage* msg) noexcept {
  return new HTTPTransactionHandlerAdaptor(
      httpTransactionHandlerProvider_(msg));
}

std::unique_ptr<proxygen::HTTPServerOptions> H2Server::createServerOptions(
    const HQToolServerParams& params,
    HTTPTransactionHandlerProvider httpTransactionHandlerProvider) {
  auto serverOptions = std::make_unique<proxygen::HTTPServerOptions>();

  serverOptions->threads = params.httpServerThreads;
  serverOptions->idleTimeout = params.httpServerIdleTimeout;
  serverOptions->shutdownOn = params.httpServerShutdownOn;
  serverOptions->enableContentCompression =
      params.httpServerEnableContentCompression;
  serverOptions->initialReceiveWindow =
      params.transportSettings
          .advertisedInitialBidiLocalStreamFlowControlWindow;
  serverOptions->receiveStreamWindowSize =
      params.transportSettings
          .advertisedInitialBidiLocalStreamFlowControlWindow;
  serverOptions->receiveSessionWindowSize =
      params.transportSettings.advertisedInitialConnectionFlowControlWindow;
  serverOptions->handlerFactories =
      proxygen::RequestHandlerChain()
          .addThen<SampleHandlerFactory>(
              std::move(httpTransactionHandlerProvider))
          .build();
  return serverOptions;
}

std::unique_ptr<H2Server::AcceptorConfig> H2Server::createServerAcceptorConfig(
    const HQToolServerParams& params) {
  auto acceptorConfig = std::make_unique<AcceptorConfig>();
  proxygen::HTTPServer::IPConfig ipConfig(
      params.localH2Address.value(), proxygen::HTTPServer::Protocol::HTTP2);
  ipConfig.sslConfigs.emplace_back(createSSLContext(params));
  acceptorConfig->push_back(ipConfig);
  return acceptorConfig;
}

std::thread H2Server::run(
    const HQToolServerParams& params,
    HTTPTransactionHandlerProvider httpTransactionHandlerProvider) {
    //auto executor = getDefaultIOUringExecutor(true);
    //auto *evbm = folly::EventBaseManager::get();
    //auto *ev_backend = evbm->getEventBase()->getBackend();
    // use the same EventBase for the main thread


    // Start HTTPServer mainloop in a separate thread
    //, executor = std::move(executor)
    std::thread t([params = folly::copy(params),
                   httpTransactionHandlerProvider =
                       std::move(httpTransactionHandlerProvider)
                       //,executor, evbm
                       ]() mutable
                  {
    {
        // auto *evbm1 = folly::EventBaseManager::get();
        // auto *ev_base = evbm1->getEventBase();
        // auto *ev_backend = ev_base->getBackend();
        // assert(evbm==evbm1);
   
        auto acceptorConfig = createServerAcceptorConfig(params);
      auto serverOptions = createServerOptions(
          params, std::move(httpTransactionHandlerProvider));
      proxygen::HTTPServer server(std::move(*serverOptions));
      server.bind(std::move(*acceptorConfig));
      server.start(nullptr, nullptr, nullptr, nullptr);//executor
    }
    // HTTPServer traps the SIGINT.  resignal HQServer
    raise(SIGINT); });

    return t;
}

} // namespace quic::samples
