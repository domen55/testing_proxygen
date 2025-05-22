/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include "SampleHandlers.h"
#include <folly/Expected.h>
#include <proxygen/httpserver/RequestHandler.h>
#include <proxygen/httpserver/ResponseBuilder.h>

namespace proxygen
{
    class ResponseHandler;
}

using quic::samples::HandlerParams;
namespace websockethandler
{

    /*
     * Websocket stream parser.
     */
    class WebSocketStream
    {
    public:
        enum class WebSocketStreamError
        {
        };
        folly::Expected<std::unique_ptr<folly::IOBuf>, WebSocketStreamError> onData(
            std::unique_ptr<folly::IOBuf> chain);
    };

    /*
     * Websocket acceptor.
     */
    class WebSocketHandler : public quic::samples::BaseSampleHandler
    {
    public:
        explicit WebSocketHandler(const HandlerParams &params, folly::EventBase *evb)
            : BaseSampleHandler(params), evb_(evb)
        {
        }
        //   void onRequest(
        //       std::unique_ptr<proxygen::HTTPMessage> request) noexcept override;

        void onBody(std::unique_ptr<folly::IOBuf> body) noexcept override;

        void onEOM() noexcept override;

        void onUpgrade(proxygen::UpgradeProtocol proto) noexcept override;

        // void requestComplete() noexcept override;
        void onHeadersComplete(std::unique_ptr<proxygen::HTTPMessage> msg) noexcept override;

        void onError(const proxygen::HTTPException &error) noexcept override;

        void onEgressPaused() noexcept override;

        void onEgressResumed() noexcept override;

    private:
        std::unique_ptr<WebSocketStream> wsStream_;
        folly::EventBase* evb_;
    };

} // namespace websockethandler
