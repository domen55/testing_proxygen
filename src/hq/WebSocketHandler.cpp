/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include "WebSocketHandler.h"

#include <folly/io/async/EventBaseManager.h>
#include <folly/io/IOBuf.h>

#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/split.hpp>
#include <proxygen/lib/utils/Logging.h>
#include <string>

using namespace proxygen;

namespace websockethandler {

const std::string kWSKeyHeader = "Sec-WebSocket-Key";
const std::string kWSProtocolHeader = "Sec-WebSocket-Protocol";
const std::string kWSExtensionsHeader = "Sec-WebSocket-Extensions";
const std::string kWSAcceptHeader = "Sec-WebSocket-Accept";
const std::string kWSVersionHeader = "Sec-WebSocket-Version";

const std::string kWSVersion = "13";
const std::string kUpgradeTo = "Websocket";

// void WebSocketHandler::onRequest(
//     std::unique_ptr<HTTPMessage> request) noexcept {

//   VLOG(4) << " New incoming request" << *request;

//   // Check if Upgrade and Connection headers are present.
//   if (!request->getHeaders().exists(HTTP_HEADER_UPGRADE) ||
//       !request->getHeaders().exists(HTTP_HEADER_CONNECTION)) {
//     LOG(ERROR) << " Missing Upgrade/Connection header";
//     ResponseBuilder(downstream_).rejectUpgradeRequest();
//     return;
//   }

//   // Make sure we are requesting an upgrade to websocket.
//   const std::string& proto =
//       request->getHeaders().getSingleOrEmpty(HTTP_HEADER_UPGRADE);
//   if (!caseInsensitiveEqual(proto, kUpgradeTo)) {
//     LOG(ERROR) << "Provided upgrade protocol: '" << proto << "', expected: '"
//                << kUpgradeTo << "'";
//     ResponseBuilder(downstream_).rejectUpgradeRequest();
//     return;
//   }

//   // Build the upgrade response.
//   ResponseBuilder response(downstream_);
//   response.status(101, "Switching Protocols")
//       .setEgressWebsocketHeaders()
//       .header(kWSVersionHeader, kWSVersion)
//       .header(kWSProtocolHeader, "websocketExampleProto")
//       .send();
// }

void WebSocketHandler::onHeadersComplete(
    std::unique_ptr<proxygen::HTTPMessage> msg) noexcept
{
}

void WebSocketHandler::onEgressPaused() noexcept
{
  VLOG(4) << "WebSocketHandler egress paused";
}

void WebSocketHandler::onEgressResumed() noexcept {
  VLOG(4) << "WebSocketHandler resumed";
}

void WebSocketHandler::onBody(std::unique_ptr<folly::IOBuf> body) noexcept {
  VLOG(4) << "WebsocketHandler::onBody";
  auto res = wsStream_->onData(std::move(body));
  if (res.hasError()) {
    //ResponseBuilder response(downstream_);
    //response.status(400, "Bad Request");
    //response.sendWithEOM();
    //sendErrorResponse("Bad Request");
    proxygen::HTTPMessage resp = createHttpResponse(400, "ERROR");
    resp.setWantsKeepalive(false);
    txn_->sendHeaders(resp);
    txn_->sendBody(folly::IOBuf::copyBuffer("ERROR"));
    txn_->sendEOM();
  } else {
    //ResponseBuilder(downstream_).body(std::move(*res)).send();
  }
}

void WebSocketHandler::onEOM() noexcept {
  //ResponseBuilder(downstream_).sendWithEOM();
  VLOG(10) << "WebSocketHandler::" << __func__ << " - ignoring";
}

void WebSocketHandler::onUpgrade(UpgradeProtocol /*protocol*/) noexcept {
  VLOG(4) << "WebSocketHandler onUpgrade";
  wsStream_ = std::make_unique<WebSocketStream>();
}

// void WebSocketHandler::requestComplete() noexcept {
//   VLOG(4) << " WebSocketHandler::requestComplete";
//   delete this;
// }

void WebSocketHandler::onError(const proxygen::HTTPException& err) noexcept {
  VLOG(4) << " WebSocketHandler::onError: " << err;
  //delete this;
  txn_->sendAbort();
}

folly::Expected<std::unique_ptr<folly::IOBuf>,
                WebSocketStream::WebSocketStreamError>
WebSocketStream::onData(std::unique_ptr<folly::IOBuf> chain) {
  // Parse websocket framing here etc.
  VLOG(4) << "WebSocketStream::onData: " << chain->clone()->moveToFbString();
  // We just echo the bytes back.
  return std::move(chain);
}

} // namespace websockethandler
