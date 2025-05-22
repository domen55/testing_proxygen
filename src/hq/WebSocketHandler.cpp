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

#include <folly/ssl/OpenSSLHash.h>
#include <folly/base64.h>
#include <folly/detail/base64_detail/Base64Common.h>
#include <folly/detail/base64_detail/Base64SWAR.h>
#include <folly/detail/base64_detail/Base64Scalar.h>
#include <folly/detail/base64_detail/Base64_SSE4_2.h>

#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/split.hpp>
#include <proxygen/lib/utils/Logging.h>
#include <string>

using namespace proxygen;

namespace websockethandler
{

  const std::string kWSKeyHeader = "Sec-WebSocket-Key";
  const std::string kWSProtocolHeader = "Sec-WebSocket-Protocol";
  const std::string kWSExtensionsHeader = "Sec-WebSocket-Extensions";
  const std::string kWSAcceptHeader = "Sec-WebSocket-Accept";
  const std::string kWSVersionHeader = "Sec-WebSocket-Version";

  const std::string kWSVersion = "13";
  const std::string kUpgradeTo = "Websocket";
  constexpr folly::StringPiece kWSMagicString =
      "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

  std::string static generateWebsocketAccept(const std::string &key)
  {
    folly::ssl::OpenSSLHash::Digest digest;
    digest.hash_init(EVP_sha1());
    digest.hash_update(folly::StringPiece(key));
    digest.hash_update(kWSMagicString);
    std::array<unsigned char, 20> arr;
    folly::MutableByteRange accept(arr.data(), arr.size());
    digest.hash_final(accept);
    return folly::base64Encode(
        std::string_view((char *)accept.data(), accept.size()));
  }

  // --- Frame methods ---
  void Frame::unmask_payload()
  {
    if (masked)
    {
      for (uint64_t i = 0; i < payload_data.size(); ++i)
      {
        payload_data[i] ^= masking_key[i % 4];
      }
    }
  }

  // --- Parser methods ---
  Parser::Parser() : current_state(State::WaitingForHeader), bytes_needed(0), internal_buffer_offset(0)
  {
    internal_buffer.reserve(8); // Enough for 64-bit length
    reset();                    // Initialize frame and state
  }

  void Parser::reset()
  {
    current_state = State::WaitingForHeader;
    bytes_needed = 0;
    internal_buffer.clear();
    internal_buffer_offset = 0;
    current_frame = Frame(); // Reset to default frame values
  }

  size_t Parser::parse(const uint8_t *data, size_t size, Frame &frame, size_t &bytes_consumed)
  {
    bytes_consumed = 0;
    frame = Frame(); // Clear the output frame

    while (bytes_consumed < size)
    {
      size_t current_chunk_size = size - bytes_consumed;

      switch (current_state)
      {
      case State::WaitingForHeader:
      {
        if (current_chunk_size < 2)
        {
          // Not enough data for the first two bytes (header)
          return 0; // Need more data
        }
        size_t consumed = parse_header(data + bytes_consumed, current_chunk_size);
        if (consumed == 0)
          return 0; // Not enough data for header
        bytes_consumed += consumed;
        break;
      }
      case State::WaitingForExtendedLength16:
      case State::WaitingForExtendedLength64:
      {
        size_t consumed = parse_extended_length(data + bytes_consumed, current_chunk_size);
        if (consumed == 0)
          return 0; // Not enough data for extended length
        bytes_consumed += consumed;
        break;
      }
      case State::WaitingForMaskingKey:
      {
        size_t consumed = parse_masking_key(data + bytes_consumed, current_chunk_size);
        if (consumed == 0)
          return 0; // Not enough data for masking key
        bytes_consumed += consumed;
        break;
      }
      case State::WaitingForPayload:
      {
        size_t consumed = parse_payload(data + bytes_consumed, current_chunk_size);
        if (consumed == 0)
          return 0; // Not enough data for payload
        bytes_consumed += consumed;

        // If payload is fully received, the frame is complete
        if (current_frame.payload_data.size() == current_frame.payload_length)
        {
          if (current_frame.masked)
          {
            current_frame.unmask_payload();
          }
          frame = current_frame; // Output the parsed frame
          current_state = State::FrameComplete;
          return bytes_consumed; // Indicate that a full frame was processed
        }
        break;
      }
      case State::FrameComplete:
      {
        // This state indicates a frame has just been completed.
        // The next call to parse should reset and start a new frame.
        // For now, we'll just indicate a full frame was parsed.
        return bytes_consumed;
      }
      case State::Error:
        // Handle error state appropriately
        return 0; // Indicate error
      }
    }
    return 0; // Not enough data for a full frame yet
  }

  size_t Parser::parse_header(const uint8_t *data, size_t size)
  {
    if (size < 2)
    {
      return 0; // Not enough data for the header
    }

    uint8_t byte0 = data[0];
    uint8_t byte1 = data[1];

    current_frame.fin = (byte0 >> 7) & 0x1;
    current_frame.rsv1 = (byte0 >> 6) & 0x1;
    current_frame.rsv2 = (byte0 >> 5) & 0x1;
    current_frame.rsv3 = (byte0 >> 4) & 0x1;
    current_frame.opcode = static_cast<Opcode>(byte0 & 0xF);
    current_frame.masked = (byte1 >> 7) & 0x1;
    uint8_t payload_len_7bit = byte1 & 0x7F;

    if (current_frame.rsv1 || current_frame.rsv2 || current_frame.rsv3)
    {
      // Reserved bits must be zero unless an extension is negotiated.
      // For simplicity, we'll treat this as an error.
      current_state = State::Error;
      std::cerr << "Error: RSV bits not zero." << std::endl;
      return 0;
    }

    // Validate opcode (rudimentary check, you might want more comprehensive validation)
    switch (current_frame.opcode)
    {
    case Opcode::Continuation:
    case Opcode::Text:
    case Opcode::Binary:
    case Opcode::Close:
    case Opcode::Ping:
    case Opcode::Pong:
      // Valid opcodes
      break;
    default:
      // Invalid opcode
      current_state = State::Error;
      std::cerr << "Error: Invalid opcode: " << static_cast<int>(current_frame.opcode) << std::endl;
      return 0;
    }

    // Determine payload length and next state
    if (payload_len_7bit <= 125)
    {
      current_frame.payload_length = payload_len_7bit;
      if (current_frame.masked)
      {
        current_state = State::WaitingForMaskingKey;
        bytes_needed = 4;
      }
      else
      {
        current_state = State::WaitingForPayload;
        bytes_needed = current_frame.payload_length;
      }
    }
    else if (payload_len_7bit == 126)
    {
      current_state = State::WaitingForExtendedLength16;
      bytes_needed = 2;
    }
    else
    { // payload_len_7bit == 127
      current_state = State::WaitingForExtendedLength64;
      bytes_needed = 8;
    }

    return 2; // Consumed 2 bytes for the header
  }

  size_t Parser::parse_extended_length(const uint8_t *data, size_t size)
  {
    size_t to_copy = std::min(size, bytes_needed - internal_buffer_offset);

    for (size_t i = 0; i < to_copy; ++i)
    {
      internal_buffer.push_back(data[i]);
    }
    internal_buffer_offset += to_copy;

    if (internal_buffer_offset == bytes_needed)
    {
      if (current_state == State::WaitingForExtendedLength16)
      {
        if (internal_buffer.size() < 2)
        { // Sanity check
          current_state = State::Error;
          std::cerr << "Error: Internal buffer too small for 16-bit length." << std::endl;
          return 0;
        }
        current_frame.payload_length = (static_cast<uint64_t>(internal_buffer[0]) << 8) |
                                       static_cast<uint64_t>(internal_buffer[1]);
      }
      else
      { // WaitingForExtendedLength64
        if (internal_buffer.size() < 8)
        { // Sanity check
          current_state = State::Error;
          std::cerr << "Error: Internal buffer too small for 64-bit length." << std::endl;
          return 0;
        }
        current_frame.payload_length = 0;
        for (int i = 0; i < 8; ++i)
        {
          current_frame.payload_length = (current_frame.payload_length << 8) | internal_buffer[i];
        }
      }

      // Prepare for the next stage
      internal_buffer.clear();
      internal_buffer_offset = 0;

      if (current_frame.masked)
      {
        current_state = State::WaitingForMaskingKey;
        bytes_needed = 4;
      }
      else
      {
        current_state = State::WaitingForPayload;
        bytes_needed = current_frame.payload_length;
        current_frame.payload_data.reserve(current_frame.payload_length);
      }
    }
    return to_copy;
  }

  size_t Parser::parse_masking_key(const uint8_t *data, size_t size)
  {
    size_t to_copy = std::min(size, bytes_needed - internal_buffer_offset);

    for (size_t i = 0; i < to_copy; ++i)
    {
      internal_buffer.push_back(data[i]);
    }
    internal_buffer_offset += to_copy;

    if (internal_buffer_offset == bytes_needed)
    {
      if (internal_buffer.size() < 4)
      { // Sanity check
        current_state = State::Error;
        std::cerr << "Error: Internal buffer too small for masking key." << std::endl;
        return 0;
      }
      for (int i = 0; i < 4; ++i)
      {
        current_frame.masking_key[i] = internal_buffer[i];
      }

      // Prepare for the next stage
      internal_buffer.clear();
      internal_buffer_offset = 0;

      current_state = State::WaitingForPayload;
      bytes_needed = current_frame.payload_length;
      current_frame.payload_data.reserve(current_frame.payload_length);
    }
    return to_copy;
  }

  size_t Parser::parse_payload(const uint8_t *data, size_t size)
  {
    size_t remaining_payload_bytes = current_frame.payload_length - current_frame.payload_data.size();
    size_t to_copy = std::min(size, remaining_payload_bytes);

    for (size_t i = 0; i < to_copy; ++i)
    {
      current_frame.payload_data.push_back(data[i]);
    }

    return to_copy;
  }
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
    VLOG(1) << "Headers complete";
    msg->dumpMessage(1);
    if (msg->getMethod() != proxygen::HTTPMethod::GET)
    {
      sendErrorResponse("bad request\n");
      return;
    }
    if (!msg->getHeaders().exists(HTTP_HEADER_UPGRADE) ||
        !msg->getHeaders().exists(HTTP_HEADER_CONNECTION))
    {
      LOG(ERROR) << " Missing Upgrade/Connection header";
      // ResponseBuilder(downstream_).rejectUpgradeRequest();
      sendErrorResponse("bad request\n");
      return;
    }

    // Make sure we are requesting an upgrade to websocket.
    const std::string &proto =
        msg->getHeaders().getSingleOrEmpty(HTTP_HEADER_UPGRADE);
    if (!caseInsensitiveEqual(proto, kUpgradeTo))
    {
      LOG(ERROR) << "Provided upgrade protocol: '" << proto << "', expected: '"
                 << kUpgradeTo << "'";
      // ResponseBuilder(downstream_).rejectUpgradeRequest();
      sendErrorResponse("bad request\n");
      return;
    }

    // Build the upgrade response.
    auto const &key = msg->getHeaders().getSingleOrEmpty(kWSKeyHeader);
    auto strval = websockethandler::generateWebsocketAccept(key);
    proxygen::HTTPMessage resp;
    resp.setVersionString(getHttpVersion());
    resp.setStatusCode(101);
    resp.setStatusMessage("Switching Protocols");
    resp.getHeaders().add(HTTP_HEADER_CONNECTION, "Upgrade");
    resp.getHeaders().add(HTTP_HEADER_UPGRADE, kUpgradeTo);
    resp.getHeaders().add(HTTP_HEADER_SEC_WEBSOCKET_ACCEPT, strval);

    resp.getHeaders().add(kWSVersionHeader, kWSVersion);
    resp.getHeaders().add(kWSProtocolHeader, "websocketExampleProto");
    resp.setWantsKeepalive(true);
    txn_->sendHeaders(resp);
    resp.dumpMessage(1);
    // ResponseBuilder response(downstream_);
    //  response.status(101, "Switching Protocols")
    //      .setEgressWebsocketHeaders()
    //      .header(kWSVersionHeader, kWSVersion)
    //      .header(kWSProtocolHeader, "websocketExampleProto")
    //      .send();

    txn_->setIdleTimeout(std::chrono::milliseconds(120000));
  }

  void WebSocketHandler::onEgressPaused() noexcept
  {
    VLOG(4) << "WebSocketHandler egress paused";
  }

  void WebSocketHandler::onEgressResumed() noexcept
  {
    VLOG(4) << "WebSocketHandler resumed";
  }

  void WebSocketHandler::onBody(std::unique_ptr<folly::IOBuf> body) noexcept
  {
    VLOG(1) << "WebsocketHandler::onBody";
    ioqueue_.insertAfterThisOne(std::move(body));
    ioqueue_.coalesce();
    auto ret = parser_.parse(ioqueue_.data(), ioqueue_.length(), frame_, consumed_bytes);
    switch(parser_.get_state())
    {
      case Parser::State::WaitingForHeader:
      VLOG(1) << "WaitingForHeader";
      break;
      case Parser::State::WaitingForExtendedLength16:
      VLOG(1) << "WaitingForExtendedLength16";
      break;
      case Parser::State::WaitingForExtendedLength64:
      VLOG(1) << "WaitingForExtendedLength64";
      break;
      case Parser::State::WaitingForMaskingKey:
      VLOG(1) << "WaitingForMaskingKey";
      break;
      case Parser::State::WaitingForPayload:
      VLOG(1) << "WaitingForPayload";
      break;
      case Parser::State::FrameComplete:
      VLOG(1) << "FrameComplete";
      break;
      case Parser::State::Error:
      VLOG(1) << "Error";
      break;
    }
    if (ret > 0 )//consumed_bytes < ioqueue_.length()
    {
      VLOG(1) << "ret bytes:" << ret;
      if( ret == ioqueue_.length() )
      {
        VLOG(1) << "ret bytes:" << ret << "== length:" << ioqueue_.length();
        ioqueue_.clear();
      }
      else
      {
        VLOG(1) << "ret bytes:" << ret << " length:" << ioqueue_.length();
        ioqueue_.trimStart(ret);
      }
      parser_.reset();
    }
    else
    {
    }

#if 0
    auto res = wsStream_->onData(std::move(body));
    if (res.hasError())
    {
      // ResponseBuilder response(downstream_);
      // response.status(400, "Bad Request");
      // response.sendWithEOM();
      // sendErrorResponse("Bad Request");
      proxygen::HTTPMessage resp = createHttpResponse(400, "ERROR");
      resp.setWantsKeepalive(false);
      txn_->sendHeaders(resp);
      txn_->sendBody(folly::IOBuf::copyBuffer("ERROR"));
      txn_->sendEOM();
    }
    else
    {
      // ResponseBuilder(downstream_).body(std::move(*res)).send();
    }
#endif
  }

  void WebSocketHandler::onEOM() noexcept
  {
    // ResponseBuilder(downstream_).sendWithEOM();
    VLOG(10) << "WebSocketHandler::" << __func__ << " - ignoring";
  }

  void WebSocketHandler::onUpgrade(UpgradeProtocol /*protocol*/) noexcept
  {
    VLOG(4) << "WebSocketHandler onUpgrade";
    wsStream_ = std::make_unique<WebSocketStream>();
  }

  // void WebSocketHandler::requestComplete() noexcept {
  //   VLOG(4) << " WebSocketHandler::requestComplete";
  //   delete this;
  // }

  void WebSocketHandler::onError(const proxygen::HTTPException &err) noexcept
  {
    VLOG(4) << " WebSocketHandler::onError: " << err;
    // delete this;
    txn_->sendAbort();
  }

  folly::Expected<std::unique_ptr<folly::IOBuf>,
                  WebSocketStream::WebSocketStreamError>
  WebSocketStream::onData(std::unique_ptr<folly::IOBuf> chain)
  {
    // Parse websocket framing here etc.
    VLOG(4) << "WebSocketStream::onData: " << chain->clone()->moveToFbString();
    // We just echo the bytes back.
    return std::move(chain);
  }

} // namespace websockethandler
