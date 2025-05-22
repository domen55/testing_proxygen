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

    // WebSocket Opcode values
    enum class Opcode : uint8_t {
        Continuation = 0x0,
        Text = 0x1,
        Binary = 0x2,
        Close = 0x8,
        Ping = 0x9,
        Pong = 0xA,
        // Add more if you want to explicitly represent reserved opcodes
    };

    // Represents a parsed WebSocket frame
    struct Frame
    {
        bool fin;
        uint8_t rsv1; // Reserved bits - usually 0
        uint8_t rsv2;
        uint8_t rsv3;
        Opcode opcode;
        bool masked;
        uint64_t payload_length;
        std::array<uint8_t, 4> masking_key; // Only valid if 'masked' is true
        std::vector<uint8_t> payload_data;

        // Default constructor
        Frame() : fin(false), rsv1(0), rsv2(0), rsv3(0), opcode(Opcode::Continuation),
                  masked(false), payload_length(0) {}

        // Method to unmask payload data (if masked)
        void unmask_payload();
    };

    // Parser class
    class Parser
    {
    public:
        // States for the parser's state machine
        enum class State
        {
            WaitingForHeader,
            WaitingForExtendedLength16,
            WaitingForExtendedLength64,
            WaitingForMaskingKey,
            WaitingForPayload,
            FrameComplete,
            Error
        };

        Parser();

        // Feeds raw bytes into the parser. Returns number of bytes consumed.
        // The 'frame' argument will be populated if a full frame is parsed.
        // 'bytes_consumed' indicates how many bytes from 'data' were used.
        size_t parse(const uint8_t *data, size_t size, Frame &frame, size_t &bytes_consumed);

        State get_state() const { return current_state; }
        void reset();

    private:
        State current_state;
        Frame current_frame;
        size_t bytes_needed; // How many more bytes are needed for the current state

        // Internal buffer to accumulate data for multi-byte fields (e.g., extended length, masking key)
        std::vector<uint8_t> internal_buffer;
        size_t internal_buffer_offset; // Current offset in the internal_buffer

        // Helper functions for parsing different parts of the frame
        size_t parse_header(const uint8_t *data, size_t size);
        size_t parse_extended_length(const uint8_t *data, size_t size);
        size_t parse_masking_key(const uint8_t *data, size_t size);
        size_t parse_payload(const uint8_t *data, size_t size);
    };

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

        void sendErrorResponse(const std::string &body)
        {
            proxygen::HTTPMessage resp = createHttpResponse(400, "ERROR");
            resp.setWantsKeepalive(false);
            txn_->sendHeaders(resp);
            txn_->sendBody(folly::IOBuf::copyBuffer(body));
            txn_->sendEOM();
        }

    private:
        folly::IOBuf ioqueue_{};
        std::unique_ptr<WebSocketStream> wsStream_;
        folly::EventBase *evb_;
        Parser parser_{};
        Frame frame_{};
        size_t consumed_bytes{0};
    };

} // namespace websockethandler
