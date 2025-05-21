#include <sys/eventfd.h>
#include <numeric>

#include <folly/FileUtil.h>
#include <folly/Function.h>
#include <folly/String.h>
#include <folly/io/async/EventHandler.h>
#include <folly/io/async/IoUringBackend.h>
#include <algorithm>

#include "SampleHandlers.h"

namespace
{
    class AlignedBuf
    {
    public:
        static constexpr size_t kAlign = 4096;
        AlignedBuf() = delete;

        AlignedBuf(size_t count, char ch) : size_(count)
        {
            ::posix_memalign(&data_, kAlign, size_);
            // CHECK(!!data_);
            //::memset(data_, ch, count);
        }

        AlignedBuf(const AlignedBuf &buf) : size_(buf.size_)
        {
            if (size_)
            {
                ::posix_memalign(&data_, kAlign, size_);
                CHECK(!!data_);
                ::memcpy(data_, buf.data_, size_);
            }
        }

        ~AlignedBuf()
        {
            if (data_)
            {
                ::free(data_);
            }
        }

        AlignedBuf &operator=(const AlignedBuf &buf)
        {
            if (data_)
            {
                ::free(data_);
            }

            size_ = buf.size_;
            if (size_)
            {
                ::posix_memalign(&data_, kAlign, size_);
                CHECK(!!data_);
                ::memcpy(data_, buf.data_, size_);
            }

            return *this;
        }

        bool operator==(const AlignedBuf &buf) const
        {
            if (size_ != buf.size_)
            {
                return false;
            }

            if (size_ == 0)
            {
                return true;
            }

            return (0 == ::memcmp(data_, buf.data_, size_));
        }

        bool operator!=(const AlignedBuf &buf) const { return !(*this == buf); }

        void *data() const { return data_; }

        size_t size() const { return size_; }

    private:
        void *data_{nullptr};
        size_t size_{0};
    };
}

static std::string formatTimestamp(time_t time)
{
  tm tm;
#ifdef _WIN32
  gmtime_s(&tm, &time);
#else
  gmtime_r(&time, &tm);
#endif
  char buf[32];
  strftime(buf, sizeof(buf), "%a, %d %b %Y %H:%M:%S GMT", &tm);
  return buf;
}

namespace quic::samples
{
    class StaticFileUringHandler : public BaseSampleHandler
    {
        static constexpr size_t kNumBlocks = 32;
        static constexpr size_t kBlockSize = 4096;

    public:
        StaticFileUringHandler(const HandlerParams &params, std::string staticRoot)
            : BaseSampleHandler(params), staticRoot_(std::move(staticRoot))
        {
        }

        void read_callback(off_t at, int idx, int res)
        {
            //VLOG(1) << "read_callback res:" << res << " at:" << at << " offset:" << offset_ << " beg:" << idx;
            if (res < 0)
            {
                txn_->sendAbort();
                return;
            }
            //buf.postallocate(res);
            readVec[idx]->append(res);
            txn_->sendBody(std::move(readVec[idx]));
            assert(offset_ == at);//should be equal, if not there is reorder
            offset_ += res;
            if (res != kBlockSize)
            {
                txn_->sendEOM();
            }
            else
            {
                if (--req_send <= 0)
                {
                    queue_read();
                }
            }
        }

        void queue_read()
        {
            if (paused_)
            {
                return;
            }
            uint64_t blocks_count = std::min(((stat.st_size - req_offset_) / kBlockSize) + 1, kNumBlocks);
            //auto data = buf.preallocate(kBlockSize * blocks_count, kBlockSize * blocks_count);
            uint64_t add_idx{0};
            for (size_t idx = 0; idx < blocks_count; idx++)
            {
                folly::IoUringBackend::FileOpCallback readCb = std::bind(&StaticFileUringHandler::read_callback, this, req_offset_, idx, std::placeholders::_1);
                readVec[idx] = folly::IOBuf::create(kBlockSize);
                backendPtr->queueRead(
                    file_->fd(), readVec[idx]->writableData(), kBlockSize, req_offset_, std::move(readCb));
                req_offset_ += kBlockSize;
                add_idx += kBlockSize;
                ++req_send;
            }
            //VLOG(1) << "queue_read";
        }

        void
        onHeadersComplete(std::unique_ptr<proxygen::HTTPMessage> msg) noexcept override
        {
            auto path = msg->getPathAsStringPiece();
            VLOG(10) << "StaticFileUringHandler::onHeadersComplete";
            VLOG(4) << "Request path: " << path;
            if (path.contains(".."))
            {
                sendError("Path cannot contain ..");
                return;
            }
            std::string safepath{};
            auto filepath = folly::to<std::string>(staticRoot_, "/", path);
            try
            {
                safepath = proxygen::SafePath::getPath(filepath, staticRoot_, true);
                file_ = std::make_unique<folly::File>(safepath, O_RDONLY | O_CLOEXEC); // O_DIRECT |
            }
            catch (...)
            {
                auto errorMsg = folly::to<std::string>(
                    "Invalid URL: cannot open requested file. "
                    "path: '",
                    path,
                    "'");
                LOG(ERROR) << errorMsg << " file: '" << filepath << "'";
                sendError(errorMsg);
                return;
            }
            auto *evbPtr = folly::EventBaseManager::get()->getEventBase();
            backendPtr = dynamic_cast<folly::IoUringBackend *>(evbPtr->getBackend());
            if (!backendPtr)
            {
                auto errorMsg = folly::to<std::string>(
                    "FailureInvalid URL: cannot open requested file. "
                    "path: '",
                    path,
                    "'");
                LOG(ERROR) << errorMsg << " file: '" << filepath << "'";
                sendError(errorMsg);
                return;
            }
            if (fstat(file_->fd(), &stat) == -1)
            {
                auto errorMsg = folly::to<std::string>(
                    "FailureInvalid URL: cannot open requested file. "
                    "path: '",
                    path,
                    "'");
                LOG(ERROR) << errorMsg << " file: '" << filepath << "'";
                sendError(errorMsg);
                return;
            }

            proxygen::HTTPMessage resp = createHttpResponse(200, "Ok");
            maybeAddAltSvcHeader(resp);
            auto& headers{resp.getHeaders()};
            headers.add(proxygen::HTTP_HEADER_CONTENT_LENGTH, std::to_string(stat.st_size));
            headers.add(proxygen::HTTP_HEADER_ETAG,  folly::sformat("\"{}-{:x}\"", stat.st_size, (long long)stat.st_mtime));
            headers.add(proxygen::HTTP_HEADER_LAST_MODIFIED, formatTimestamp(stat.st_mtime));
            headers.add(proxygen::HTTP_HEADER_ACCEPT_RANGES, "bytes");
            
            
           ;
            txn_->sendHeaders(resp);
            queue_read();
            // albuf = std::make_unique<AlignedBuf>()
            // int fd = folly::fileops::open(tempFile.path().c_str(), O_DIRECT | O_RDWR);
            // fd_ = folly::fileops::open(tempFile.path().c_str(), O_DIRECT | O_RDONLY | O_CLOEXEC);

            // proxygen::HTTPMessage resp = createHttpResponse(200, "Ok");
            // maybeAddAltSvcHeader(resp);
            // txn_->sendHeaders(resp);
            // use a CPU executor since read(2) of a file can block
            // folly::getUnsafeMutableGlobalCPUExecutor()->add(
            //     std::bind(&StaticFileUringHandler::readFile,
            //               this,
            //               folly::EventBaseManager::get()->getEventBase()));
        }

        void onBody(std::unique_ptr<folly::IOBuf> /*chain*/) noexcept override
        {
        }

        void onEOM() noexcept override
        {
        }

        void onError(const proxygen::HTTPException & /*error*/) noexcept override
        {
            VLOG(10) << "StaticFileUringHandler::onError";
            txn_->sendAbort();
        }

        void onEgressPaused() noexcept override
        {
            VLOG(10) << "StaticFileUringHandler::onEgressPaused";
            paused_ = true;
        }

        void onEgressResumed() noexcept override
        {
            VLOG(10) << "StaticFileUringHandler::onEgressResumed";
            if (paused_)
            {
                paused_ = false;
                queue_read();
            }
            // folly::getUnsafeMutableGlobalCPUExecutor()->add(
            //     std::bind(&StaticFileUringHandler::readFile,
            //               this,
            //               folly::EventBaseManager::get()->getEventBase()));
        }

    private:
#if 0
        void readFile(folly::EventBase *evb)
        {
            folly::IOBufQueue buf;
            while (file_ && !paused_)
            {
                // read 4k-ish chunks and foward each one to the client
                auto data = buf.preallocate(4096, 4096);
                auto rc = folly::readNoInt(file_->fd(), data.first, data.second);
                if (rc < 0)
                {
                    // error
                    VLOG(4) << "Read error=" << rc;
                    file_.reset();
                    evb->runInEventBaseThread([this]
                                              {
             LOG(ERROR) << "Error reading file";
             txn_->sendAbort(); });
                    break;
                }
                else if (rc == 0)
                {
                    // done
                    file_.reset();
                    VLOG(4) << "Read EOF";
                    evb->runInEventBaseThread([this]
                                              {
              txn_->sendEOM(); 
              VLOG(1) << "I am here123"; });
                    break;
                }
                else
                {
                    VLOG(1) << "Sending to runin:" << rc;
                    buf.postallocate(rc);
                    evb->runInEventBaseThread([this, body = buf.move()]() mutable
                                              {
             VLOG(1) << "I am here size:" << body->length();
             txn_->sendBody(std::move(body)); });
                }
            }
        }
#endif

        void sendError(const std::string &errorMsg)
        {
            proxygen::HTTPMessage resp = createHttpResponse(400, "Bad Request");
            resp.setWantsKeepalive(true);
            maybeAddAltSvcHeader(resp);
            txn_->sendHeaders(resp);
            txn_->sendBody(folly::IOBuf::copyBuffer(errorMsg));
            txn_->sendEOM();
        }

        // std::unique_ptr<AlignedBuf> albuf;
        struct stat stat{};
        std::array<std::unique_ptr<folly::IOBuf>,kNumBlocks> readVec{};
        std::unique_ptr<folly::File> file_;
        std::atomic<bool> paused_{false};
        std::string staticRoot_;
        folly::IoUringBackend *backendPtr{nullptr};
        int req_send {0};
        off_t offset_{0};
        off_t req_offset_{0};
        //folly::IOBufQueue buf;
    };

}