/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <folly/portability/GFlags.h>

#include <folly/init/Init.h>

#include "hq/ConnIdLogger.h"
//#include <proxygen/httpserver/samples/hq/HQClient.h>
#include "hq/HQCommandLine.h"
#include "hq/HQParams.h"
#include "hq/HQServerModule.h"
#include <proxygen/lib/transport/PersistentQuicPskCache.h>
#include <folly/io/async/IoUringBackend.h>
#include <folly/io/async/EventBaseManager.h>

#include <iostream>  // For std::cout, std::cerr
#include <sys/resource.h> // For getrlimit, setrlimit, RLIMIT_NOFILE
#include <errno.h>   // For errno
#include <string.h>  // For strerror

using namespace quic::samples;

DEFINE_bool(use_iouring_event_eventfd, true, "");
DEFINE_int32(io_capacity, 0, "");
DEFINE_int32(io_submit_sqe, 0, "");
DEFINE_int32(io_max_get, 0, "");
DEFINE_bool(set_iouring_defer_taskrun, true, "");
DEFINE_int32(io_max_submit, 0, "");
DEFINE_int32(io_registers, 2048, "");
DEFINE_int32(io_prov_buffs_size, 2048, "");
DEFINE_int32(io_prov_buffs, 2000, "");
DEFINE_bool(io_zcrx, false, "");
DEFINE_int32(io_zcrx_num_pages, 16384, "");
DEFINE_int32(io_zcrx_refill_entries, 16384, "");
DEFINE_string(io_zcrx_ifname, "eth0", "");
DEFINE_int32(io_zcrx_queue_id, 0, "");

void setMaxOpenFds(rlim_t new_limit)
{
  struct rlimit rl;
  // Get current limits
  if (getrlimit(RLIMIT_NOFILE, &rl) == -1)
  {
    PLOG(ERROR) << "Failed to getrlimit"; // PLOG for errno
    return;
  }
  LOG(INFO) << "Current soft limit: " << rl.rlim_cur << ", hard limit: " << rl.rlim_max;
  rl.rlim_cur = new_limit;
  // You cannot set the soft limit higher than the hard limit unless you are root
  // So, if the new limit exceeds the hard limit, cap it at the hard limit
  if (rl.rlim_cur > rl.rlim_max)
  {
    rl.rlim_cur = rl.rlim_max;
    LOG(WARNING) << "Requested limit " << new_limit << " exceeds hard limit. Capped at " << rl.rlim_cur;
  }

  if (setrlimit(RLIMIT_NOFILE, &rl) == -1)
  {
    PLOG(ERROR) << "Failed to setrlimit"; // PLOG for errno
  }
  else
  {
    LOG(INFO) << "Successfully set soft limit to: " << rl.rlim_cur;
  }

  // Verify the new limit
  if (getrlimit(RLIMIT_NOFILE, &rl) == -1)
  {
    PLOG(ERROR) << "Failed to getrlimit after setting";
  }
  else
  {
    LOG(INFO) << "New effective soft limit: " << rl.rlim_cur;
  }
}

#if FOLLY_HAVE_WEAK_SYMBOLS
FOLLY_ATTR_WEAK int resolve_napi_callback(
    int /*ifindex*/, uint32_t /*queueId*/);
#else
static int resolve_napi_callback(int /*ifindex*/, uint32_t /*queueId*/)
{
  return -1;
}
#endif

folly::IoUringBackend::Options getIoUringOptions()
{
  folly::IoUringBackend::Options options;
  options.setRegisterRingFd(FLAGS_use_iouring_event_eventfd);

  if (FLAGS_io_prov_buffs_size > 0 && FLAGS_io_prov_buffs > 0)
  {
    options.setInitialProvidedBuffers(
        FLAGS_io_prov_buffs_size, FLAGS_io_prov_buffs);
  }

  if (FLAGS_io_registers > 0)
  {
    options.setUseRegisteredFds(static_cast<size_t>(FLAGS_io_registers));
  }

  if (FLAGS_io_capacity > 0)
  {
    options.setCapacity(static_cast<size_t>(FLAGS_io_capacity));
  }

  if (FLAGS_io_submit_sqe > 0)
  {
    options.setSqeSize(FLAGS_io_submit_sqe);
  }

  if (FLAGS_io_max_get > 0)
  {
    options.setMaxGet(static_cast<size_t>(FLAGS_io_max_get));
  }

  if (FLAGS_io_max_submit > 0)
  {
    options.setMaxSubmit(static_cast<size_t>(FLAGS_io_max_submit));
  }

  if (FLAGS_set_iouring_defer_taskrun)
  {
    if (folly::IoUringBackend::kernelSupportsDeferTaskrun())
    {
      options.setDeferTaskRun(FLAGS_set_iouring_defer_taskrun);
    }
    else
    {
      LOG(ERROR) << "not setting DeferTaskRun as not supported on this kernel";
    }
  }

  static std::atomic<int32_t> currQueueId{FLAGS_io_zcrx_queue_id};
  if (FLAGS_io_zcrx)
  {
    options.setZeroCopyRx(true)
        .setZeroCopyRxInterface(FLAGS_io_zcrx_ifname)
        .setZeroCopyRxQueue(currQueueId.fetch_add(1))
        .setZeroCopyRxNumPages(FLAGS_io_zcrx_num_pages)
        .setZeroCopyRxRefillEntries(FLAGS_io_zcrx_refill_entries)
        .setResolveNapiCallback(resolve_napi_callback);
  }

  return options;
}


std::unique_ptr<folly::EventBaseBackendBase> getEventBaseDetails()
  {
    //folly::EventBaseBackendBase ret;
    std::unique_ptr<folly::PollIoBackend> ret;
    // ret.factory = &getEventBaseBackend;
    // ret.supportsRecvmsgMultishot =
    //     folly::IoUringBackend::kernelSupportsRecvmsgMultishot();
    return ret;
  }

  std::unique_ptr<folly::EventBaseBackendBase> getEventBaseBackendFunc()
  {
#if FOLLY_HAS_LIBURING
    try
    {
      // TODO numa node affinitization
      // static int sqSharedCore = 0;
      // LOG(INFO) << "Sharing eb sq poll on core: " << sqSharedCore;
      // options.setSQGroupName("fast_eb").setSQCpu(sqSharedCore);
      return std::make_unique<folly::IoUringBackend>(getIoUringOptions());
    }
    catch (const std::exception &ex)
    {
      LOG(FATAL) << "Failed to create io_uring backend: "
                 << folly::exceptionStr(ex);
    }
#else
    LOG(FATAL) << "io_uring not supported";
#endif
  }

  int main(int argc, char *argv[])
  {
    auto startTime = std::chrono::duration_cast<std::chrono::milliseconds>(
                         std::chrono::steady_clock().now().time_since_epoch())
                         .count();
#if FOLLY_HAVE_LIBGFLAGS
  // Enable glog logging to stderr by default.
  gflags::SetCommandLineOptionWithMode(
      "logtostderr", "1", gflags::SET_FLAGS_DEFAULT);
#endif
  folly::init(&argc, &argv, false);
  int err = 0;
  setMaxOpenFds(262144);
  {
    // folly::EventBase* mainEventBase_ = EventBaseManager::get()->getEventBase();
    // //foly::EventBase::BackendFactory factory_;
    // mainEventBase_->setBackendFactory(getEventBaseDetails);
    //mainEventBase_
        // Preinitialize EventBase with custom settings on startup.
        auto* eventBase = new folly::EventBase(
            folly::EventBase::Options().setBackendFactory(
                getEventBaseBackendFunc));
        folly::EventBaseManager::get()->setEventBase(
            eventBase, true /* takeOwnership */);
      
  }

  auto expectedParams = initializeParamsFromCmdline();
  if (expectedParams) {
    auto& params = expectedParams.value();
    // TODO: move sink to params
    proxygen::ConnIdLogSink sink(params.logdir, params.logprefix);
    if (sink.isValid()) {
      AddLogSink(&sink);
    } else if (!params.logdir.empty()) {
      LOG(ERROR) << "Cannot open " << params.logdir;
    }

    switch (params.mode) {
      case HQMode::SERVER:
        startServer(boost::get<HQToolServerParams>(params.params));
        break;
      // case HQMode::CLIENT:
      //   err = startClient(boost::get<HQToolClientParams>(params.params));
      //   break;
      default:
        LOG(ERROR) << "Unknown mode specified: ";
        return -1;
    }
    if (params.logRuntime) {
      LOG(INFO) << "Run time: "
                << std::chrono::duration_cast<std::chrono::milliseconds>(
                       std::chrono::steady_clock().now().time_since_epoch())
                           .count() -
                       startTime
                << "ms";
    }
    return err;
  } else {
    for (auto& param : expectedParams.error()) {
      LOG(ERROR) << "Invalid param: " << param.name << " " << param.value << " "
                 << param.errorMsg;
    }
    return -1;
  }
}
