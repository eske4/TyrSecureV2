#pragma once

#include <array>
#include <bpf/libbpf.h>
#include <memory>

#include "EPollBinding.hpp"
#include "IEbpfModule.hpp"
#include "master.skel.h"
#include "system/FD.hpp"

namespace OdinSight::Daemon::Monitor::Kernel {

class EbpfManager {
private:
  /** --- Private Type Aliases (Zero External Exposure) --- **/
  using FD           = OdinSight::System::FD;
  using EPollBinding = OdinSight::System::EPollBinding;
  using EPollManager = OdinSight::System::EPollManager;

  using ModuleArray =
      std::array<std::unique_ptr<IEbpfModule>, static_cast<size_t>(EbpfModuleId::MODULE_COUNT)>;

  // Aliasing the complex BPF types to keep the member list readable
  using RingBufferPtr = std::unique_ptr<struct ring_buffer, decltype(&ring_buffer__free)>;
  using MasterSkelPtr = std::unique_ptr<struct master, decltype(&master__destroy)>;

  /** --- Members --- **/
  ModuleArray   m_modules;
  RingBufferPtr m_ringbuf_reader{nullptr, ring_buffer__free};
  MasterSkelPtr m_master_skel{nullptr, master__destroy};

  FD              m_shared_rb_fd;
  struct bpf_map *m_shared_rb_map = nullptr;

  std::unique_ptr<EPollBinding> m_binding;
  bool                          m_isActive = false;

  static int handleEvent(void *ctx, void *data, size_t data_sz);

public:
  EbpfManager();
  ~EbpfManager() = default;

  // Rule of Five
  EbpfManager(const EbpfManager &)                = delete;
  EbpfManager &operator=(const EbpfManager &)     = delete;
  EbpfManager(EbpfManager &&) noexcept            = default;
  EbpfManager &operator=(EbpfManager &&) noexcept = default;

  /** --- Public API --- **/
  [[nodiscard]] bool start();
  [[nodiscard]] bool addModule(std::unique_ptr<IEbpfModule> mod);
  [[nodiscard]] bool removeModule(EbpfModuleId mod_id);

  // Note: Using the internal alias for the parameter
  [[nodiscard]] bool createEPollBinding(EPollManager *manager);
};

} // namespace OdinSight::Daemon::Monitor::Kernel
