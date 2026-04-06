#pragma once

#include "CommandListener.hpp"
#include "EPollManager.hpp"
#include "EbpfManager.hpp"
#include "Runner.hpp"
#include "common/Result.hpp"
#include "ebpf_types.h"
#include "system/CGroup.hpp"
#include "system/FD.hpp"
#include <span>

namespace OdinSight::Daemon {

class OdinEngine {
  using FD              = OdinSight::System::FD;
  using CGroup          = System::CGroup;
  using CommandListener = Control::CommandListener;
  using Runner          = Launcher::Runner;
  using EbpfManager     = Monitor::Kernel::EbpfManager;
  using IEbpfModule     = Monitor::Kernel::IEbpfModule;
  using EPollManager    = System::EPollManager;
  using EbpfModuleId    = OdinSight::Daemon::Monitor::Kernel::EbpfModuleId;

private:
  static constexpr auto MODULE_COUNT = Monitor::Kernel::EBPF_MODULES_COUNT;

  std::unique_ptr<EPollManager> m_epoll_mgr = nullptr;

  std::unique_ptr<EbpfManager>     m_ebpf_mgr = nullptr;
  std::unique_ptr<Runner>          m_runner   = nullptr;
  std::unique_ptr<CommandListener> m_listener = nullptr;

  std::shared_ptr<CGroup> m_cgroup = nullptr;

  static constexpr std::string_view ctx = "OdinEngine";

  std::vector<EbpfModuleId> m_loadedProtectionModules;
  size_t                    m_loadedCount = 0;

  OdinEngine() = default;

  [[nodiscard]] Odin::Result<void> initializeListeners();
  [[nodiscard]] Odin::Result<void> initializeManagers();

public:
  OdinEngine(OdinEngine&&)                 = default;
  OdinEngine(const OdinEngine&)            = delete;
  OdinEngine& operator=(OdinEngine&&)      = default;
  OdinEngine& operator=(const OdinEngine&) = delete;

  ~OdinEngine() = default;

  Odin::Result<void> init();
  Odin::Result<void> run();

  Odin::Result<void> switchToWaiting();
  Odin::Result<void> switchToMonitoring();

  // --- Getters for Handlers ---
  [[nodiscard]] Runner*                 getRunner() const noexcept { return m_runner.get(); }
  [[nodiscard]] EbpfManager*            getEbpf() const noexcept { return m_ebpf_mgr.get(); }
  [[nodiscard]] CommandListener*        getListener() const noexcept { return m_listener.get(); }
  [[nodiscard]] EPollManager*           getEPoll() const noexcept { return m_epoll_mgr.get(); }
  [[nodiscard]] std::shared_ptr<CGroup> getCGroup() const noexcept { return m_cgroup; }

  [[nodiscard]] std::span<const EbpfModuleId> getActiveProtections() const noexcept {
    return {m_loadedProtectionModules.data(), m_loadedProtectionModules.size()};
  }
  [[nodiscard]] Odin::Result<void> registerModule(EbpfModuleId mod_id);
  void                             clearModules() { m_loadedProtectionModules.clear(); }

  [[nodiscard]] static Odin::Result<OdinEngine> create(std::shared_ptr<CGroup> parent_cg);
};

} // namespace OdinSight::Daemon
