#include "EnvironmentValidator.hpp"
#include "system/FD.hpp"
#include "utils/FDUtil.hpp"
#include <array>
#include <cerrno>
#include <cstdint>
#include <filesystem>
#include <iostream>
#include <sstream>
#include <string>
#include <unordered_set>
#include <vector>

namespace fs = std::filesystem;

namespace OdinSight::System::Environment {

constexpr char errorCtx[] = "EnvironmentValidator";

Result<void> Validator::isSecureBootEnabled() {
  constexpr std::size_t secureBootVarSize      = 5;
  constexpr uint8_t     secureBootEnabledValue = 1;
  const std::string     dirPath                = "/sys/firmware/efi/efivars/";
  std::string           secureBootFileName;

  if (!fs::exists(dirPath) || !fs::is_directory(dirPath)) {
    return std::unexpected(Odin::Error::Logic(errorCtx, "check secure boot",
                                              "EFI variables directory is unavailable"));
  }

  for (const auto& entry : fs::directory_iterator(dirPath)) {
    const auto& filename = entry.path().filename().string();

    if (filename.rfind("SecureBoot-", 0) == 0) {
      secureBootFileName = filename;
      break;
    }
  }

  if (secureBootFileName.empty()) {
    return std::unexpected(
        Odin::Error::Logic(errorCtx, "check secure boot", "SecureBoot EFI variable is missing"));
  }

  FD dirFd(dirPath, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
  if (!dirFd) {
    return std::unexpected(Odin::Error::System(errorCtx, "open EFI variables directory", errno));
  }

  FD secureBootFd(dirFd, secureBootFileName, O_RDONLY);
  if (!secureBootFd) {
    return std::unexpected(Odin::Error::System(errorCtx, "open SecureBoot EFI variable", errno));
  }

  std::array<uint8_t, secureBootVarSize> data{};
  const ssize_t bytesRead = ::read(secureBootFd.get(), data.data(), data.size());
  if (bytesRead < 0) {
    return std::unexpected(Odin::Error::System(errorCtx, "read SecureBoot EFI variable", errno));
  }

  if (static_cast<std::size_t>(bytesRead) != data.size()) {
    return std::unexpected(Odin::Error::Logic(errorCtx, "read SecureBoot EFI variable",
                                              "SecureBoot EFI variable has an unexpected format"));
  }

  if (data.back() != secureBootEnabledValue) {
    return std::unexpected(
        Odin::Error::Logic(errorCtx, "check secure boot", "Secure Boot is disabled"));
  }

  return {};
}

Result<void> Validator::isKernelLockdownEnabled() {
  std::filesystem::path lockdownFilePath = "/sys/module/module/parameters/sig_enforce";

    Odin::Result<FD> lockdownFd = OdinSight::Util::FD::openFile(lockdownFilePath);

  if (!lockdownFd) {
    return std::unexpected(Odin::Error::System(errorCtx, "open kernel lockdown state", errno));
  }
  std::array<char, 256> buffer{};
  const ssize_t         bytesRead = ::read(lockdownFd->get(), buffer.data(), buffer.size() - 1);

  if (bytesRead <= 0) {
    return std::unexpected(Odin::Error::System(errorCtx, "read kernel lockdown state", errno));
  }

  buffer[bytesRead] = '\0';
  const std::string lockdownStatus(buffer.data());

  bool lockdownEnabled = lockdownStatus.find("[confidentiality]") != std::string::npos;

  if (!lockdownEnabled) {
    return std::unexpected(Odin::Error::Logic(
        errorCtx, "check kernel lockdown", "Kernel lockdown confidentiality mode is not enabled"));
  }

  return {};
}

Result<void> Validator::isKernelModuleSignatureEnforcementEnabled() {
  //[[nodiscard]] inline Odin::Result<System::FD> openFile(std::filesystem::path path) {
  std::filesystem::path sigEnforceFilePath = "/sys/module/module/parameters/sig_enforce";

  Odin::Result<FD> sigFileFD = OdinSight::Util::FD::openFile(sigEnforceFilePath);

  if (!sigFileFD) {
    return std::unexpected(
        Odin::Error::System(errorCtx, "open module signature enforcement state", errno));
  }

  std::array<char, 256> buffer{};
  const ssize_t         bytesRead = ::read(sigFileFD->get(), buffer.data(), buffer.size() - 1);

  if (bytesRead <= 0) {
    return std::unexpected(
        Odin::Error::System(errorCtx, "read module signature enforcement state", errno));
  }

  buffer[bytesRead] = '\0';

  std::string sigEnforce(buffer.data());
  while (!sigEnforce.empty() && (sigEnforce.back() == '\n' || sigEnforce.back() == '\r')) {
    sigEnforce.pop_back();
  }

  bool kernelModuleSignatureEnforcementEnabled =
      sigEnforce == "1" || sigEnforce == "Y" || sigEnforce == "y";

  if (!kernelModuleSignatureEnforcementEnabled) {
    return std::unexpected(Odin::Error::Logic(errorCtx, "check module signature enforcement",
                                              "Kernel module signature enforcement is disabled"));
  }

  return {};
}

Result<void> Validator::isValid() {
  Result<void> secureBootEnabled = isSecureBootEnabled();
  Result<void> kLockdownEnabled  = isKernelLockdownEnabled();
  Result<void> kernelModuleSignatureEnforcementEnabled =
      isKernelModuleSignatureEnforcementEnabled();
  Result<void> unsignedKernelModuleLoadProbeResult = canLoadUnsignedKernelModules();

  if (!secureBootEnabled) { std::cout << "Invalid: Secure Boot - Disabled" << std::endl; }

  if (!kLockdownEnabled) { std::cout << "Invalid: Kernel lockdown - Disabled" << std::endl; }

  if (!kernelModuleSignatureEnforcementEnabled) {
    std::cout << "Invalid: Kernel module signature enforcement - Disabled" << std::endl;
  }

  if (unsignedKernelModuleLoadProbeResult) {
    std::cout << "Invalid: Unsigned kernel module was loaded in" << std::endl;
  } else {
    std::cout << unsignedKernelModuleLoadProbeResult.error().message() << std::endl;
  }

  if (!(secureBootEnabled && kLockdownEnabled && kernelModuleSignatureEnforcementEnabled &&
        unsignedKernelModuleLoadProbeResult)) {
    return std::unexpected(Odin::Error::Logic(errorCtx, "Environment Validation", "Failed"));
  }

  return {};
}
} // namespace OdinSight::System::Environment
