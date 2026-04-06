#pragma once

#include "common/Result.hpp"

namespace OdinSight::System::Environment {

template <typename T> using Result = Odin::Result<T>;

class Validator {
private:
  /**
   * Checks whether UEFI Secure Boot is enabled.
   * Reads the SecureBoot EFI variable from /sys/firmware/efi/efivars/ and verifies
   * that the EFI payload byte indicates Secure Boot is enabled.
   * @return success when Secure Boot is enabled, otherwise a structured error.
   */
  [[nodiscard]] static Result<void> isSecureBootEnabled();

  /**
   * Checks whether kernel lockdown is enabled in confidentiality mode.
   * Reads /sys/kernel/security/lockdown and looks for the active mode.
   * This implementation specifically treats "[confidentiality]" as enabled.
   * @return true if kernel lockdown confidentiality mode is active, false otherwise.
   */
  [[nodiscard]] static Result<void> isKernelLockdownEnabled();

  /**
   * Checks whether kernel module signature enforcement is enabled.
   * Reads /sys/module/module/parameters/sig_enforce.
   * When enabled, only properly signed kernel modules may be loaded.
   * @return true if signature enforcement is enabled, false otherwise.
   */
  [[nodiscard]] static Result<void> isKernelModuleSignatureEnforcementEnabled();

  /**
   * Actively probes whether the running system can load a real unsigned module.
   * @return success when an unsigned module load succeeds, otherwise a structured error that
   *         explains why the load was denied or why the probe failed.
   */
  [[nodiscard]] static Result<void> canLoadUnsignedKernelModules();

public:
  [[nodiscard]] static Result<void> isValid();
};
} // namespace OdinSight::System::Environment
