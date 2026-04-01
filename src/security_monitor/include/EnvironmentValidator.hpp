#pragma once

namespace OdinSight::System::Environment {

namespace UnsignedKernelModuleLoadProbe {

enum class Status {
  kBlockedBySignaturePolicy,
  kDeniedForOtherSecurityReason,
  kAllowed,
  kNotRoot,
  kUnsupportedPlatform,
  kKernelInfoUnavailable,
  kKernelHeadersMissing,
  kTempDirectoryCreationFailed,
  kSourceWriteFailed,
  kBuildFailed,
  kModuleOpenFailed,
  kUnexpectedLoadFailure
};

struct Result {
  bool   isBlocked;
  Status status;
};

} // namespace UnsignedKernelModuleLoadProbe

class Validator {
private:
  /**
   * Checks whether UEFI Secure Boot is enabled.
   *
   * Reads the SecureBoot EFI variable from /sys/firmware/efi/efivars/.
   *
   * @return true if Secure Boot is enabled, false otherwise.
   */
  static bool isSecureBootEnabled();

  /**
   * Checks whether kernel lockdown is enabled in confidentiality mode.
   *
   * Reads /sys/kernel/security/lockdown and looks for the active mode.
   * This implementation specifically treats "[confidentiality]" as enabled.
   *
   * @return true if kernel lockdown confidentiality mode is active, false otherwise.
   */
  static bool isKernelLockdownEnabled();

  /**
   * Checks whether kernel module signature enforcement is enabled.
   *
   * Reads /sys/module/module/parameters/sig_enforce.
   * When enabled, only properly signed kernel modules may be loaded.
   *
   * @return true if signature enforcement is enabled, false otherwise.
   */
  static bool isKernelModuleSignatureEnforcementEnabled();

  /**
   * Actively probes whether the running system blocks a real unsigned module load.
   *
   * @return the probe status and whether the kernel blocked the load attempt.
   */
  static UnsignedKernelModuleLoadProbe::Result isUnsignedKernelModuleLoadBlocked();

public:
  static bool isValid();
};
} // namespace OdinSight::System::Environment
