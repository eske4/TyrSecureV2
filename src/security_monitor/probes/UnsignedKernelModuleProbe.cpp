#include "EnvironmentValidator.hpp"
#include "system/FD.hpp"

#include <cerrno>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <string>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

namespace fs = std::filesystem;

namespace OdinSight::System::Environment {

namespace {

using ProbeStatus = UnsignedKernelModuleLoadProbe::Status;

constexpr char kProbeModuleName[] = "odinsight_unsigned_probe";

constexpr char kProbeModuleSource[] = R"(#include <linux/init.h>
#include <linux/module.h>

static int __init odinsight_unsigned_probe_init(void) {
  return 0;
}

static void __exit odinsight_unsigned_probe_exit(void) {
}

module_init(odinsight_unsigned_probe_init);
module_exit(odinsight_unsigned_probe_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("OdinSight");
MODULE_DESCRIPTION("OdinSight unsigned kernel module probe");
)";

constexpr char kProbeMakefile[] = "obj-m += odinsight_unsigned_probe.o\n";

struct ProbeExecutionResult {
  ProbeStatus status;
  int         errorCode{0};
};

struct ProbePaths {
  fs::path directory;
  fs::path sourceFile;
  fs::path makefile;
  fs::path moduleFile;
};

class ScopedDirectoryCleanup {
public:
  explicit ScopedDirectoryCleanup(fs::path path) : path_(std::move(path)) {}

  ~ScopedDirectoryCleanup() {
    if (path_.empty()) {
      return;
    }

    std::error_code ec;
    fs::remove_all(path_, ec);
    if (ec) {
      std::cerr << "Failed to clean up unsigned kernel module probe files in " << path_ << '\n';
    }
  }

  ScopedDirectoryCleanup(const ScopedDirectoryCleanup &)            = delete;
  ScopedDirectoryCleanup &operator=(const ScopedDirectoryCleanup &) = delete;

private:
  fs::path path_;
};

bool writeTextFile(const fs::path &path, const std::string &contents) {
  std::ofstream file(path);
  if (!file) {
    return false;
  }

  file << contents;
  return file.good();
}

bool runCommand(const std::vector<std::string> &args) {
  if (args.empty()) {
    return false;
  }

  const pid_t pid = ::fork();
  if (pid < 0) {
    return false;
  }

  if (pid == 0) {
    std::vector<char *> argv;
    argv.reserve(args.size() + 1);

    for (const auto &arg : args) {
      argv.push_back(const_cast<char *>(arg.c_str()));
    }
    argv.push_back(nullptr);

    ::execvp(argv[0], argv.data());
    _exit(127);
  }

  int status = 0;
  if (::waitpid(pid, &status, 0) < 0) {
    return false;
  }

  return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

std::optional<fs::path> getKernelBuildDirectory() {
  struct utsname kernelInfo{};
  if (::uname(&kernelInfo) != 0) {
    return std::nullopt;
  }

  const fs::path buildDir = fs::path("/usr/lib/modules") / kernelInfo.release / "build";
  if (!fs::is_directory(buildDir)) {
    return std::nullopt;
  }

  return buildDir;
}

std::optional<ProbePaths> createProbePaths() {
  char  directoryTemplate[] = "/tmp/odinsight-kmod-probe-XXXXXX";
  char *directoryPath       = ::mkdtemp(directoryTemplate);
  if (!directoryPath) {
    return std::nullopt;
  }

  ProbePaths paths;
  paths.directory  = directoryPath;
  paths.sourceFile = paths.directory / "odinsight_unsigned_probe.c";
  paths.makefile   = paths.directory / "Makefile";
  paths.moduleFile = paths.directory / "odinsight_unsigned_probe.ko";
  return paths;
}

bool writeProbeSources(const ProbePaths &paths) {
  return writeTextFile(paths.sourceFile, kProbeModuleSource) &&
         writeTextFile(paths.makefile, kProbeMakefile);
}

bool buildProbeModule(const fs::path &kernelBuildDir, const ProbePaths &paths) {
  return runCommand({
      "make",
      "-s",
      "-C",
      kernelBuildDir.string(),
      "M=" + paths.directory.string(),
      "modules",
  });
}

ProbeExecutionResult classifyLoadFailure(int err) {
  switch (err) {
  case EKEYREJECTED:
  case ENOKEY:
  case EBADMSG:
    return {ProbeStatus::kBlockedBySignaturePolicy, err};

  case EPERM:
  case EACCES:
    return {ProbeStatus::kDeniedForOtherSecurityReason, err};

  default:
    return {ProbeStatus::kUnexpectedLoadFailure, err};
  }
}

ProbeExecutionResult tryLoadProbeModule(const ProbePaths &paths) {
  FD moduleFd(paths.moduleFile.string(), O_RDONLY);
  if (!moduleFd) {
    return {ProbeStatus::kModuleOpenFailed, errno};
  }

  errno             = 0;
  const long result = ::syscall(SYS_finit_module, moduleFd.get(), "", 0);
  if (result != 0) {
    return classifyLoadFailure(errno);
  }

  #ifdef SYS_delete_module
    errno = 0;
    if (::syscall(SYS_delete_module, kProbeModuleName, O_NONBLOCK) != 0) {
      std::cerr << "Unsigned kernel module probe loaded successfully, but could not be unloaded:"
                << std::strerror(errno) << " (Code: " << errno << ")\n";
    }
  #endif

  return {ProbeStatus::kAllowed, 0};
}

ProbeExecutionResult runUnsignedModuleLoadProbe() {
  if (::geteuid() != 0) {
    return {ProbeStatus::kNotRoot, 0};
  }

#ifndef SYS_finit_module
  return {ProbeStatus::kUnsupportedPlatform, 0};
#else
  const auto kernelBuildDir = getKernelBuildDirectory();
  if (!kernelBuildDir) {
    struct utsname kernelInfo{};
    if (::uname(&kernelInfo) != 0) {
      return {ProbeStatus::kKernelInfoUnavailable, errno};
    }

    return {ProbeStatus::kKernelHeadersMissing, 0};
  }

  const auto probePaths = createProbePaths();
  if (!probePaths) {
    return {ProbeStatus::kTempDirectoryCreationFailed, errno};
  }

  ScopedDirectoryCleanup cleanup(probePaths->directory);

  if (!writeProbeSources(*probePaths)) {
    return {ProbeStatus::kSourceWriteFailed, errno};
  }

  if (!buildProbeModule(*kernelBuildDir, *probePaths)) {
    return {ProbeStatus::kBuildFailed, 0};
  }

  return tryLoadProbeModule(*probePaths);
#endif
}

void logProbeFailure(const ProbeExecutionResult &result) {
  switch (result.status) {
  case ProbeStatus::kNotRoot:
    std::cerr << "Probe info: Unsigned kernel module probe requires root privileges.\n";
    break;

  case ProbeStatus::kUnsupportedPlatform:
    std::cerr << "Probe info: Kernel module load probe is not supported on this platform.\n";
    break;

  case ProbeStatus::kKernelInfoUnavailable:
    std::cerr << "Probe info: Failed to determine the running kernel release: "
              << std::strerror(result.errorCode) << " (Code: " << result.errorCode << ")\n";
    break;

  case ProbeStatus::kKernelHeadersMissing: {
    struct utsname kernelInfo{};
    if (::uname(&kernelInfo) == 0) {
      const fs::path kernelBuildDir = fs::path("/usr/lib/modules") / kernelInfo.release / "build";
      std::cerr << "Probe info: Kernel headers are missing at " << kernelBuildDir
                << "; cannot build the runtime unsigned kernel module probe.\n";
    } else {
      std::cerr << "Probe info: Kernel headers are missing; cannot build the runtime unsigned kernel "
                   "module probe.\n";
    }
    break;
  }

  case ProbeStatus::kTempDirectoryCreationFailed:
    std::cerr << "Probe info: Failed to create a temporary directory for the unsigned module probe: "
              << std::strerror(result.errorCode) << " (Code: " << result.errorCode << ")\n";
    break;

  case ProbeStatus::kSourceWriteFailed:
    std::cerr << "Probe info: Failed to write the unsigned module probe sources.\n";
    break;

  case ProbeStatus::kBuildFailed:
    std::cerr << "Probe info: Failed to build the unsigned kernel module probe.\n";
    break;

  case ProbeStatus::kModuleOpenFailed:
    std::cerr << "Probe info: Failed to open built unsigned kernel module probe: "
              << std::strerror(result.errorCode) << " (Code: " << result.errorCode << ")\n";
    break;

  case ProbeStatus::kUnexpectedLoadFailure:
    std::cerr << "Probe info: Unsigned kernel module probe failed for an unexpected reason: "
              << std::strerror(result.errorCode) << " (Code: " << result.errorCode << ")\n";
    break;

  case ProbeStatus::kDeniedForOtherSecurityReason:
  case ProbeStatus::kBlockedBySignaturePolicy:
  case ProbeStatus::kAllowed:
    break;
  }
}

} // namespace

UnsignedKernelModuleLoadProbe::Result Validator::isUnsignedKernelModuleLoadBlocked() {
  const ProbeExecutionResult result = runUnsignedModuleLoadProbe();

  switch (result.status) {
  case ProbeStatus::kBlockedBySignaturePolicy:
    std::cerr << "Probe info: Unsigned kernel module load was denied by signature policy: "
              << std::strerror(result.errorCode) << " (Code: " << result.errorCode << ")\n";
    return {true, result.status};

  case ProbeStatus::kDeniedForOtherSecurityReason:
    std::cerr << "Probe info: Unsigned kernel module load was denied: "
              << std::strerror(result.errorCode) << " (Code: " << result.errorCode << ")\n";
    return {true, result.status};

  case ProbeStatus::kAllowed:
    return {false, result.status};

  default:
    logProbeFailure(result);
    return {false, result.status};
  }
}

} // namespace OdinSight::System::Environment
