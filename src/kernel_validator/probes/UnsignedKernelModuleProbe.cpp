#include "EnvironmentValidator.hpp"
#include "system/FD.hpp"

#include <cerrno>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

namespace fs = std::filesystem;

namespace OdinSight::System::Environment {

namespace {

constexpr char errorCtx[] = "UnsignedKernelModuleProbe";
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

Result<void> writeTextFile(const fs::path &path, const std::string &contents) {
  std::ofstream file(path);
  if (!file) {
    return std::unexpected(Odin::Error::Logic(
        errorCtx,
        "write unsigned kernel module probe source",
        "Failed to open the unsigned kernel module probe source file"));
  }

  file << contents;
  if (!file.good()) {
    return std::unexpected(Odin::Error::Logic(
        errorCtx,
        "write unsigned kernel module probe source",
        "Failed to write the unsigned kernel module probe source file"));
  }

  return {};
}

Result<void> runCommand(const std::vector<std::string> &args) {
  if (args.empty()) {
    return std::unexpected(
        Odin::Error::Logic(errorCtx, "run unsigned kernel module probe build", "Build command is empty"));
  }

  const pid_t pid = ::fork();
  if (pid < 0) {
    return std::unexpected(Odin::Error::System(errorCtx, "fork unsigned kernel module probe build", errno));
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
    return std::unexpected(Odin::Error::System(errorCtx, "wait for unsigned kernel module probe build", errno));
  }

  if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
    return std::unexpected(Odin::Error::Logic(
        errorCtx,
        "build unsigned kernel module probe",
        "Failed to build the unsigned kernel module probe"));
  }

  return {};
}

Result<fs::path> getKernelBuildDirectory() {
  struct utsname kernelInfo{};
  if (::uname(&kernelInfo) != 0) {
    return std::unexpected(Odin::Error::System(errorCtx, "read kernel release", errno));
  }

  const fs::path buildDir = fs::path("/usr/lib/modules") / kernelInfo.release / "build";
  if (!fs::is_directory(buildDir)) {
    return std::unexpected(Odin::Error::Logic(
        errorCtx,
        "locate kernel headers",
        "Kernel headers required for the unsigned kernel module probe are missing"));
  }

  return buildDir;
}

Result<ProbePaths> createProbePaths() {
  char  directoryTemplate[] = "/tmp/odinsight-kmod-probe-XXXXXX";
  char *directoryPath       = ::mkdtemp(directoryTemplate);
  if (!directoryPath) {
    return std::unexpected(
        Odin::Error::System(errorCtx, "create unsigned kernel module probe directory", errno));
  }

  ProbePaths paths;
  paths.directory  = directoryPath;
  paths.sourceFile = paths.directory / "odinsight_unsigned_probe.c";
  paths.makefile   = paths.directory / "Makefile";
  paths.moduleFile = paths.directory / "odinsight_unsigned_probe.ko";
  return paths;
}

Result<void> writeProbeSources(const ProbePaths &paths) {
  const Result<void> sourceWriteResult = writeTextFile(paths.sourceFile, kProbeModuleSource);
  if (!sourceWriteResult) {
    return std::unexpected(sourceWriteResult.error());
  }

  const Result<void> makefileWriteResult = writeTextFile(paths.makefile, kProbeMakefile);
  if (!makefileWriteResult) {
    return std::unexpected(makefileWriteResult.error());
  }

  return {};
}

Result<void> buildProbeModule(const fs::path &kernelBuildDir, const ProbePaths &paths) {
  return runCommand({
      "make",
      "-s",
      "-C",
      kernelBuildDir.string(),
      "M=" + paths.directory.string(),
      "modules",
  });
}

Result<void> classifyLoadFailure(int err) {
  switch (err) {
  case EKEYREJECTED:
  case ENOKEY:
  case EBADMSG:
    return std::unexpected(
        Odin::Error::System(errorCtx, "load unsigned kernel module denied by signature policy", err));

  case EPERM:
  case EACCES:
    return std::unexpected(
        Odin::Error::System(errorCtx, "load unsigned kernel module denied by other security policy", err));

  default:
    return std::unexpected(Odin::Error::System(errorCtx, "load unsigned kernel module probe", err));
  }
}

Result<void> tryLoadProbeModule(const ProbePaths &paths) {
  FD moduleFd(paths.moduleFile.string(), O_RDONLY);
  if (!moduleFd) {
    return std::unexpected(
        Odin::Error::System(errorCtx, "open built unsigned kernel module probe", errno));
  }

  errno             = 0;
  const long result = ::syscall(SYS_finit_module, moduleFd.get(), "", 0);
  if (result != 0) {
    return classifyLoadFailure(errno);
  }

#ifdef SYS_delete_module
  errno = 0;
  if (::syscall(SYS_delete_module, kProbeModuleName, O_NONBLOCK) != 0) {
    std::cerr << "Unsigned kernel module probe loaded successfully, but could not be unloaded: "
              << std::strerror(errno) << " (Code: " << errno << ")\n";
  }
#endif

  return {};
}

Result<void> runUnsignedModuleLoadProbe() {
  if (::geteuid() != 0) {
    return std::unexpected(Odin::Error::Logic(
        errorCtx,
        "load unsigned kernel module probe",
        "Unsigned kernel module probe requires root privileges"));
  }

#ifndef SYS_finit_module
  return std::unexpected(Odin::Error::Logic(
      errorCtx,
      "load unsigned kernel module probe",
      "Kernel module load probe is not supported on this platform"));
#else
  const Result<fs::path> kernelBuildDir = getKernelBuildDirectory();
  if (!kernelBuildDir) {
    return std::unexpected(kernelBuildDir.error());
  }

  const Result<ProbePaths> probePaths = createProbePaths();
  if (!probePaths) {
    return std::unexpected(probePaths.error());
  }

  ScopedDirectoryCleanup cleanup(probePaths->directory);

  const Result<void> probeSourcesWriteResult = writeProbeSources(*probePaths);
  if (!probeSourcesWriteResult) {
    return std::unexpected(probeSourcesWriteResult.error());
  }

  const Result<void> probeBuildResult = buildProbeModule(*kernelBuildDir, *probePaths);
  if (!probeBuildResult) {
    return std::unexpected(probeBuildResult.error());
  }

  return tryLoadProbeModule(*probePaths);
#endif
}

} // namespace

Result<void> Validator::canLoadUnsignedKernelModules() {
  return runUnsignedModuleLoadProbe();
}

} // namespace OdinSight::System::Environment
