#include "CGroupService.hpp"
#include "OdinEngine.hpp"
#include "common/Result.hpp"
#include "system/CGroup.hpp"
#include <EnvironmentValidator.hpp>
#include <cstdlib>
#include <sys/prctl.h>

using CGroup               = OdinSight::System::CGroup;
using CGService            = OdinSight::System::CGService;
using EnvironmentValidator = OdinSight::System::Environment::Validator;
using OdinEngine           = OdinSight::Daemon::OdinEngine;

int main() {
  Odin::Result<void> isEnvValid = EnvironmentValidator::isValid();

  if (!isEnvValid) {
    // return EXIT_FAILURE;
  }

  auto cg_res = CGroup::create("OdinSight");

  if (!cg_res) {
    std::cerr << "[FATAL] Root CGroup initialization failed\n"
              << "Reason: ";
    cg_res.error().log();
    return EXIT_FAILURE;
  }

  auto cg_root    = std::move(cg_res.value());
  auto enable_res = OdinSight::System::CGService::enableSubtreeControllers(*cg_root);
  if (!enable_res) { enable_res.error().log(); }

  auto engine_res = OdinEngine::create(cg_root);

  if (!engine_res) {
    std::cerr << "[FATAL] Engine construction failed\n"
              << "Trace: ";
    engine_res.error().log();

    return EXIT_FAILURE;
  }

  auto& engine = engine_res.value();

  if (auto res = engine.init(); !res) {
    std::cerr << "[FATAL] Daemon initialization failed\n"
              << "Trace: ";
    res.error().log();
    return EXIT_FAILURE;
  }

  if (auto res = engine.run(); !res) {
    std::cerr << "[RUNTIME] Engine encountered a critical error\n"
              << "Trace: ";
    res.error().log();
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}
