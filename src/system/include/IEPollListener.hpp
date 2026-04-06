#include "system/FD.hpp"
#include <stdint.h>

namespace OdinSight::System {

class IEPollListener {

public:
  virtual ~IEPollListener() = default;

  virtual uint32_t getEvents() const = 0;

  /**
   * @brief Called by EPollManager when activity occurs on the FD.
   */
  virtual void onEpollEvent(uint32_t events) = 0;

  /**
   * @brief Returns the File Descriptor this listener is watching.
   */
  virtual const FD &getFd() const = 0;
};

} // namespace OdinSight::System
