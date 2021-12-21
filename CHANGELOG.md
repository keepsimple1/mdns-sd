# Version 0.2.1

- mDNS daemon respond socket to be blocking for simpler send.

# Version 0.2.0

- Public API internally to use the unblocking try_send() to replace send().
- Add `Again` in Error type to support retry.

# Version 0.1.0

- Initial version
