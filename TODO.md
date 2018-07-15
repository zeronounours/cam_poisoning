A list of remaining things to do
================================

* Improve the logger handling: add a replacement for perror

* Improve the logger to redirect to file

* Don't queue unicast ethernet frames to the current interface
  - Move it to the queuing function. Currently message can be queued in
  restore_mac_callback

* Don't queue broadcast & multicast ethernet frames
  - Only queue message whose MAC is in the cache
  - Move it to the queuing function. Currently message can be queued in
  restore_mac_callback

* Update the ARP cache based on gratiutous ARP

* Don't send asynchronous CAM restoration frame for intercepted hosts

* Force re-poisoning of hosts when a frame is received from one of them

* In the restore_mac_callback, ensure that packets which must intercepted are
sent through the IPC instead of being queued

* Multi-thread the poisoning for effeciency. Currently on retransmission,
the main thread may be blocked for 750ms if it doesn't succeed in restoring the
CAM tables; meanwhile, poisoning doesn't happen anymore. Can have
  - one thread to retransmit not-targetted frames asynchronously
  - one thread to poison and retransmit from time to time


* Add support for more than 2 intercepted hosts

* Dynamically set the size of the reception frame buffer based on the MTU

* Handle IPC socket permissions: full access to the socket may be dangerous
because it may allow unprivileged users to inject raw packet

* Add additional modes for poisoning, restoration and ARP cache discovery
  - __Poisoning__:
    * mere Ethernet frame
  - __Restoration__:
    * stealth: wait for a frame from the host
  - __ARP cache__:
    * retrieve local cache
    * stealth: wait for broadcasted ARP requests
    * semi-stealth: increase time between each ARP requests
    * user-input: cache given through commandline

