#include <csignal>

#include "ids_cli.h"
#include "debug_logger.h"


::flow_inspector::IdsCli* global_cli{nullptr};


void signal_handler(int signal) {
  if (global_cli) {
    global_cli->stop();
  }
  ::flow_inspector::internal::coutDebug() << "stop signal: " << signal << ::std::endl;
}


void sighup_handler(int signal) {
  if (!global_cli) {
    return;
  }
  ::flow_inspector::internal::coutDebug() << "sighup signal: " << signal << ::std::endl;
  global_cli->updateRules();
}

int main(int argc, char **argv) {
  ::flow_inspector::IdsCli cli(argc, argv);
  global_cli = &cli;

  ::std::signal(SIGINT, signal_handler);
  ::std::signal(SIGHUP, sighup_handler);

  cli.start();
  return 0;
}