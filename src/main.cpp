#include <csignal>

#include "ids_cli.h"


::flow_inspector::IdsCli* global_cli{nullptr};


void signal_handler(int signal) {
    if (global_cli) {
        global_cli->stop();
    }
    ::flow_inspector::internal::coutDebug() << "stop signal: " << signal << ::std::endl;
    // ::std::exit(0);
}

int main(int argc, char **argv) {
    ::flow_inspector::IdsCli cli(argc, argv);
    global_cli = &cli;

    ::std::signal(SIGINT, signal_handler);

    cli.start();
    return 0;
}