#include <cassert>
#include <cstdio>
#include <fstream>
#include <sstream>

#include <csignal>
#include <unistd.h>

#include "softflow/daemon.hpp"

using namespace softflow;

namespace {

std::string temp_path(const std::string& suffix) {
    std::ostringstream oss;
    oss << "/tmp/softflow_test_" << getpid() << suffix;
    return oss.str();
}

void test_pidfile_writes_and_removes_itself() {
    const auto path = temp_path("_pidfile1");
    {
        PidFile pf(path);
        assert(pf.path() == path);

        std::ifstream in(path);
        long pid = 0;
        in >> pid;
        assert(pid == static_cast<long>(getpid()));
    }
    // The file must be gone once the PidFile goes out of scope.
    std::ifstream in(path);
    assert(!in.is_open());
}

void test_pidfile_rejects_a_running_process() {
    const auto path = temp_path("_pidfile2");
    PidFile pf(path); // owns the file, naming this (running) process

    bool threw = false;
    try {
        PidFile second(path); // should detect that `path` names a live PID
    } catch (const std::runtime_error&) {
        threw = true;
    }
    assert(threw);
}

void test_pidfile_move_transfers_ownership() {
    const auto path = temp_path("_pidfile3");
    PidFile pf(path);
    PidFile moved(std::move(pf));
    assert(moved.path() == path);

    // The moved-from object must no longer remove the file when it is
    // destroyed (it no longer owns it) -- destroying `pf` here (at scope
    // exit) must not delete the file out from under `moved`.
}

void test_pidfile_stale_file_is_overwritten() {
    const auto path = temp_path("_pidfile4");
    {
        // Write a pidfile naming a PID that (almost certainly) does not
        // exist, simulating a stale file left behind by an earlier,
        // crashed run.
        std::ofstream out(path);
        out << "999999999\n";
    }
    // Constructing a PidFile at the same path must not throw, since the
    // named process does not exist (ESRCH), and must successfully
    // overwrite the file with this process's own PID.
    PidFile pf(path);
    std::ifstream in(path);
    long pid = 0;
    in >> pid;
    assert(pid == static_cast<long>(getpid()));
}

void test_signal_pipe_reports_delivered_signals() {
    SignalPipe pipe;

    // Nothing has been sent yet.
    assert(pipe.drain().empty());

    raise(SIGUSR1);
    // Give the signal a moment to be delivered and the handler to run
    // (raise() is synchronous on the delivering thread for POSIX signals
    // in a single-threaded process, so this should already be true, but a
    // short retry loop keeps the test robust against unusual scheduling).
    std::vector<int> seen;
    for (int attempt = 0; attempt < 100 && seen.empty(); ++attempt) {
        seen = pipe.drain();
    }
    assert(seen.size() == 1);
    assert(seen[0] == SIGUSR1);

    // Draining again with nothing new pending returns empty.
    assert(pipe.drain().empty());
}

void test_signal_pipe_reports_multiple_distinct_signals() {
    SignalPipe pipe;
    raise(SIGHUP);
    raise(SIGUSR1);

    std::vector<int> seen;
    for (int attempt = 0; attempt < 100 && seen.size() < 2; ++attempt) {
        auto batch = pipe.drain();
        seen.insert(seen.end(), batch.begin(), batch.end());
    }
    assert(seen.size() == 2);
    assert(seen[0] == SIGHUP);
    assert(seen[1] == SIGUSR1);
}

} // namespace

int main() {
    test_pidfile_writes_and_removes_itself();
    test_pidfile_rejects_a_running_process();
    test_pidfile_move_transfers_ownership();
    test_pidfile_stale_file_is_overwritten();
    test_signal_pipe_reports_delivered_signals();
    test_signal_pipe_reports_multiple_distinct_signals();
    std::puts("all daemon tests passed");
    return 0;
}
