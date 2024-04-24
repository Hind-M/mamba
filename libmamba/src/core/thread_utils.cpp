// Copyright (c) 2019, QuantStack and Mamba Contributors
//
// Distributed under the terms of the BSD 3-Clause License.
//
// The full license is in the file LICENSE, distributed with this software.

#include <atomic>
#include <iostream>
#ifndef _WIN32
#include <signal.h>
#endif

#include "mamba/core/invoke.hpp"
#include "mamba/core/output.hpp"
#include "mamba/core/thread_utils.hpp"

namespace mamba
{
    /***********************
     * thread interruption *
     ***********************/

    namespace
    {
        std::atomic<bool> sig_interrupted(false);
        std::atomic<int> sig_interrupt_scope_count{ 0 };
    }

    void reset_signal_handler()
    {
        std::signal(SIGINT, SIG_DFL);
    }

    int increment_interrupt_scope()
    {
        return ++sig_interrupt_scope_count;
    }

    int decrement_interrupt_scope()
    {
        auto current_count = --sig_interrupt_scope_count;
        if (current_count < 0)
        {
            throw "current_count is negative!";
        }
        return current_count;
    }

    bool is_interrupt_scope()
    {
        return sig_interrupt_scope_count > 0;
    }

    namespace
    {
        void handle_signal(int signum)
        {
            if (is_interrupt_scope() && !is_sig_interrupted())
            {
                std::cerr << "Interrupted!!!" << std::endl;
                set_sig_interrupted();
                return;
            }

            std::cerr << "USING DEFAULT!!!" << std::endl;
            SIG_DFL(signum);
        }
    }

    // #ifndef _WIN32
    //     namespace
    //     {
    //         std::thread::native_handle_type sig_recv_thread;
    //         std::atomic<bool> receiver_exists(false);
    //     }
    //
    //     void reset_sig_interrupted()
    //     {
    //         sig_interrupted.store(false);
    //         set_default_signal_handler();
    //     }
    //
    //     int kill_receiver_thread()
    //     {
    //         if (receiver_exists.load())
    //         {
    //             pthread_cancel(sig_recv_thread);
    //             receiver_exists.store(false);
    //             return 0;
    //         }
    //         return -1;
    //     }
    //
    //     int stop_receiver_thread()
    //     {
    //         if (receiver_exists.load())
    //         {
    //             pthread_kill(sig_recv_thread, SIGINT);
    //             receiver_exists.store(false);
    //             return 0;
    //         }
    //         return -1;
    //     }
    //
    //     int default_signal_handler(sigset_t sigset)
    //     {
    //         std::cerr << "Start handling signal..." << std::endl;
    //         int signum = 0;
    //         // wait until a signal is delivered:
    //         sigwait(&sigset, &signum);
    //         std::cerr << "signal received!" << std::endl;
    //         handle_signal(signum);
    //         std::cerr << "signal handled!" << std::endl;
    //         return signum;
    //     }
    //
    //     void set_signal_handler(const std::function<void(sigset_t)>& handler)
    //     {
    //         stop_receiver_thread();
    //         std::cerr << "set_signal_handler" << std::endl;
    //         // block signals in this thread and subsequently
    //         // spawned threads
    //         sigset_t sigset;
    //         sigemptyset(&sigset);
    //         sigaddset(&sigset, SIGINT);
    //         // sigaddset(&sigset, SIGTERM);
    //         pthread_sigmask(SIG_BLOCK, &sigset, nullptr);
    //         std::thread receiver(handler, sigset);
    //         sig_recv_thread = receiver.native_handle();
    //         receiver_exists.store(true);
    //         receiver.detach();
    //     }
    //
    //     void set_default_signal_handler()
    //     {
    //         std::cerr << "LINUX: set_default_signal_handler" << std::endl;
    //         std::cout << "LINUX: set_default_signal_handler" << std::endl;
    //         set_signal_handler(default_signal_handler);
    //     }
    // #else
    void set_default_signal_handler()
    {
        std::cerr << "WINDOWS: set_default_signal_handler" << std::endl;
        std::cout << "WINDOWS: set_default_signal_handler" << std::endl;
        std::signal(SIGINT, &handle_signal);
    }

    // #endif

    bool is_sig_interrupted() noexcept
    {
        return sig_interrupted.load();
    }

    void set_sig_interrupted() noexcept
    {
        sig_interrupted.store(true);
    }

    void interruption_point()
    {
        if (is_sig_interrupted())
        {
            throw thread_interrupted();
        }
    }

    /*******************************
     * thread count implementation *
     *******************************/

    namespace
    {
        int thread_count = 0;
        std::mutex clean_mutex;
        std::condition_variable clean_var;

        std::mutex main_mutex;
        std::condition_variable main_var;
    }  // namespace

    void increase_thread_count()
    {
        std::unique_lock<std::mutex> lk(clean_mutex);
        ++thread_count;
    }

    void decrease_thread_count()
    {
        std::unique_lock<std::mutex> lk(clean_mutex);
        --thread_count;
        std::notify_all_at_thread_exit(clean_var, std::move(lk));
    }

    int get_thread_count()
    {
        return thread_count;
    }

    void wait_for_all_threads()
    {
        std::unique_lock<std::mutex> lk(clean_mutex);
        clean_var.wait(lk, []() { return thread_count == 0; });
    }

    /*************************
     * thread implementation *
     *************************/

    bool thread::joinable() const noexcept
    {
        return m_thread.joinable();
    }

    std::thread::id thread::get_id() const noexcept
    {
        return m_thread.get_id();
    }

    void thread::join()
    {
        m_thread.join();
    }

    void thread::detach()
    {
        m_thread.detach();
    }

    std::thread::native_handle_type thread::native_handle()
    {
        return m_thread.native_handle();
    }

    /**********************
     * interruption_guard *
     **********************/

    std::function<void()> interruption_guard::m_cleanup_function;

    interruption_guard::~interruption_guard()
    {
        wait_for_all_threads();
        if (is_sig_interrupted() || std::uncaught_exceptions() > 0)
        {
            const auto result = safe_invoke(std::move(m_cleanup_function));
            if (!result)
            {
                LOG_ERROR << "interruption_guard invocation failed: " << result.error().what();
            }
        }
    }

}  // namespace mamba
