# Unit tests of the Linux port, and the end-to-end test that runs koios-agent
# against a mock gateway (tests/e2e.py, Python 3 standard library only).

set(TEST_SCRATCH ${CMAKE_CURRENT_BINARY_DIR}/scratch)
file(MAKE_DIRECTORY ${TEST_SCRATCH})

function(koios_test name)
    add_executable(${name} ${name}.c)
    target_link_libraries(${name} PRIVATE koios_sdk)
    target_include_directories(${name} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/..)
    if(NOT APPLE)
        target_compile_definitions(${name} PRIVATE _GNU_SOURCE)
    endif()
    target_compile_options(${name} PRIVATE -Wall -Wextra -Wno-unused-parameter)
endfunction()

koios_test(test_os)
koios_test(test_logstore)
koios_test(test_metrics)
koios_test(test_ws)

# Restart-surviving slots: one process writes, the next reads.
file(MAKE_DIRECTORY ${TEST_SCRATCH}/os)
add_test(NAME os COMMAND test_os ${TEST_SCRATCH}/os write)
add_test(NAME os_slots_survive COMMAND test_os ${TEST_SCRATCH}/os read)
set_tests_properties(os PROPERTIES FIXTURES_SETUP os_slots)
set_tests_properties(os_slots_survive PROPERTIES FIXTURES_REQUIRED os_slots)

# The log ring in memory, then on disk across two processes.
file(MAKE_DIRECTORY ${TEST_SCRATCH}/logstore)
add_test(NAME logstore_memory COMMAND test_logstore ${TEST_SCRATCH}/logstore memory)
add_test(NAME logstore_write
    COMMAND ${CMAKE_COMMAND} -E env sh -c "rm -f ${TEST_SCRATCH}/logstore/logring && $<TARGET_FILE:test_logstore> ${TEST_SCRATCH}/logstore write")
add_test(NAME logstore_survives COMMAND test_logstore ${TEST_SCRATCH}/logstore read)
set_tests_properties(logstore_write PROPERTIES FIXTURES_SETUP logring)
set_tests_properties(logstore_survives PROPERTIES FIXTURES_REQUIRED logring)

file(MAKE_DIRECTORY ${TEST_SCRATCH}/metrics)
add_test(NAME metrics COMMAND test_metrics ${TEST_SCRATCH}/metrics)

add_test(NAME websocket COMMAND test_ws)
set_tests_properties(websocket PROPERTIES TIMEOUT 120)

if(KOIOS_BUILD_AGENT)
    find_package(Python3 COMPONENTS Interpreter)
    if(Python3_FOUND)
        add_test(NAME agent_e2e
            COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/e2e.py
                --agent $<TARGET_FILE:koios-agent> --scratch ${TEST_SCRATCH}/e2e)
        set_tests_properties(agent_e2e PROPERTIES TIMEOUT 180)
    endif()
endif()
