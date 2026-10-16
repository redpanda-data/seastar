# perf-tests

`perf-tests` is a simple microbenchmarking framework. Its main purpose is to allow monitoring the impact that code changes have on performance.

## Theory of operation

The framework performs each test in several runs. During a run the microbenchmark code is executed in a loop and the average time of an iteration is computed. The shown results are median, median absolute deviation, maximum and minimum value of all the runs.

```
single run iterations:    0
single run duration:      1.000s
number of runs:           5

test                            iterations      median         mad         min         max
combined.one_row                    745336   691.218ns     0.175ns   689.073ns   696.476ns
combined.single_active                7871    85.271us    76.185ns    85.145us   108.316us
```

`perf-tests` allows limiting the number of iterations or the duration of each
run. If duration is used, the implementation depends on whether a test declares
iters_per_sec. If it does the total iteration count is calculated directly
based on that value, and if not an additional dry run is used to estimate how
many iterations can be run in the specified time.

### Flags

* `-i <n>` or `--iterations <n>` – fixes the number of iterations in each run at `n`, however long that takes (0 to let `--duration` decide)
* `-d <t>` or `--duration <t>` – limits the duration of each run to no more than `t` seconds, unless `--iterations` has already fixed the count (0 for unlimited)
* `-r <n>` or `--runs <n>` – the number of runs of each test to execute
* `-t <regexs>` or `--tests <regexs>` – executes only tests which names match any regular expression in a comma-separated list `regexs`
* `--list` – lists all available tests
* `--suggest-rates` – after the results, print the iteration rate measured for each test as a `.iters_per_sec` declaration to paste into its `PERF_TEST` macro
* `--overhead-threshold <percent>` – warn if measurement overhead exceeds this percentage (default: 10)
* `--fail-on-high-overhead` – fail the test run if any test exceeds the overhead threshold

## Example usage

### Simple test

Performance tests are defined in a similar manner to unit tests. Macro `PERF_TEST(test_group, test_case)` allows specifying the name of the test and the group it belongs to. Microbenchmark can either return nothing or a future.

Compiler may attempt to optimise too much of the test logic. A way of preventing this is passing the final result of all computations to a function `perf_tests::do_not_optimize()`. That function should introduce little to none overhead, but forces the compiler to actually compute the value.

```c++
PERF_TEST(example, simple1)
{
    auto v = compute_value();
    perf_tests::do_not_optimize(v);
}

PERF_TEST(example, simple2)
{
    return compute_different_value().then([] (auto v) {
        perf_tests::do_not_optimize(v);
    });
}
```

### Fixtures

As it is in case of unit tests, performance tests may benefit from using a fixture that would set up a proper environment. Such tests should use macro `PERF_TEST_F(test_group, test_case)`. The test itself will be a member function of a class derivative of `test_group`.

The constructor and destructor of a fixture are executed in a context of Seastar thread, but the actual test logic is not. The same instance of a fixture will be used all runs (and iterations) of a given test, but a unique fixture is created for each test. In the example below, exactly 2 fixture objects will be created, for `fixture1` and `fixture2` tests. If you want to share setup _between_ test cases, you can use static members as shown below.

```c++
class example {
protected:
    data_set _ds1;
    data_set _ds2;
private:
    static data_set perpare_data_set();
public:
    example()
        : _ds1(prepare_data_set())
        , _ds2(prepare_data_set())
    { }
};

PERF_TEST_F(example, fixture1)
{
    auto r = do_something_with(_ds1);
    perf_tests::do_not_optimize(r);
}

PERF_TEST_F(example, fixture2)
{
    auto r = do_something_with(_ds1, _ds2);
    perf_tests::do_not_optimize(r);
}
```

### Custom time measurement

Even with fixtures it may be necessary to do some costly initialization during each iteration. Its impact can be reduced by specifying the exact part of the test that should be measured using functions `perf_tests::start_measuring_time()` and `perf_tests::stop_measuring_time()`.

```c++
PERF_TEST(example, custom_time_measurement2)
{
    auto data = prepare_data();
    perf_tests::start_measuring_time();
    do_something(std::move(data));
    perf_tests::stop_measuring_time();
}

PERF_TEST(example, custom_time_measurement2)
{
    auto data = prepare_data();
    perf_tests::start_measuring_time();
    return do_something_else(std::move(data)).finally([] {
        perf_tests::stop_measuring_time();
    });
}
```

#### Measurement overhead

The cost of starting and stopping the timers is substantial, about 1μs for a start/stop pair, due to the overhead of reading the performance counters in the kernel. When using manual time measurement with `start_measuring_time()`/`stop_measuring_time()`, you should ensure that the timed region is substantially longer than this overhead to reduce measurement error. A common approach is to use a loop inside the timed region and return the number of iterations from the test method.

If you do _not_ use these manual methods, the overhead is very low (a few instructions) as the test method is already called in such a loop by the framework, with the time manipulation methods outside that.

##### Overhead column

The framework tracks and reports the estimated measurement overhead as a percentage in the `overhead` column. This is calculated by:

1. Calibrating the cost of a single `start_measuring_time()`/`stop_measuring_time()` pair at startup
2. Counting how many times these functions are called during each test run
3. Computing `overhead% = (call_count × cost_per_call) / measured_runtime × 100`

A high overhead percentage (e.g., >10%) indicates that the timing instrumentation is consuming a significant portion of the measured time, which reduces the accuracy of the results. This typically happens when:
- The timed region is very short (comparable to the ~1μs overhead)
- `start_measuring_time()`/`stop_measuring_time()` are called many times with little work between them

To reduce overhead, either:
- Increase the amount of work in each timed region
- Use an inner loop and return the iteration count, rather than calling start/stop for each iteration

##### Overhead warnings

By default, a warning is printed if any test has median overhead exceeding 10%:

```
WARNING: test 'example.my_test' has high measurement overhead: 15.2% (threshold: 10.0%)
```

You can adjust the threshold with `--overhead-threshold <percent>`, or fail the test run entirely when overhead is too high with `--fail-on-high-overhead`.

### Fixed iteration counts

Calibrating the iteration count with a dry run keeps the duration of a run stable, but makes the number of iterations depend on how fast the machine is and on whatever else it was doing during the dry run. A test which declares how many iterations it completes in one second gets the opposite trade-off: the count is fixed at the declared rate times `--duration`, no dry run is used to pick it, and the duration of a run becomes the approximate quantity.

```c++
PERF_TEST(example, declared_rate, .iters_per_sec = 10'000'000)
{
    auto v = compute_value();
    perf_tests::do_not_optimize(v);
}
```

The rate is a `double`, so it can be written in scientific notation - `.iters_per_sec = 1.2e6` as well as `1'200'000`.

A declared rate is only honored in a release build. The rate is a measurement of one, and a build with sanitizers or debug checks runs an order of magnitude slower, so holding the count fixed there would stretch every run by that factor to produce numbers that are not comparable to a release build's anyway. The opt-in is the `SEASTAR_PERF_TESTS_HONOR_DECLARED_RATE` macro, which the CMake build defines for the release build types and the Bazel build for `--config=release`. Either can be told otherwise, to hold the count fixed in a slow build or to calibrate it in a fast one: pass `--enable-perf-test-declared-rates` or `--disable-perf-test-declared-rates` to `configure.py`, or set `--@seastar//:perf_test_declared_rates` under Bazel. In a build which does not honor them the count is calibrated by the dry run as usual, and the configuration header says so:

```
declared rates:           ignored (not a release build)
```

With the default `--duration 1` that test runs exactly 10,000,000 iterations per run; with `--duration 5`, exactly 50,000,000. The rate is expressed in the same iterations that `--iterations` limits and the `iters` column reports, so a test which returns an iteration count from its body declares its rate in those inner iterations.

An explicit `--iterations` overrides the declaration, and `--duration 0` (no duration limit) disables it, since there is then no duration to scale by.

The rate is a measurement, so the framework will take it for you: `--suggest-rates` prints one pasteable declaration per test, measured on the wall clock (what `--duration` actually limits) and rounded to two significant digits.

```
measured iteration rates, to declare in the PERF_TEST macro so that a
run's iteration count no longer depends on the speed of the machine:

  example.simple1              .iters_per_sec = 2'700'000'000
  example.declared_rate        .iters_per_sec = 52'000'000
  example.big_inner_loop       .iters_per_sec = 540
```

It works whether or not the test already declares a rate, so the same command both writes the declarations and refreshes them.

A declared rate is a measurement of one machine, so it only approximates the duration on another. It does not affect the reported results, which are always per-iteration, so a rate that is out of date costs nothing but a run that is shorter or longer than asked for. Once a run strays more than a factor of two from the requested duration, the achieved rate is reported so the declaration can be refreshed:

```
WARNING: test 'example.declared_rate' declares 100000 iterations/s but achieved 2.87e+07/s, so each run took 3.484ms rather than the requested 1.000s
```
