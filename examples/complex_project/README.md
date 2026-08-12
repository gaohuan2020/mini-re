# Complex project fixture

This fixture is a multi-file C++17 project used by `examples/complex_project_demo.py`.
The checked-in `src/analyzer.cpp` intentionally contains a stub only for the vector
overload. mini-re must use the address map to select that overload, replace only its
body in a full project overlay, and preserve the scalar overload and every other file.

Build with either interface:

```bash
make clean all && make test && make runtime

cmake -S . -B build-cmake
cmake --build build-cmake
ctest --test-dir build-cmake --output-on-failure
./build-cmake/scoring_cli --self-test
```
