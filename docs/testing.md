# 测试指南

mini-re 将测试分成离线回归、复杂修复闭环、对象格式矩阵和真实端到端矩阵。默认测试不会访问模型服务，也不会用 fake 结果冒充真实集成结果。

## 依赖

- Python 3.9+
- C/C++ 编译器（`cc`、`clang++`）
- `file`、`nm`、`objdump`；macOS 可回退到 `otool`
- 仅真实矩阵需要 Ghidra Bridge、两个不同模型和相应凭据

## 默认离线套件

```bash
python3 -m pip install -e .
python3 -m unittest discover -s tests -v
```

测试覆盖：

| 层级 | 测试文件 | 验证内容 |
|---|---|---|
| 基础证据 | `tests/test_mini_re.py` | 对象元数据、符号、反汇编、模型响应解析与 CLI 约束 |
| 高级流水线 | `tests/test_advanced.py` | 7 项 Ghidra artifact、知识图谱、overlay、重载保护、门禁和日志 |
| 确定性验证 | `tests/test_verifiers.py` | objective verifier 与 11 项 parity signal |
| 复杂闭环 | `tests/test_complex_loop.py` | checker FAIL 后诊断回灌、候选修复以及 build/test/runtime 独立门禁 |
| 复杂 C++ 项目 | `tests/test_complex_project.py` | 多文件静态库、重载地址映射、完整 overlay、Make build、单测和 CLI runtime 修复闭环 |
| 格式矩阵 | `tests/test_format_matrix.py` | clang 真实生成 native、ELF、COFF C++ 对象并提取证据 |
| 对象/反编译对照 | `tests/test_decompile_demo.py` | 检查随仓库提交的 ELF `.o`、目标符号、证据提取、恢复代码编译和行为对照 |
| 集成矩阵 | `tests/test_real_integration_matrix.py` | 配置契约，以及可选的真实 Ghidra + 双模型执行 |

默认预期为 31 项测试中 30 项通过、1 项跳过。跳过项是需要外部工程、Ghidra 和模型凭据的真实端到端测试。

## 多文件 C++ 项目闭环

```bash
python3 examples/complex_project_demo.py \
  --output-dir work/complex-project-demo
```

这个测试会复制 `examples/complex_project/`，从参考实现生成真实 C++ 对象文件，然后执行严格 fake Ghidra、两个 scripted 模型和真实项目门禁。关键断言包括：

1. 地址 `0x1000` 通过完整签名选中 `Analyzer::score(vector, Options)`，不会误改标量重载。
2. 第一轮候选能够通过 `make clean all` 和 `make test`，但 `make runtime` 失败。
3. checker、objective verifier 和 runtime 输出全部进入第二轮 reverser prompt。
4. 第二轮重新执行 build/test/runtime，三类门禁全部 PASS。
5. 原项目源码不变；最终 overlay 包含静态库、CLI、include/src/tests 和两套构建描述。
6. 每轮日志、知识图谱、目标完整签名和地址映射路径均可审计。

## 复杂对象修复闭环

```bash
python3 examples/complex_loop_demo.py \
  --output-dir work/complex-loop-demo
```

这个演示会：

1. 将 `examples/complex.c` 编译成真实 `.o`。
2. 第一轮让 reverser 返回一个可编译但逻辑不完整的函数。
3. checker、objective verifier 和 runtime gate 分别识别缺失循环、switch 和行为错误。
4. 把上一候选、全部 verdict 和构建输出注入第二轮 prompt。
5. 第二轮修复后重新执行所有检查，只有全部通过才结束。

检查输出目录中的以下文件可审计反馈闭环：

```text
reports/logs/round-1.json
reports/logs/round-2.json
reports/knowledge-graph.json
reports/result.json
```

## 真实 ELF/COFF/C++ 矩阵

复制并修改示例配置：

```bash
cp examples/real-matrix.example.json /tmp/mini-re-real-matrix.json
```

每个 case 必须提供真实对象文件、格式、Ghidra 地址、源码映射，以及非空的 build/test/runtime 命令。reverser 和 checker 必须使用不同模型。

```bash
export OPENAI_API_KEY='reverser-key'
export MINI_RE_CHECKER_API_KEY='checker-key'

python3 integration_matrix.py \
  --config /tmp/mini-re-real-matrix.json \
  --output-dir reports/real-matrix
```

也可以通过 unittest 门禁运行：

```bash
export MINI_RE_REAL_MATRIX_CONFIG=/tmp/mini-re-real-matrix.json
export MINI_RE_REAL_MATRIX_TIMEOUT=7200
python3 -m unittest tests.test_real_integration_matrix -v
```

## CI

`.github/workflows/ci.yml` 在 push 和 pull request 时运行 Python 3.9–3.13 矩阵。CI 只运行可复现的离线套件；真实模型凭据不会写入仓库或默认工作流。

如果本机缺少 `clang++`，格式矩阵会明确跳过。发布前应在安装 clang 的环境至少运行一次完整套件。
