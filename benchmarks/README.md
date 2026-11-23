# Performance Benchmark Harness

Automated performance benchmark and stress-testing harness for `stellar-toml-lint`.

## Features

- **Synthetic TOML generation** - Creates configurations with 10KB to 5MB
- **Performance regression thresholds** - < 50ms per 1,000 lines
- **CI integration** - Compares PR performance against main branch
- **Memory profiling** - Tracks heap allocations during linting

## Usage

```bash
npm run bench
```

## Configuration

Performance thresholds are defined in `benchmarks/runner.ts`:

| File Size | Threshold |
| --------- | --------- |
| < 10KB    | 5ms       |
| < 100KB   | 20ms      |
| < 1MB     | 50ms      |
| < 5MB     | 200ms     |

## Output

The runner outputs a summary table:

```
[PASS] small      | Lines:    100 | Size:  5.2KB | Time:  1.23ms | Memory:  2.10MB
[PASS] medium     | Lines:   1000 | Size: 52.3KB | Time:  5.67ms | Memory:  4.50MB
[PASS] large      | Lines:  10000 | Size: 523.1KB | Time: 15.42ms | Memory: 12.30MB
[PASS] xlarge     | Lines: 100000 | Size: 5.1MB | Time: 45.21ms | Memory: 45.20MB
```

## Requirements

- Node.js 20+
- `tsx` for running TypeScript directly
