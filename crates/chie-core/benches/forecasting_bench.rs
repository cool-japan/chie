//! Benchmarks for resource usage forecasting.

use chie_core::forecasting::{ForecastMethod, Forecaster};
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;

/// Benchmark adding samples.
fn bench_add_sample(c: &mut Criterion) {
    let mut forecaster = Forecaster::new(ForecastMethod::LinearRegression);

    c.bench_function("forecasting_add_sample", |b| {
        b.iter(|| {
            forecaster.add_sample(black_box(100.0));
        });
    });
}

/// Benchmark adding multiple samples.
fn bench_add_samples(c: &mut Criterion) {
    let mut group = c.benchmark_group("forecasting_add_samples");

    for count in [10, 50, 100] {
        let samples: Vec<f64> = (0..count).map(|i| i as f64 * 10.0).collect();

        group.throughput(Throughput::Elements(count as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}_samples", count)),
            &samples,
            |b, samps| {
                b.iter(|| {
                    let mut forecaster = Forecaster::new(ForecastMethod::LinearRegression);
                    forecaster.add_samples(black_box(samps));
                });
            },
        );
    }

    group.finish();
}

/// Benchmark forecasting with different methods.
fn bench_forecast_methods(c: &mut Criterion) {
    let mut group = c.benchmark_group("forecasting_methods");

    let methods = [
        ForecastMethod::MovingAverage,
        ForecastMethod::LinearRegression,
        ForecastMethod::ExponentialSmoothing,
    ];

    for method in methods {
        let mut forecaster = Forecaster::new(method);

        // Add historical data
        for i in 0..50 {
            forecaster.add_sample((i as f64) * 10.0 + (i as f64).sin() * 5.0);
        }

        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{:?}", method)),
            &forecaster,
            |b, fc| {
                b.iter(|| {
                    let _ = fc.forecast(black_box(1));
                });
            },
        );
    }

    group.finish();
}

/// Benchmark forecasting different periods ahead.
fn bench_forecast_periods(c: &mut Criterion) {
    let mut group = c.benchmark_group("forecasting_periods");

    let mut forecaster = Forecaster::new(ForecastMethod::LinearRegression);

    // Add historical data with linear trend
    for i in 0..100 {
        forecaster.add_sample((i as f64) * 2.5);
    }

    for periods in [1, 5, 10, 50, 100] {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}_periods", periods)),
            &periods,
            |b, &per| {
                b.iter(|| {
                    let _ = forecaster.forecast(black_box(per));
                });
            },
        );
    }

    group.finish();
}

/// Benchmark time-to-capacity calculation.
fn bench_time_to_capacity(c: &mut Criterion) {
    let mut forecaster = Forecaster::new(ForecastMethod::LinearRegression);

    // Add historical data with growth
    for i in 0..50 {
        forecaster.add_sample((i as f64) * 10.0);
    }

    c.bench_function("forecasting_time_to_capacity", |b| {
        b.iter(|| {
            let _ = forecaster.time_to_capacity(black_box(1000.0));
        });
    });
}

/// Benchmark growth rate calculation.
fn bench_growth_rate(c: &mut Criterion) {
    let mut forecaster = Forecaster::new(ForecastMethod::LinearRegression);

    // Add historical data
    for i in 0..100 {
        forecaster.add_sample((i as f64) * 5.0);
    }

    c.bench_function("forecasting_growth_rate", |b| {
        b.iter(|| {
            let _ = forecaster.growth_rate();
        });
    });
}

/// Benchmark sample count.
fn bench_sample_count(c: &mut Criterion) {
    let mut forecaster = Forecaster::new(ForecastMethod::LinearRegression);

    // Add historical data with clear trend
    for i in 0..100 {
        forecaster.add_sample((i as f64) * 3.0);
    }

    c.bench_function("forecasting_sample_count", |b| {
        b.iter(|| {
            let _ = forecaster.sample_count();
        });
    });
}

/// Benchmark anomaly detection.
fn bench_is_anomalous(c: &mut Criterion) {
    let mut forecaster = Forecaster::new(ForecastMethod::LinearRegression);

    // Add historical data
    for i in 0..100 {
        forecaster.add_sample((i as f64) * 2.0 + 50.0);
    }

    c.bench_function("forecasting_is_anomalous", |b| {
        b.iter(|| {
            let _ = forecaster.is_anomalous(black_box(2.0));
        });
    });
}

/// Benchmark confidence calculation.
fn bench_confidence(c: &mut Criterion) {
    let mut forecaster = Forecaster::new(ForecastMethod::LinearRegression);

    // Add historical data
    for i in 0..100 {
        forecaster.add_sample((i as f64) * 2.0 + (i as f64 * 0.1).sin() * 10.0);
    }

    c.bench_function("forecasting_confidence", |b| {
        b.iter(|| {
            let _ = forecaster.confidence();
        });
    });
}

/// Benchmark with different history sizes.
fn bench_history_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("forecasting_history_size");

    for max_samples in [10, 50, 100, 500, 1000] {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("history_{}", max_samples)),
            &max_samples,
            |b, &hist_size| {
                b.iter(|| {
                    let mut forecaster =
                        Forecaster::with_config(ForecastMethod::LinearRegression, hist_size, 0.3);

                    // Fill history
                    for i in 0..hist_size {
                        forecaster.add_sample((i as f64) * 2.0);
                    }

                    // Forecast
                    let _ = forecaster.forecast(5);
                });
            },
        );
    }

    group.finish();
}

/// Benchmark bulk forecasting operations.
fn bench_bulk_forecast(c: &mut Criterion) {
    let mut group = c.benchmark_group("forecasting_bulk");

    for count in [10, 100, 1000] {
        group.throughput(Throughput::Elements(count as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}_forecasts", count)),
            &count,
            |b, &cnt| {
                let mut forecaster = Forecaster::new(ForecastMethod::LinearRegression);

                // Add historical data
                for i in 0..100 {
                    forecaster.add_sample((i as f64) * 2.0);
                }

                b.iter(|| {
                    for i in 1..=cnt {
                        let _ = forecaster.forecast(i);
                    }
                });
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_add_sample,
    bench_add_samples,
    bench_forecast_methods,
    bench_forecast_periods,
    bench_time_to_capacity,
    bench_growth_rate,
    bench_sample_count,
    bench_is_anomalous,
    bench_confidence,
    bench_history_sizes,
    bench_bulk_forecast
);
criterion_main!(benches);
