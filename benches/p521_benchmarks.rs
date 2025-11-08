use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use hpcrypt_curves::p521::{Point, Scalar, FieldElement};

fn field_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("p521_field");

    let a = FieldElement::from_bytes(&[0x42u8; 66]).unwrap();
    let b = FieldElement::from_bytes(&[0x43u8; 66]).unwrap();

    group.bench_function("add", |bench| {
        bench.iter(|| {
            black_box(a.add(&b))
        })
    });

    group.bench_function("sub", |bench| {
        bench.iter(|| {
            black_box(a.sub(&b))
        })
    });

    group.bench_function("mul", |bench| {
        bench.iter(|| {
            black_box(a.mul(&b))
        })
    });

    group.bench_function("square", |bench| {
        bench.iter(|| {
            black_box(a.square())
        })
    });

    group.bench_function("invert", |bench| {
        bench.iter(|| {
            black_box(a.invert())
        })
    });

    group.finish();
}

fn scalar_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("p521_scalar");

    let a = Scalar::from_bytes(&[0x42u8; 66]);
    let b = Scalar::from_bytes(&[0x43u8; 66]);

    group.bench_function("add", |bench| {
        bench.iter(|| {
            black_box(a.add(&b))
        })
    });

    group.bench_function("mul", |bench| {
        bench.iter(|| {
            black_box(a.mul(&b))
        })
    });

    group.bench_function("invert", |bench| {
        bench.iter(|| {
            black_box(a.invert())
        })
    });

    group.finish();
}

fn point_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("p521_point");

    let g = Point::generator();
    let s1 = Scalar::from_bytes(&[0x42u8; 66]);
    let s2 = Scalar::from_bytes(&[0x43u8; 66]);
    let p1 = g.scalar_mul(&s1);
    let p2 = g.scalar_mul(&s2);

    group.bench_function("add", |bench| {
        bench.iter(|| {
            black_box(p1.add(&p2))
        })
    });

    group.bench_function("double", |bench| {
        bench.iter(|| {
            black_box(p1.double())
        })
    });

    group.bench_function("to_affine", |bench| {
        bench.iter(|| {
            black_box(p1.to_affine())
        })
    });

    group.finish();
}

fn scalar_multiplication(c: &mut Criterion) {
    let mut group = c.benchmark_group("p521_scalar_mul");

    let g = Point::generator();
    let scalar = Scalar::from_bytes(&[0x42u8; 66]);
    let scalar2 = Scalar::from_bytes(&[0x43u8; 66]);

    group.bench_function("generator_variable_time", |bench| {
        bench.iter(|| {
            black_box(g.scalar_mul(&scalar))
        })
    });

    // Arbitrary point multiplication
    let p = g.scalar_mul(&scalar2);

    group.bench_function("arbitrary_point_variable_time", |bench| {
        bench.iter(|| {
            black_box(p.scalar_mul(&scalar))
        })
    });

    group.finish();
}

fn karatsuba_impact(c: &mut Criterion) {
    let mut group = c.benchmark_group("p521_karatsuba_analysis");

    let a = FieldElement::from_bytes(&[0x42u8; 66]).unwrap();
    let b = FieldElement::from_bytes(&[0x43u8; 66]).unwrap();

    // Multiplication uses Karatsuba (after our optimization)
    group.bench_function("mul_with_karatsuba", |bench| {
        bench.iter(|| {
            black_box(a.mul(&b))
        })
    });

    // Squaring uses optimized schoolbook
    group.bench_function("square_optimized", |bench| {
        bench.iter(|| {
            black_box(a.square())
        })
    });

    // Compare with naive squaring (mul(a, a))
    group.bench_function("square_via_mul", |bench| {
        bench.iter(|| {
            black_box(a.mul(&a))
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    field_operations,
    scalar_operations,
    point_operations,
    scalar_multiplication,
    karatsuba_impact,
);
criterion_main!(benches);
