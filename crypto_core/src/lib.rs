use pyo3::prelude::*;

/// Temporary stub so we can verify the PyO3 bridge works.
/// Day 2 replaces this with the first real crypto benchmarks.
#[pyfunction]
fn add(left: u64, right: u64) -> PyResult<u64> {
    Ok(left + right)
}

#[pymodule]
fn crypto_core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(add, m)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2).unwrap();
        assert_eq!(result, 4);
    }
}
