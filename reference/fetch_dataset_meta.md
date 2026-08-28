# Fetch nrows/ncols for a vector of dataset ids concurrently via curl's multi-handle pool.

A single call to `/size` per dataset is enough. First the `configs[]`
array is checked: if the dataset does not have exactly one config,
nrows/ncols are both NA. If it does have exactly one config, `nrows` is
computed by summing `num_rows` across all of that config's entries in
the `splits[]` array (rather than trusting the config-level aggregate
directly), and `ncols` is read from `num_columns` on one of those splits
(column count doesn't vary across splits of the same config).

## Usage

``` r
fetch_dataset_meta(ids, max_concurrent = 10, timeout = 30)
```

## Arguments

- ids:

  Character vector of dataset ids, e.g. "google/dataset-one".

- max_concurrent:

  Integer. Max simultaneous connections in the pool.

- timeout:

  Numeric. Per-request timeout in seconds.

## Value

A data.table with columns: id, nrows, ncols.

## Details

If a dataset has zero or more than one config, both nrows and ncols are
set to NA – there's no single unambiguous row/column count to report in
that case.
