# List Datasets from Hugging Face Hub

Query datasets hosted on <https://huggingface.co/datasets> via the
Hugging Face Hub API, returning metadata such as dataset id, gated
status, and download counts.

## Usage

``` r
list_datasets(
  num_of_dataset = 100,
  chunk_size = 100,
  search = NULL,
  author = NULL,
  fetch_meta = TRUE,
  max_concurrent = 10,
  ...
)
```

## Arguments

- num_of_dataset:

  (`integer(1)`)  
  Total number of records to retrieve. Must be a positive integer.
  Default is `100`.

- chunk_size:

  (`integer(1)`)  
  Number of records to request per API call. Default is `100`.

- search:

  (`character(1)`)  
  Optional search keyword to filter datasets by. Default is `NULL`.

- author:

  (`character(1)`)  
  Optional author/organization name to filter datasets by. Default is
  `NULL`.

- fetch_meta:

  (`logical(1)`)  
  If `TRUE` (default), also fetches `nrows` and `ncols` for each dataset
  via
  [`fetch_dataset_meta()`](https://mlr-org.github.io/mlr3hf/reference/fetch_dataset_meta.md).
  If `FALSE`, skips this extra network call and returns only `id`,
  `gated`, `downloads`.

- max_concurrent:

  (`integer(1)`)  
  Maximum number of simultaneous connections used when fetching
  metadata. Default is `10`.

- ...:

  Additional arguments passed on to `get_with_retry()`, e.g.
  `max_retries`.

## Value

(`data.table()`) of results with columns `id`, `nrows`, and `ncols` or
an empty `data.table()` if no datasets are found.

## References

<https://huggingface.co/docs/hub/api>

## Examples

``` r
if (FALSE) { # \dontrun{
dat <- list_datasets(num_of_dataset = 50)
dat <- list_datasets(num_of_dataset = 500, chunk_size = 100)
dat <- list_datasets(author = "a4n9i")
} # }
```
