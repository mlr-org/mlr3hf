backend_hfhub <- function(path, primary_key = NULL, target = NULL, ...) {
  ext <- tolower(tools::file_ext(path))

  data <- switch(ext,
    "csv"     = utils::read.csv(path, stringsAsFactors = FALSE),
    "parquet" = arrow::read_parquet(path),
    "tsv"     = utils::read.csv(path, sep = "\t", stringsAsFactors = FALSE),
    cli::cli_abort("current not supporting for your given format: {ext}")
  )

  data <- as.data.frame(data)
  data <- data.table::as.data.table(data)

  if (is.null(primary_key)) {
    primary_key <- "mlr3_row_id"
    data.table::set(data, j = primary_key, value = seq_len(nrow(data)))
  } else {
    if (!primary_key %in% names(data)) {
      cli::cli_abort("Column '{primary_key}' not found in data")
    }
  }

  mlr3::as_data_backend(data, primary_key = primary_key)
}