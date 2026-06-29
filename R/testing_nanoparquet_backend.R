nano_parquet <- function(path, primary_key = NULL, ...) {
  requireNamespace("mlr3")

  dt <- lapply(path, nanoparquet::read_parquet)
  combined <- data.table::rbindlist(dt, use.names = TRUE, fill = TRUE)

  if (is.null(primary_key)) {
    primary_key <- "mlr3_row_id"
    combined[, (primary_key) := seq_len(.N)]
  } else {
    if (!primary_key %in% names(combined)) {
      stop(sprintf("Column '%s' not found", primary_key))
    }
    
    combined[, (primary_key) := as.integer(get(primary_key))]
  }

  backend <- mlr3::as_data_backend(
    data = combined,
    primary_key = primary_key
  )
  return(backend)
}