# Copyright 2022 Agile Data, Inc <code@mftlabs.io>

defmodule Database.Behaviour do
  @callback insert(collection :: String.t(), body:: map) :: {:ok, id :: String.t()} | {:error, any}
  @callback insert_with_id(collection :: String.t(), body:: map, id :: String.t()) :: :ok | {:error, any}
  @callback update(collection :: String.t(), body:: map, id :: String.t()) :: :ok | {:error, any}
  @callback delete(collection :: String.t(), clauses :: map) :: :ok | {:error, any}
  @callback delete_by_id(collection :: String.t(), id :: String.t()) :: :ok | {:error, any}
  @callback delete_one(collection :: String.t(), clauses :: map) :: :ok | {:error, any}

  @callback add_to_field(collection :: String.t(), body:: map, id :: String.t(), field :: String.t()) :: :ok | {:error, any}
  @callback add_to_field_with_id(collection :: String.t(), body:: map, id :: String.t(), field :: String.t(), fieldid :: String.t()) :: :ok | {:error, any}
  @callback update_in_field(collection :: String.t(), body:: map, id :: String.t(), field :: String.t(), idx :: String.t()) :: :ok | {:error, any}
  @callback delete_from_field(collection :: String.t(), body:: map, id :: String.t(), field :: String.t(), idx :: String.t()) :: :ok | {:error, any}

  @callback find_one(collection :: String.t(), clauses :: map, opts :: list) :: data :: map | {:error, any}
  @callback find_one_and_update(collection :: String.t(), clauses :: map, body:: map) :: :ok | {:error, any}
  @callback find(collection :: String.t(), clauses :: map, opts :: map) :: any | {:error, any}
  @callback find_by_id(collection :: String.t(), id :: String.t(), opts :: list) :: any | {:error, any}

  @callback get_rows(collection :: String.t(), queryParms :: map) :: any | {:error, any}
  @callback get_in_field(collection :: String.t(), id :: String.t(), field :: String.t(), idx :: String.t()) :: any | {:error, any}

  @callback bulk_insert(doc :: list) :: any | {:error, any}
  @callback bulk_perform(ops :: list, index :: String.t()) :: :ok | {:error, any}

  @callback delete_index(index :: String.t()) :: :ok | {:error, any}

  @callback aggregate_field(collection :: String.t(), field :: String.t()) :: result :: any | {:error, any}


end

