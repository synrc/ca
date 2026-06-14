defmodule Param do
  def run do
    specs = CA.Profile.Data.specs()
    long_params =
      Enum.flat_map(specs, fn spec ->
        Enum.flat_map(spec.parameters, fn
          {name, desc, _} ->
            len = String.length(desc)
            if len > 500 do
              [{spec.id, name, len, desc}]
            else
              []
            end
          {name, desc} ->
            len = String.length(desc)
            if len > 500 do
              [{spec.id, name, len, desc}]
            else
              []
            end
          _ -> []
        end)
      end)
      |> Enum.sort_by(fn {_, _, len, _} -> len end, :desc)
    IO.puts("Found #{length(long_params)} parameters with description > 500 characters.\n")
    Enum.each(Enum.take(long_params, 20), fn {spec_id, name, len, desc} ->
      IO.puts("Spec ID: #{spec_id}")
      IO.puts("Param: #{name}")
      IO.puts("Length: #{len}")
      IO.puts("Preview: #{String.slice(desc, 0, 100)}...\n")
    end)
  end
end

