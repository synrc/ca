defmodule Param do
  def run do
    specs = CA.Profile.Data.specs()

    # 1. Long descriptions (> 500 characters)
    long_params =
      Enum.flat_map(specs, fn spec ->
        Enum.flat_map(spec.parameters, fn
          {name, desc, _} -> if String.length(desc) > 500, do: [{spec.id, name, desc}], else: []
          {name, desc} -> if String.length(desc) > 500, do: [{spec.id, name, desc}], else: []
          _ -> []
        end)
      end)

    # 2. Duplicate keys inside the same spec
    duplicate_params =
      Enum.flat_map(specs, fn spec ->
        keys = Enum.map(spec.parameters, fn
          {name, _, _} -> name
          {name, _} -> name
          _ -> nil
        end) |> Enum.reject(&is_nil/1)
        
        dups = keys -- Enum.uniq(keys) |> Enum.uniq()
        if length(dups) > 0 do
          Enum.map(dups, fn dup -> {spec.id, dup} end)
        else
          []
        end
      end)

    # 3. PDF hyphen-space artifacts (e.g., "обліко- вих")
    hyphen_space_params =
      Enum.flat_map(specs, fn spec ->
        Enum.flat_map(spec.parameters, fn
          {name, desc, _} -> if Regex.match?(~r/\p{L}-\s+\p{L}/u, desc), do: [{spec.id, name, desc}], else: []
          {name, desc} -> if Regex.match?(~r/\p{L}-\s+\p{L}/u, desc), do: [{spec.id, name, desc}], else: []
          _ -> []
        end)
      end)

    # 4. Double semicolons (";;")
    double_semicolon_params =
      Enum.flat_map(specs, fn spec ->
        Enum.flat_map(spec.parameters, fn
          {name, desc, _} -> if String.contains?(desc, ";;"), do: [{spec.id, name, desc}], else: []
          {name, desc} -> if String.contains?(desc, ";;"), do: [{spec.id, name, desc}], else: []
          _ -> []
        end)
      end)

    # 5. Trailing or embedded layout numbers (e.g., page numbers like "388" at the end of clauses)
    layout_number_params =
      Enum.flat_map(specs, fn spec ->
        Enum.flat_map(spec.parameters, fn
          {name, desc, _} -> if Regex.match?(~r/\s\d+(\s|$)/, desc), do: [{spec.id, name, desc}], else: []
          {name, desc} -> if Regex.match?(~r/\s\d+(\s|$)/, desc), do: [{spec.id, name, desc}], else: []
          _ -> []
        end)
      end)

    IO.puts("=== PARAMETER QUALITY AUDIT REPORT ===\n")
    IO.puts("1. Parameters with description > 500 characters: #{length(long_params)}")
    IO.puts("2. Specs containing duplicate parameter keys: #{length(Enum.uniq(Enum.map(duplicate_params, &elem(&1, 0))))}")
    IO.puts("3. Parameters with PDF hyphenation space artifacts (e.g., 'обліко- вих'): #{length(hyphen_space_params)}")
    IO.puts("4. Parameters with double semicolons (';;'): #{length(double_semicolon_params)}")
    IO.puts("5. Parameters with leaked PDF page/layout numbers: #{length(layout_number_params)}\n")

    IO.puts("--- DUPLICATE PARAMETER KEYS (SAMPLE) ---")
    Enum.take(duplicate_params, 15)
    # Group duplicates by spec
    |> Enum.group_by(&elem(&1, 0), &elem(&1, 1))
    |> Enum.each(fn {spec_id, dup_keys} ->
      IO.puts("Spec ID: #{spec_id} -> Duplicate Keys: #{inspect(dup_keys)}")
    end)
    IO.puts("")

    IO.puts("--- PDF HYPHENATION SPACE ARTIFACTS (SAMPLE) ---")
    Enum.take(hyphen_space_params, 10)
    |> Enum.each(fn {spec_id, name, desc} ->
      match = Regex.run(~r/\p{L}-\s+\p{L}/u, desc)
      IO.puts("Spec ID: #{spec_id} | Param: #{name} | Artifact: #{inspect(match)}")
      IO.puts("Context: #{desc}\n")
    end)

    IO.puts("--- DOUBLE SEMICOLONS (SAMPLE) ---")
    Enum.take(double_semicolon_params, 5)
    |> Enum.each(fn {spec_id, name, desc} ->
      IO.puts("Spec ID: #{spec_id} | Param: #{name}")
      IO.puts("Context: #{desc}\n")
    end)

    IO.puts("--- LEAKED PDF PAGE/LAYOUT NUMBERS (SAMPLE) ---")
    Enum.take(layout_number_params, 10)
    |> Enum.each(fn {spec_id, name, desc} ->
      match = Regex.run(~r/\s\d+(\s|$)/, desc)
      IO.puts("Spec ID: #{spec_id} | Param: #{name} | Leaked Number: #{inspect(match)}")
      IO.puts("Context: #{desc}\n")
    end)
  end
end

