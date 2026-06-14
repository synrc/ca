defmodule FamilyDescGenerator do
  def run do
    all_specs = CA.Profile.Data.specs()

    # Filter only top-level families and main controls (no sub-controls like AC-2(1))
    _specs_by_id = Map.new(all_specs, &{&1.id, &1})

    families =
      all_specs
      |> Enum.filter(fn spec ->
        parts = String.split(to_string(spec.id), "-")
        # e.g. "id-spe-ac"
        length(parts) == 3
      end)

    controls =
      all_specs
      |> Enum.filter(fn spec ->
        parts = String.split(to_string(spec.id), "-")
        # e.g. "id-spe-ac-1" and "id-spe-ac-1-1"
        length(parts) >= 4
      end)
      |> Enum.group_by(fn spec ->
        parts = String.split(to_string(spec.id), "-")
        "id-spe-#{Enum.at(parts, 2)}" |> String.to_atom()
      end)

    output =
      families
      |> Enum.map(fn fam_spec ->
        family_atom = fam_spec.id
        family_title = fam_spec.title
        family_name = String.split(to_string(family_atom), "-") |> Enum.at(2) |> String.upcase()

        children = Map.get(controls, family_atom, [])

        children_titles =
          children
          |> Enum.sort_by(fn spec ->
            spec.id
            |> to_string()
            |> String.split("-")
            |> Enum.drop(3)
            |> Enum.map(fn part ->
              case Integer.parse(part) do
                {num, _rest} -> num
                :error -> 999
              end
            end)
          end)
          |> Enum.map(fn child ->
            short_title = String.split(child.title, " - ", parts: 2) |> List.last()
            parts = String.split(short_title, " (")

            if length(parts) == 2 do
              base = List.first(parts) |> String.downcase() |> String.capitalize()
              "#{base} (#{List.last(parts)}"
            else
              String.capitalize(String.slice(short_title, 0, 1)) <>
                String.slice(short_title, 1..-1//1)
            end
          end)

        children_text =
          if children_titles == [] do
            "не містить визначених заходів."
          else
            "включає такі заходи захисту: " <> Enum.join(children_titles, "; ") <> "."
          end

        "Клас заходів захисту #{family_name} — #{family_title} #{children_text}"
      end)
      |> Enum.join("\n\n")

    File.write!("family_descriptions.txt", output)
    IO.puts("Generated family_descriptions.txt")
  end
end

#FamilyDescGenerator.run()
