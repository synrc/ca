defmodule CA.PRO do
  @moduledoc """
  Функції доступу до інвентарів судів для КСЗІ (cmdb-profile).
  Призначений для простого й ідіоматичного пошуку категорій та конкретних серійних номерів (інвентарних номерів)
  по всіх профілях без використання макросів.
  """

  @inventory_modules [
    {CA.CmdbProfiles.Cod.HW, :cod, :hw},
    {CA.CmdbProfiles.Cod.Sys, :cod, :sys},
    {CA.CmdbProfiles.Vyshhorod.HW, :vyshhorod, :hw},
    {CA.CmdbProfiles.Vyshhorod.Sys, :vyshhorod, :sys}
  ]

  @process_modules [
    {CA.CmdbProfiles.Cod.Proc, :cod},
    {CA.CmdbProfiles.Vyshhorod.Proc, :vyshhorod}
  ]

  @data_modules [
    {CA.CmdbProfiles.Cod.Data, :cod},
    {CA.CmdbProfiles.Vyshhorod.Data, :vyshhorod}
  ]

  # --- API ДЛЯ КАТЕГОРІЙ ІНВЕНТАРЯ (HW / SYS) ---

  @doc """
  Отримати всі категорії інвентаря по всіх судах та профілях.
  Додає метадані: `:court`, `:inventory_type`, `:category_key`.
  """
  def list_categories do
    for {mod, court, type} <- @inventory_modules,
        {category_key, items} <- mod.inventory(),
        item <- items do
      item
      |> Map.put(:court, court)
      |> Map.put(:inventory_type, type)
      |> Map.put(:category_key, category_key)
    end
  end

  @doc """
  Отримати конкретну категорію за її ID (наприклад, "HW-SRV-01" або "SYS-OS-01").
  """
  def get_category(category_id) do
    list_categories()
    |> Enum.find(fn cat -> cat.id == category_id end)
  end

  @doc """
  Пошук категорій за довільними фільтрами (map, keyword list або функція-предикат).
  """
  def search_categories(filters) do
    list_categories()
    |> Enum.filter(&matches_filters?(&1, filters))
  end

  # --- API ДЛЯ КОНКРЕТНИХ ЕКЗЕМПЛЯРІВ (INSTANCES) ---

  @doc """
  Отримати всі конкретні екземпляри обладнання/активів (instances) по всіх категоріях.
  Додає метадані: `:court`, `:inventory_type`, `:category_id`, `:category_key`.
  """
  def list_instances do
    for cat <- list_categories(),
        instance <- Map.get(cat, :instances, []) do
      instance
      |> Map.put(:court, cat.court)
      |> Map.put(:inventory_type, cat.inventory_type)
      |> Map.put(:category_id, cat.id)
      |> Map.put(:category_key, cat.category_key)
    end
  end

  @doc """
  Отримати конкретний екземпляр за його ID (наприклад, "COD-SRV-01") або
  інвентарним/серійним номером (наприклад, "47850001", "101890577").
  """
  def get_instance(id_or_serial) do
    list_instances()
    |> Enum.find(fn inst ->
      inst.id == id_or_serial or Map.get(inst, :inventory_num) == id_or_serial
    end)
  end

  @doc """
  Пошук екземплярів за довільними фільтрами (map, keyword list або функція-предикат).
  """
  def search_instances(filters) do
    list_instances()
    |> Enum.filter(&matches_filters?(&1, filters))
  end

  # --- API ДЛЯ БІЗНЕС-ПРОЦЕСІВ ---

  @doc """
  Отримати всі процеси по всіх судах.
  """
  def list_processes do
    for {mod, court} <- @process_modules,
        {process_key, process} <- mod.processes() do
      process
      |> Map.put(:court, court)
      |> Map.put(:process_key, process_key)
    end
  end

  @doc """
  Отримати процес за його ID (наприклад, "P-DOC").
  """
  def get_process(process_id) do
    list_processes()
    |> Enum.find(fn proc -> proc.id == process_id end)
  end

  @doc """
  Пошук процесів за фільтрами.
  """
  def search_processes(filters) do
    list_processes()
    |> Enum.filter(&matches_filters?(&1, filters))
  end

  # --- API ДЛЯ КЛАСИФІКАЦІЇ ДАНИХ ---

  @doc """
  Отримати всі класифікації даних по всіх судах.
  """
  def list_classifications do
    for {mod, court} <- @data_modules,
        {class_key, class} <- mod.classification() do
      class
      |> Map.put(:court, court)
      |> Map.put(:classification_key, class_key)
    end
  end

  @doc """
  Отримати класифікацію за її ID (наприклад, "D-PUB").
  """
  def get_classification(class_id) do
    list_classifications()
    |> Enum.find(fn class -> class.id == class_id end)
  end

  @doc """
  Пошук класифікацій за фільтрами.
  """
  def search_classifications(filters) do
    list_classifications()
    |> Enum.filter(&matches_filters?(&1, filters))
  end

  # --- ЗРУЧНИЙ ВИСВІТЛЕННЯ ДЛЯ IEx (З АВТОШИРИНОЮ ТЕРМІНАЛУ) ---

  @doc """
  Отримати всі категорії для COURT або COD у вигляді Erlang-кортежів,
  що автоналаштовують свою ширину під ширину терміналу IEx для зручного читання.
  """
  def categories(court_str) do
    court = parse_court(court_str)
    width = terminal_width()

    # overhead for print formatting: `{"", "", []}` -> ~14 chars
    overhead = 14

    for cat <- search_categories(court: court) do
      id = cat.id
      controls_str = Enum.join(cat.controls, ",")
      name_width = max(10, width - String.length(id) - String.length(controls_str) - overhead)
      name = format_string(cat.name, name_width)
      {id, name, cat.controls}
    end
  end

  @doc """
  Отримати весь інвентар (instances) для COURT або COD у вигляді Erlang-кортежів.
  """
  def inventory(court_str) do
    court = parse_court(court_str)
    width = terminal_width()

    # overhead for print formatting: `{"", "", "", "", ""}` -> ~18 chars
    overhead = 18

    for inst <- search_instances(court: court) do
      id = inst.id
      inv_num = Map.get(inst, :inventory_num) || ""
      status = Map.get(inst, :status) || ""
      location = Map.get(inst, :location) || ""

      model_raw = Map.get(inst, :model) || Map.get(inst, :name) || ""

      used_width = String.length(id) + String.length(inv_num) + String.length(status) + String.length(location) + overhead
      model_width = max(15, width - used_width)
      model = format_string(model_raw, model_width)

      {id, inv_num, model, location, status}
    end
  end

  @doc """
  Отримати всі ризики для COURT або COD у вигляді Erlang-кортежів.
  """
  def risk(court_str) do
    court = parse_court(court_str)
    width = terminal_width()

    risk_mod = case court do
      :cod -> CA.CmdbProfiles.Cod.Risk
      :vyshhorod -> CA.CmdbProfiles.Vyshhorod.Risk
    end

    # overhead for print formatting: `{"", "", []}` -> ~14 chars
    overhead = 14

    for r <- flatten_risks(risk_mod.taxonomy()) do
      id = r.id
      controls_str = Enum.join(r.controls, ",")
      name_width = max(10, width - String.length(id) - String.length(controls_str) - overhead)
      name = format_string(r.name, name_width)
      {id, name, r.controls}
    end
  end

  @doc """
  Отримати системний софт (SYS інвентар) для COURT або COD у вигляді Erlang-кортежів.
  """
  def sys(court_str) do
    court = parse_court(court_str)
    width = terminal_width()

    # overhead for print formatting: `{"", "", []}` -> ~14 chars
    overhead = 14

    for cat <- search_categories(court: court, inventory_type: :sys) do
      id = cat.id
      controls_str = Enum.join(cat.controls, ",")
      name_width = max(10, width - String.length(id) - String.length(controls_str) - overhead)
      name = format_string(cat.name, name_width)
      {id, name, cat.controls}
    end
  end

  @doc """
  Отримати мережеве зонування (NET) для COURT або COD у вигляді Erlang-кортежів.
  """
  def net(court_str) do
    court = parse_court(court_str)
    width = terminal_width()
    overhead = 14

    net_mod = case court do
      :cod -> CA.CmdbProfiles.Cod.Net
      :vyshhorod -> CA.CmdbProfiles.Vyshhorod.Net
    end

    for {_key, zone} <- net_mod.zones() do
      id = zone.id
      controls_str = Enum.join(zone.controls, ",")
      name_width = max(10, width - String.length(id) - String.length(controls_str) - overhead)
      name = format_string(zone.name, name_width)
      {id, name, zone.controls}
    end
  end

  @doc """
  Отримати бізнес-процеси (PROC) для COURT або COD у вигляді Erlang-кортежів.
  """
  def proc(court_str) do
    court = parse_court(court_str)
    width = terminal_width()
    overhead = 14

    for p <- list_processes(), p.court == court do
      id = p.id
      controls_str = Enum.join(p.controls, ",")
      name_width = max(10, width - String.length(id) - String.length(controls_str) - overhead)
      name = format_string(p.name, name_width)
      {id, name, p.controls}
    end
  end

  @doc """
  Отримати класифікацію даних (DATA) для COURT або COD у вигляді Erlang-кортежів.
  """
  def data(court_str) do
    court = parse_court(court_str)
    width = terminal_width()
    overhead = 14

    for c <- list_classifications(), c.court == court do
      id = c.id
      controls_str = Enum.join(c.controls, ",")
      name_width = max(10, width - String.length(id) - String.length(controls_str) - overhead)
      name = format_string(c.name, name_width)
      {id, name, c.controls}
    end
  end

  @doc """
  Отримати ролі доступу (ROLES) для COURT або COD у вигляді Erlang-кортежів.
  """
  def roles(court_str) do
    court = parse_court(court_str)
    width = terminal_width()
    overhead = 14

    abac_mod = case court do
      :cod -> CA.CmdbProfiles.Cod.ABAC
      :vyshhorod -> CA.CmdbProfiles.Vyshhorod.ABAC
    end

    for {_key, role} <- abac_mod.roles() do
      id = role.id
      controls_str = Enum.join(role.controls, ",")
      name_width = max(10, width - String.length(id) - String.length(controls_str) - overhead)
      name = format_string(role.name, name_width)
      {id, name, role.controls}
    end
  end

  # --- ВНУТРІШНІ ДОПОМІЖНІ ФУНКЦІЇ ФОРМАТУВАННЯ ---

  defp parse_court(court) when court in [:cod, :vyshhorod], do: court
  defp parse_court(court) when is_binary(court) do
    case String.downcase(court) do
      "cod" -> :cod
      "court" -> :vyshhorod
      "vyshhorod" -> :vyshhorod
      _ -> raise ArgumentError, "Unknown court: #{inspect(court)}. Expected 'COD' or 'COURT'"
    end
  end

  defp terminal_width do
    width = case :io.columns() do
      {:ok, w} when w > 0 -> w
      _ -> 120
    end

    if Process.whereis(IEx.Config) do
      IEx.configure(
        inspect: [
          limit: :infinity,
          printable_limit: :infinity,
          width: width
        ],
        colors: [
          eval_result: [:cyan, :bright],
          eval_info: [:yellow],
          eval_error: [:red, :bright]
        ]
      )
    end

    width
  end

  defp format_string(str, max_len) do
    str = String.replace(str, "\n", " ") |> String.trim()
    if String.length(str) > max_len do
      len = max(0, max_len - 3)
      String.slice(str, 0, len) <> "..."
    else
      str
    end
  end

  defp flatten_risks(map) when is_map(map) do
    if Map.has_key?(map, :id) and Map.has_key?(map, :name) do
      [map]
    else
      Enum.flat_map(map, fn {_k, v} -> flatten_risks(v) end)
    end
  end
  defp flatten_risks(list) when is_list(list) do
    Enum.flat_map(list, &flatten_risks/1)
  end
  defp flatten_risks(_), do: []

  # --- ДОПОМІЖНІ ФУНКЦІЇ ФІЛЬТРАЦІЇ ---

  # Фільтрація за допомогою анонімної функції-предиката
  defp matches_filters?(item, filters) when is_function(filters, 1) do
    filters.(item)
  end

  # Фільтрація за списком пар ключ-значення (Map або Keyword list)
  defp matches_filters?(item, filters) when is_list(filters) or is_map(filters) do
    Enum.all?(filters, fn {key, val} ->
      case Map.fetch(item, key) do
        {:ok, item_val} -> match_value?(item_val, val)
        _ -> false
      end
    end)
  end

  defp match_value?(item_val, val) when is_list(item_val) do
    if is_list(val) do
      Enum.all?(val, &(&1 in item_val))
    else
      val in item_val
    end
  end

  defp match_value?(item_val, val), do: item_val == val
end
