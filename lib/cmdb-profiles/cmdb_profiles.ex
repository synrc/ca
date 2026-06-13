defmodule CA.PRO do
  @moduledoc """
  Функції доступу до інвентарів судів для КСЗІ (cmdb-profile).
  Призначений для простого й ідіоматичного пошуку категорій та конкретних серійних номерів (інвентарних номерів)
  по всіх профілях без використання макросів.
  """

  @inventory_modules [
    {CA.HW, :erp, :hw},
    {CA.Sys, :erp, :sys}
  ]

  @process_modules [
    {CA.Proc, :erp}
  ]

  @data_modules [
    {CA.Data, :erp}
  ]

  # --- API ДЛЯ КАТЕГОРІЙ ІНВЕНТАРЯ (HW / SYS) ---

  @doc """
  Отримати всі категорії інвентаря по всіх судах та профілях.
  Додає метадані: `:court`, `:inventory_type`, `:category_key`.
  """
  def list_categories do
    # 1. Base Inventory Modules (HW / Sys)
    inventory_items =
      for {mod, court, type} <- @inventory_modules,
          {category_key, items} <- mod.inventory(),
          item <- items do
        item
        |> Map.put(:court, court)
        |> Map.put(:inventory_type, type)
        |> Map.put(:category_key, category_key)
      end

    # 2. Net Modules (zones)
    net_items =
      for {mod, court} <- [
            {CA.Net, :erp}
          ],
          {category_key, zones} <- mod.zones(),
          zone <- zones do
        zone
        |> Map.put(:court, court)
        |> Map.put(:inventory_type, :net)
        |> Map.put(:category_key, category_key)
      end

    # 3. Risk Modules (taxonomy)
    risk_items =
      for {mod, court} <- [
            {CA.Risk, :erp}
          ],
          {category_key, risks} <- mod.taxonomy(),
          risk <- risks do
        risk
        |> Map.put(:court, court)
        |> Map.put(:inventory_type, :risk)
        |> Map.put(:category_key, category_key)
      end

    # 4. Data Modules (classification)
    data_items =
      for {mod, court} <- [
            {CA.Data, :erp}
          ],
          {category_key, classifications} <- mod.classification(),
          data <- classifications do
        data
        |> Map.put(:court, court)
        |> Map.put(:inventory_type, :data)
        |> Map.put(:category_key, category_key)
      end

    # 5. ABAC Modules (roles)
    abac_items =
      for {mod, court} <- [
            {CA.ABAC, :erp}
          ],
          {category_key, roles} <- mod.roles(),
          role <- roles do
        role
        |> Map.put(:court, court)
        |> Map.put(:inventory_type, :abac)
        |> Map.put(:category_key, category_key)
      end

    # 6. Process Modules (processes)
    process_items =
      for {mod, court} <- @process_modules,
          {category_key, processes} <- mod.processes(),
          process <- processes do
        process
        |> Map.put(:court, court)
        |> Map.put(:inventory_type, :process)
        |> Map.put(:category_key, category_key)
      end

    inventory_items ++ net_items ++ risk_items ++ data_items ++ abac_items ++ process_items
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
        {process_key, processes} <- mod.processes(),
        process <- processes do
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
        {class_key, classifications} <- mod.classification(),
        class <- classifications do
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
  Отримати фізичний HW-інвентар (instances) для COURT, COD або ERP.
  Показує лише апаратні екземпляри з полями: id, inventory_num, model, location, status.
  """
  def inventory(court_str) do
    court = parse_court(court_str)
    width = terminal_width()

    # overhead for print formatting: `{"", "", "", "", ""}` -> ~18 chars
    overhead = 18

    hw_mod = case court do
      :erp      -> CA.HW
    end

    for {_key, groups} <- hw_mod.inventory(),
        group <- groups,
        inst <- Map.get(group, :instances, []) do
      id = inst.id
      inv_num = Map.get(inst, :inventory_num, "")
      model_raw = Map.get(inst, :model, Map.get(inst, :name, ""))
      used_width = String.length(id) + String.length(inv_num) + overhead
      model_width = max(15, width - used_width)
      model = format_string(model_raw, model_width)
      {id, inv_num, model}
    end
  end

  @doc """
  Отримати всі ризики для COURT або COD у вигляді Erlang-кортежів.
  """
  def risk(court_str) do
    court = parse_court(court_str)
    width = terminal_width()

    risk_mod = case court do
      :erp -> CA.Risk
    end

    # overhead for print formatting: `{"", "", []}` -> ~14 chars
    overhead = 14

    for {_key, groups} <- risk_mod.taxonomy(),
        group <- groups,
        inst <- Map.get(group, :instances, []) do
      id = inst.id
      controls_str = Enum.join(Map.get(inst, :controls, []), ",")
      name_raw = Map.get(inst, :name, "")
      used_width = String.length(id) + String.length(controls_str) + overhead
      name_width = max(10, width - used_width)
      name = format_string(name_raw, name_width)
      {id, name, Map.get(inst, :controls, [])}
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

    sys_mod = case court do
      :erp -> CA.Sys
    end

    for {_key, groups} <- sys_mod.inventory(),
        group <- groups,
        inst <- Map.get(group, :instances, []) do
      id = inst.id
      controls_str = Enum.join(Map.get(inst, :controls, []), ",")
      version_suffix =
        case Map.get(inst, :version) do
          nil -> ""
          "" -> ""
          "N/A" -> ""
          version -> " (" <> version <> ")"
        end
      name_raw = Map.get(inst, :name, "") <> version_suffix
      used_width = String.length(id) + String.length(controls_str) + overhead
      name_width = max(10, width - used_width)
      name = format_string(name_raw, name_width)
      {id, name, Map.get(inst, :controls, [])}
    end
  end

  @doc """
  Отримати мережеві інстанси (NET) для COURT або COD у вигляді Erlang-кортежів.
  Розгортає :instances всередині кожної зони (аналогічно до inventory/1).
  """
  def net(court_str) do
    court = parse_court(court_str)
    width = terminal_width()

    # overhead: {id, name, subnet} -> ~16 chars
    overhead = 16

    net_mod = case court do
      :erp -> CA.Net
    end

    for {_key, zones} <- net_mod.zones(),
        zone <- zones,
        inst <- Map.get(zone, :instances, []) do
      id = inst.id
      subnet = Map.get(inst, :subnet, "")
      name_raw = Map.get(inst, :name, "")
      used_width = String.length(id) + String.length(subnet) + overhead
      name_width = max(10, width - used_width)
      name = format_string(name_raw, name_width)
      {id, name, subnet}
    end
  end

  @doc """
  Отримати бізнес-процеси (PROC) для COURT або COD — розгортає :instances кожної групи.
  """
  def proc(court_str) do
    court = parse_court(court_str)
    width = terminal_width()
    overhead = 16

    proc_mod = case court do
      :erp -> CA.Proc
    end

    for {_key, groups} <- proc_mod.processes(),
        group <- groups,
        inst <- Map.get(group, :instances, []) do
      id = inst.id
      owner = Map.get(inst, :owner, "")
      name_raw = Map.get(inst, :name, "")
      used_width = String.length(id) + String.length(owner) + overhead
      name_width = max(10, width - used_width)
      name = format_string(name_raw, name_width)
      {id, name, owner}
    end
  end

  @doc """
  Отримати класифікацію даних (DATA) для COURT або COD — розгортає :instances кожної групи.
  """
  def data(court_str) do
    court = parse_court(court_str)
    width = terminal_width()
    overhead = 16

    data_mod = case court do
      :erp -> CA.Data
    end

    for {_key, groups} <- data_mod.classification(),
        group <- groups,
        inst <- Map.get(group, :instances, []) do
      id = inst.id
      storage = Map.get(inst, :storage, "")
      name_raw = Map.get(inst, :name, "")
      used_width = String.length(id) + String.length(storage) + overhead
      name_width = max(10, width - used_width)
      name = format_string(name_raw, name_width)
      {id, name, storage}
    end
  end

  @doc """
  Отримати ролі доступу (ROLES) для COURT або COD — розгортає :instances кожної групи.
  """
  def roles(court_str) do
    court = parse_court(court_str)
    width = terminal_width()
    overhead = 16

    abac_mod = case court do
      :erp -> CA.ABAC
    end

    for {_key, groups} <- abac_mod.roles(),
        group <- groups,
        inst <- Map.get(group, :instances, []) do
      id = inst.id
      users_str = Map.get(inst, :users, []) |> Enum.join(", ")
      name_raw = Map.get(inst, :name, "")
      used_width = String.length(id) + String.length(users_str) + overhead
      name_width = max(10, width - used_width)
      name = format_string(name_raw, name_width)
      {id, name, Map.get(inst, :users, [])}
    end
  end

  # --- ВНУТРІШНІ ДОПОМІЖНІ ФУНКЦІЇ ФОРМАТУВАННЯ ---

  defp parse_court(court) when court in [:cod, :vyshhorod, :erp], do: court
  defp parse_court(court) when is_binary(court) do
    case String.downcase(court) do
      "cod" -> :cod
      "court" -> :vyshhorod
      "vyshhorod" -> :vyshhorod
      "erp" -> :erp
      _ -> raise ArgumentError, "Unknown court: #{inspect(court)}. Expected 'COD', 'COURT' or 'ERP'"
    end
  end

  def terminal_width do
    width = case :io.columns() do
      {:ok, w} when w > 0 -> w + 50
      _ -> 200
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
