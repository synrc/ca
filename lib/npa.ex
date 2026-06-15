defmodule CA.NPA do
  @moduledoc """
  Generates anonymized normative and legal act orders (накази) for enterprise security.
  """
  require EEx

  def gen_order_szi_establishment(opts \\ []) do
    defaults = [
      tryzub_def: CA.NPA.tryzub_def(),
      parent_org: "Державна судова адміністрація України",
      org_name: "Державне підприємство «Інформаційні судові системи»",
      city: "Київ",
      date: "30.01.2024",
      number: "18_ОД",
      system_name: "ЄСІКС",
      ciso_name: "Іван ПЕТРЕНКО",
      ciso_title: "начальник відділу інформаційної безпеки",
      director_name: "Василь ШЕВЧЕНКО",
      director_title: "Генеральний директор"
    ]
    render_order_template("order_szi_establishment", defaults, opts, "order_szi_establishment")
  end

  def gen_order_kszi_development(opts \\ []) do
    defaults = [
      tryzub_def: CA.NPA.tryzub_def(),
      parent_org: "Державна судова адміністрація України",
      org_name: "Державне підприємство «Інформаційні судові системи»",
      city: "Київ",
      date: "05.02.2024",
      number: "22_ОД",
      system_name: "ЄСІКС",
      developer_name: "ДП «УСС»",
      head_of_group: "Петро СИДОРЕНКО",
      survey_deadline: "20.02.2024",
      risk_deadline: "28.02.2024",
      director_name: "Василь ШЕВЧЕНКО",
      director_title: "Генеральний директор"
    ]
    render_order_template("order_kszi_development", defaults, opts, "order_kszi_development")
  end

  def gen_order_at_ir_ma_ps_pe(opts \\ []) do
    defaults = [
      tryzub_def: CA.NPA.tryzub_def(),
      parent_org: "Державна судова адміністрація України",
      org_name: "Державне підприємство «Інформаційні судові системи»",
      city: "Київ",
      date: "09.01.2023",
      number: "3_ОД",
      system_name: "ЄСІКС",
      ciso_name: "Дмитро КОВАЛЕНКО",
      ciso_title: "начальник відділу інформаційної безпеки",
      director_name: "Олексій ГРИЦЕНКО",
      director_title: "В. о. генерального директора"
    ]
    render_order_template("order_at_ir_ma_ps_pe", defaults, opts, "order_at_ir_ma_ps_pe")
  end

  def gen_order_admin_appointment(opts \\ []) do
    defaults = [
      tryzub_def: CA.NPA.tryzub_def(),
      parent_org: "Державна судова адміністрація України",
      org_name: "Державне підприємство «Інформаційні судові системи»",
      city: "Київ",
      date: "30.01.2024",
      number: "19_ОД",
      system_name: "ЄСІКС",
      pol_date: "09.01.2023",
      pol_num: "3_ОД",
      prev_date: "17.01.2023",
      prev_num: "08_ОД",
      ciso_name: "Дмитро КОВАЛЕНКО",
      director_name: "Микола МЕЛЬНИК",
      director_title: "Генеральний директор",
      domain_admins: [
        %{name: "Олександр ІВАНЕНКО", title: "начальник відділу адміністрування IT-інфраструктури"},
        %{name: "Юрій ПЕТРЕНКО", title: "адміністратор системи"},
        %{name: "Олександр СИДОРЕНКО", title: "інженер відділу адміністрування мереж"}
      ],
      network_admins: [
        %{name: "Михайло ДМИТРЕНКО", title: "адміністратор системи"},
        %{name: "Юрій ПЕТРЕНКО", title: "адміністратор системи"},
        %{name: "Олександр СИДОРЕНКО", title: "інженер"},
        %{name: "Андрій КОВАЛЬЧУК", title: "адміністратор системи"}
      ],
      app_admins: [
        %{name: "Олександр ІВАНЕНКО", title: "начальник відділу"},
        %{name: "Михайло ПАВЛЕНКО", title: "адміністратор системи"},
        %{name: "Петро КУЗЬМЕНКО", title: "директор департаменту"},
        %{name: "Олексій МОРОЗ", title: "начальник відділу СУБД"},
        %{name: "Олександр ЛЕБЕДЄВ", title: "фахівець з інформаційних технологій"},
        %{name: "Юрій ПЕТРЕНКО", title: "адміністратор системи"},
        %{name: "Олександр СИДОРЕНКО", title: "інженер"},
        %{name: "Андрій КОВАЛЬЧУК", title: "адміністратор системи"},
        %{name: "Роман ТКАЧЕНКО", title: "адміністратор бази даних"},
        %{name: "Іван КРАВЧЕНКО", title: "адміністратор бази даних"}
      ],
      db_admins: [
        %{name: "Петро КУЗЬМЕНКО", title: "директор департаменту"},
        %{name: "Олексій МОРОЗ", title: "начальник відділу СУБД"},
        %{name: "Роман ТКАЧЕНКО", title: "адміністратор бази даних"},
        %{name: "Іван КРАВЧЕНКО", title: "адміністратор бази даних"}
      ],
      security_admins: [
        %{name: "Євген РОМАНЕНКО", title: "начальник відділу адміністрування мереж"},
        %{name: "В'ячеслав БОЙКО", title: "адміністратор системи відділу інформаційної безпеки"}
      ],
      backup_admins: [
        %{name: "Олександр ІВАНЕНКО", title: "начальник відділу"},
        %{name: "Євген РОМАНЕНКО", title: "начальник відділу"},
        %{name: "Петро КУЗЬМЕНКО", title: "директор департаменту"},
        %{name: "Олексій МОРОЗ", title: "начальник відділу СУБД"}
      ]
    ]
    render_order_template("order_admin_appointment", defaults, opts, "order_admin_appointment")
  end

  def gen_order_physical_access(opts \\ []) do
    defaults = [
      tryzub_def: CA.TeX.tryzub_def(),
      parent_org: "Державна судова адміністрація України",
      org_name: "Державне підприємство «Інформаційні судові системи»",
      city: "Київ",
      date: "28.05.2026",
      number: "96_ОД",
      base_date: "13.04.2023",
      base_num: "53_ОД",
      prev_date: "16.05.2025",
      prev_num: "67_ОД",
      address: "м. Київ, вул. Липська, 18/5",
      director_name: "Василь ШЕВЧЕНКО",
      director_title: "Генеральний директор",
      ciso_name: "Дмитро КОВАЛЕНКО",
      persons: [
        %{name: "КЛИМЕНКО Володимир", title: "Головний інженер"},
        %{name: "ІВАНЕНКО Юрій", title: "Директор департаменту централізованого адміністрування мереж та системного супроводу"},
        %{name: "ГЕРАСИМЧУК Микола", title: "Директор департаменту розробки програмного забезпечення"},
        %{name: "КУЗЬМЕНКО Петро", title: "Директор департаменту підтримки користувачів"},
        %{name: "СИДОРЕНКО Юрій", title: "Начальник відділу інформаційної безпеки"},
        %{name: "ПАВЛЕНКО Михайло", title: "Адміністратор системи відділу адміністрування IT-інфраструктури"},
        %{name: "КОЛОМІЄЦЬ Денис", title: "Адміністратор системи"},
        %{name: "ЛЕБЕДЄВ Олександр", title: "Фахівець з інформаційних технологій"}
      ]
    ]
    render_order_template("order_physical_access", defaults, opts, "order_physical_access")
  end

  defp render_order_template(template_name, default_opts, overrides, output_name) do
    logo_style = Keyword.get(overrides, :logo, :mono)
    tryzub = Keyword.get(overrides, :tryzub_def) || CA.NPA.tryzub_def(logo_style)

    opts = Keyword.merge(default_opts, overrides)
    escaped_opts = Enum.map(opts, fn {k, v} -> {k, CA.TeX.escape_val(v)} end)
    escaped_opts = Keyword.put(escaped_opts, :tryzub_def, tryzub)

    content = EEx.eval_file("priv/templates/#{template_name}.tex.eex", assigns: escaped_opts)
    filename = "priv/templates/#{output_name}.tex"
    File.write!(filename, content)
    filename
  end

  def tryzub_def(style \\ :mono) do
    case style do
      :mono ->
        """
        \\newcommand{\\tryzub}[1][1]{%
          \\begin{tikzpicture}[scale=0.03*#1, yscale=-1, baseline=(current bounding box.center)]
            % Shield: transparent background, black stroke
            \\filldraw[fill=white, draw=black, line width=1.5pt]
              svg {m5 5h650v689c0 48-29 97-76 117l-251 105-251-105c-44-20-76-65-72-117z};

            % Right half of Tryzub (Black)
            \\fill[color=black] 
              svg {m329 53c-6 4-2 396 0 401 12 43 29 81 48 112-104 31-63 146-48 287 7-12 17-21 28-28 43-34 70-81 79-132h133v-580c-148 88-132 213-148 361 59-10 75 76-3 83-92-149-59-257-59-419 0-37-9-62-30-85zm200 143v297h-22c-6-23-21-41-42-51 8-85 10-189 64-246zm-22 337h22v120h-89c0-19-3-39-8-58 36-4 68-29 75-62zm-114 71c4 16 6 33 6 49h-50c1-27 19-44 44-49zm-44 89h46c-7 31-23 61-46 85z};

            % Left (mirrored) half of Tryzub (Black)
            \\fill[color=black] 
              svg {m331 53c6 4 2 396 0 401-12 43-29 81-48 112 104 31 63 146 48 287-7-12-17-21-28-28-43-34-70-81-79-132h-133v-580c148 88 132 213 148 361-59-10-75 76 3 83 92-149 59-257 59-419 0-37 9-62 30-85zm-200 143v297h22c6-23 21-41 42-51-8-85-10-189-64-246zm22 337h-22v120h89c0-19 3-39 8-58-36-4-68-29-75-62zm114 71c-4 16-6 33-6 49h50c-1-27-19-44-44-49zm44 89h-46c7 31 23 61 46 85z};
          \\end{tikzpicture}%
        }
        """

      _ ->
        """
        \\newcommand{\\tryzub}[1][1]{%
          \\begin{tikzpicture}[scale=0.03*#1, yscale=-1, baseline=(current bounding box.center)]
            % Blue shield
            \\fill[color={rgb,255:red,0;green,91;blue,187}, draw={rgb,255:red,255;green,213;blue,0}, line width=1.5pt]
              svg {m5 5h650v689c0 48-29 97-76 117l-251 105-251-105c-44-20-76-65-72-117z};

            % Right half of Tryzub
            \\fill[color={rgb,255:red,255;green,213;blue,0}]
              svg {m329 53c-6 4-2 396 0 401 12 43 29 81 48 112-104 31-63 146-48 287 7-12 17-21 28-28 43-34 70-81 79-132h133v-580c-148 88-132 213-148 361 59-10 75 76-3 83-92-149-59-257-59-419 0-37-9-62-30-85zm200 143v297h-22c-6-23-21-41-42-51 8-85 10-189 64-246zm-22 337h22v120h-89c0-19-3-39-8-58 36-4 68-29 75-62zm-114 71c4 16 6 33 6 49h-50c1-27 19-44 44-49zm-44 89h46c-7 31-23 61-46 85z};

            % Left (mirrored) half of Tryzub
            \\fill[color={rgb,255:red,255;green,213;blue,0}]
              svg {m331 53c6 4 2 396 0 401-12 43-29 81-48 112 104 31 63 146 48 287-7-12-17-21-28-28-43-34-70-81-79-132h-133v-580c148 88 132 213 148 361-59-10-75 76 3 83 92-149 59-257 59-419 0-37 9-62 30-85zm-200 143v297h22c6-23 21-41 42-51-8-85-10-189-64-246zm22 337h-22v120h89c0-19 3-39 8-58-36-4-68-29-75-62zm114 71c-4 16-6 33-6 49h50c-1-27-19-44-44-49zm44 89h-46c7 31 23 61 46 85z};
          \\end{tikzpicture}%
        }
        """
    end
  end

end
