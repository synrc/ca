defmodule CA.TeX do
  @moduledoc """
  Generates LaTeX files based on the security-profiles.tex template.
  """
  require EEx

  @template """
  \\documentclass{article}

  \\usepackage[utf8]{inputenc}
  \\usepackage[T1]{fontenc}
  \\usepackage{helvet}
  \\usepackage{geometry}
  \\usepackage{xcolor}
  \\usepackage{eso-pic}
  \\usepackage{fancyhdr}
  \\usepackage{parskip}
  \\usepackage{microtype}
  \\usepackage[english, ukrainian]{babel}
  \\usepackage{url}
  \\usepackage{amsmath}
  \\usepackage{amssymb}
  \\usepackage{amsthm}
  \\usepackage{longtable}
  \\usepackage{booktabs}
  \\usepackage{hyperref}
  \\usepackage{titlesec}
  \\usepackage{tocloft}

  \\renewcommand{\\cftsecfont}{\\small\\bfseries}
  \\renewcommand{\\cftsubsecfont}{\\footnotesize}
  \\renewcommand{\\cftsubsubsecfont}{\\scriptsize}
  \\renewcommand{\\cftsecpagefont}{\\small\\bfseries}
  \\renewcommand{\\cftsubsecpagefont}{\\footnotesize}
  \\renewcommand{\\cftsubsubsecpagefont}{\\scriptsize}

  \\definecolor{nato}{HTML}{293757}
  \\definecolor{footergray}{gray}{0.65}

  \\geometry{a4paper,left=3cm,right=3cm,top=3cm,bottom=3cm}
  \\renewcommand{\\familydefault}{\\sfdefault}
  \\setcounter{secnumdepth}{3}

  \\titleformat{\\section}
    {\\color{nato}\\Huge\\bfseries\\raggedright}{\\thesection.}{1em}{}
  \\titlespacing*{\\section}{0pt}{30pt}{12pt}

  \\titleformat{\\subsection}
    {\\color{nato}\\LARGE\\bfseries\\raggedright}{\\thesubsection.}{1em}{}
  \\titlespacing*{\\subsection}{0pt}{20pt}{8pt}

  \\titleformat{\\subsubsection}
    {\\color{nato}\\Large\\bfseries\\raggedright}{\\thesubsubsection.}{1em}{}
  \\titlespacing*{\\subsubsection}{0pt}{10pt}{6pt}

  \\fancyhf{}
  \\fancyhead[R]{\\small\\color{footergray} <%= @date %>}
  \\fancyfoot[L]{\\small\\color{footergray} <%= @subtitle %>. <%= @title %>.}
  \\fancyfoot[R]{\\small\\color{footergray}\\thepage}

  \\newcommand\\HUGE[1]{\\fontsize{40}{40}\\selectfont #1}

  \\renewcommand{\\headrulewidth}{0pt}
  \\renewcommand{\\footrulewidth}{0.4pt}
  \\renewcommand{\\footrule}{\\color{footergray}\\hrule width \\textwidth height 0.4pt}

  \\begin{document}

  \\pagestyle{fancy}

  \\begin{titlepage}
    \\AddToShipoutPictureBG*{\\AtPageLowerLeft{\\color{nato}\\rule{\\paperwidth}{\\paperheight}}}
    \\color{white}\\thispagestyle{empty}\\vspace*{2cm}\\centering
    {\\Huge  \\textbf{<%= @subtitle %>} \\par} \\vspace{1cm}
    {\\HUGE  \\textbf{<%= @title %>} \\par} \\vspace{1cm}
    \\vfill
    {\\large <%= @year %> \\copyright\\ <%= @copyright %> \\par}
  \\end{titlepage}

  \\newpage

  \\begin{center}
    {\\Huge\\color{nato}\\bfseries <%= @toc_title %>\\par}
  \\end{center}
  \\vspace{40pt}
  \\tableofcontents

  \\begin{abstract}
  <%= @abstract %>
  \\end{abstract}

  <%= @body %>

  \\end{document}
  """

  EEx.function_from_string(:def, :render, @template, [:assigns])

  @doc """
  Generates a LaTeX document string.

  ## Options
    * `:date` - document date (default: "31 березня 2026")
    * `:subtitle` - subtitle on title page and footer (default: "ПК КЗІ КЗЗІ")
    * `:title` - title on title page and footer (default: "Профілі безпеки")
    * `:year` - copyright year (default: "2026")
    * `:copyright` - copyright owner (default: "Криптографічні Телесистеми")
    * `:toc_title` - title for Table of Contents (default: "Зміст")
    * `:abstract` - abstract content
    * `:body` - document body content

  ## Example
      CA.TeX.generate(
        title: "Профіль безпеки",
        subtitle: "Комплексна система захисту інформації",
        abstract: "...",
        body: "\\\\section{Вступна частина} ..."
      )
  """
  def generate(opts \\ []) do
    opts =
      Keyword.merge(
        [
          date: "2 червня 2026",
          subtitle: "Комплексна система захисту інформації",
          title: "Профіль безпеки",
          year: "2026",
          copyright: "Критпографічні Телесистеми",
          toc_title: "Зміст",
          abstract: "",
          body: ""
        ],
        opts
      )

    render(Enum.into(opts, %{}))
  end

  def gen do
    :lists.flatten([
      # В Шаблоні Держспецзв'язку
      legal_l1_profile_1(),
      legal_l1_profile_2(),
      legal_l2_profile(),
      legal_l3_profile(CA.L3.ERP),
      # В Шаблоні ТОВ "Криптографічні Телесистеми"
      gen_bible(),
    ])
  end

  def gen_bible(opts \\ []) do
    all_oids = Enum.map(CA.Profile.Data.specs(), &CA.SPE.oid(&1.id))
    {body, count} = generate_body(all_oids)

    opts =
      Keyword.merge(
        [
          title: "Повний каталог заходів із захисту інформації (#{count})",
          subtitle: "Комплексна система захисту інформації",
          abstract:
            "Повний каталог (Bible) — містить абсолютно всі заходи, посилення та субконтролі згідно з повним скоупом НД ТЗІ КСЗІ.",
          body: body
        ],
        opts
      )

    content = generate(opts)
    File.write!("priv/bible_profile.tex", content)
    "priv/bible_profile.tex"
  end

  defp generate_body(controls) do
    profile_specs = unfold(controls)

    all_specs = CA.Profile.Data.specs()
    oid_to_spec = Map.new(all_specs, fn spec -> {CA.SPE.oid(spec.id), spec} end)

    {sections, _} =
      Enum.map_reduce(profile_specs, nil, fn spec, last_fam ->
        parts = spec.id |> to_string() |> String.split("-")
        family = Enum.at(parts, 2) |> String.upcase()

        latex_level =
          case length(parts) do
            4 -> "subsection"
            5 -> "subsubsection"
            _ -> "paragraph"
          end

        spec =
          if latex_level == "subsubsection" do
            short_title = String.split(spec.title, " - ", parts: 2) |> List.last()
            %{spec | title: short_title}
          else
            spec
          end

        params = Map.get(spec, :parameters, [])
        formatted = format_control(spec, params, latex_level)

        if family != last_fam do
          family_atom = String.to_atom("id-spe-#{String.downcase(family)}")
          family_spec = Map.get(oid_to_spec, CA.SPE.oid(family_atom))

          family_desc =
            if family_spec && family_spec.description != "",
              do: escape_latex(family_spec.description) <> "\n\n",
              else: ""

          ai_summary = CA.FamilyDescriptions.get_summary(family_atom)
          ai_text = if ai_summary != "", do: escape_latex(ai_summary) <> "\n\n", else: ""

          children_text = CA.FamilyDescriptions.get_children_text(family_atom, profile_specs)

          children_str =
            if children_text != "",
              do: "\\textbf{Перелік заходів захисту:} " <> escape_latex(children_text) <> "\n\n",
              else: ""

          {"\\section{#{family}}\n#{family_desc}#{ai_text}#{children_str}" <> formatted, family}
        else
          {formatted, last_fam}
        end
      end)

    {Enum.join(sections, "\n\n"), length(profile_specs)}
  end

  def unfold([%{subcontrols: _} | _] = controls) do
    Enum.flat_map(controls, fn fam ->
      Enum.map(fam.subcontrols, fn sc ->
        %{
          id: String.to_atom("id-spe-" <> String.downcase(sc.id)),
          title: sc.name,
          description: sc.text,
          parameters: Map.get(sc, :parameters, [])
        }
      end)
    end)
  end

  def unfold(oids) do
    all_specs = CA.Profile.Data.specs()
    oid_to_spec = Map.new(all_specs, fn spec -> {CA.SPE.oid(spec.id), spec} end)

    oids
    |> Enum.reject(fn oid -> tuple_size(oid) == 9 end)
    |> Enum.uniq()
    |> Enum.sort_by(&Tuple.to_list/1)
    |> Enum.map(&Map.get(oid_to_spec, &1))
    |> Enum.reject(&is_nil/1)
  end

  defp format_control(spec, [], latex_level) do
    """
    \\#{latex_level}{#{escape_latex(spec.title)}}
    #{escape_latex(spec.description)}

    \\vspace{10pt}
    \\textit{Немає параметрів для цього контролю.}
    \\vspace{10pt}
    """
  end

  defp format_control(spec, params, latex_level) do
    params_paragraphs =
      params
      |> Enum.with_index(1)
      |> Enum.map(fn {param, idx} ->
        {name, desc, opts} =
          case param do
            {n, d, o} -> {n, d, o}
            {n, d} -> {n, d, []}
          end

        type = Keyword.get(opts, :type, "") |> to_string() |> escape_latex()
        default = Keyword.get(opts, :default, "") |> inspect() |> escape_latex()

        """
        {\\footnotesize\\bfseries
        No: #{idx}\\\\
        Name: #{escape_latex(to_string(name))}\\\\
        Type: #{type}\\\\
        Default: #{default}
        }

        {\\footnotesize #{escape_latex(desc)}}

        """
      end)
      |> Enum.join("\n")

    """
    \\#{latex_level}{#{escape_latex(spec.title)}}
    #{escape_latex(spec.description)}

    \\vspace{10pt}
    #{params_paragraphs}
    """
  end

  defp escape_latex(text) do
    text
    |> to_string()
    |> String.replace(<<0xF02D::utf8>>, "-")
    |> String.replace(<<0x2013::utf8>>, "--")
    |> String.replace(<<0x2014::utf8>>, "---")
    |> String.replace(<<0x02BC::utf8>>, "'")
    |> String.replace(<<0x2019::utf8>>, "'")
    |> String.replace("\\", "\\textbackslash{}")
    |> String.replace("{", "\\{")
    |> String.replace("}", "\\}")
    |> String.replace("$", "\\$")
    |> String.replace("&", "\\&")
    |> String.replace("%", "\\%")
    |> String.replace("#", "\\#")
    |> String.replace("_", "\\_\\allowbreak{}")
    |> String.replace("~", "\\textasciitilde{}")
    |> String.replace("^", "\\textasciicircum{}")
    |> String.replace("\"", "\\textquotedbl{}")
    |> String.replace("\n", "\\\\ \n")
  end

  @legal_template_l2 """
  \\documentclass[10pt]{article}
  \\usepackage[T1,T2A]{fontenc}
  \\usepackage[utf8]{inputenc}
  \\usepackage[english,ukrainian]{babel}
  \\usepackage{geometry}
  \\usepackage{longtable}
  \\usepackage{array}
  \\usepackage{multirow}
  \\usepackage{hyperref}
  \\usepackage{mathptmx}
  \\renewcommand{\\familydefault}{\\rmdefault}

  \\geometry{a4paper,left=2cm,right=2cm,top=2cm,bottom=2cm}

  \\begin{document}

  \\begin{flushright}
  ЗАТВЕРДЖЕНО\\\\
  Наказ <%= @org_name %>\\\\
  \\_\\_\\_\\_\\_\\_\\_\\_\\_\\_\\_\\_ 2026 року №\\_\\_\\_\\_
  \\end{flushright}

  \\begin{center}
  \\textbf{\\large <%= @title %>}
  \\end{center}

  \\footnotesize
  \\begin{longtable}{|c|>{\\raggedright\\arraybackslash}p{4cm}|>{\\raggedright\\arraybackslash}p{6cm}|>{\\raggedright\\arraybackslash}p{1.5cm}|>{\\raggedright\\arraybackslash}p{3.5cm}|}
  \\hline
  \\textbf{№ з/п} & \\textbf{Назва дії з безпеки інформації} & \\textbf{Зміст дії} & \\textbf{Заходи захисту} & \\textbf{Мінімальні необхідні параметри}\\\\
  \\hline
  \\endfirsthead

  \\hline
  \\textbf{№ з/п} & \\textbf{Назва дії з безпеки інформації} & \\textbf{Зміст дії} & \\textbf{Заходи захисту} & \\textbf{Мінімальні необхідні параметри}\\\\
  \\hline
  \\endhead

  \\hline
  \\endfoot

  \\hline
  \\endlastfoot

  <%= @table_body %>

  \\end{longtable}

  \\end{document}
  """

  @legal_template_l3 """
  \\documentclass[10pt]{article}
  \\usepackage[T1,T2A]{fontenc}
  \\usepackage[utf8]{inputenc}
  \\usepackage[english,ukrainian]{babel}
  \\usepackage{geometry}
  \\usepackage{longtable}
  \\usepackage{array}
  \\usepackage{multirow}
  \\usepackage{hyperref}
  \\usepackage{mathptmx}
  \\renewcommand{\\familydefault}{\\rmdefault}

  \\geometry{a4paper,left=2cm,right=2cm,top=2cm,bottom=2cm}

  \\begin{document}

  \\begin{flushright}
  ЗАТВЕРДЖЕНО\\\\
  Наказом <%= @org_name %>\\\\
  від \\_\\_ \\_\\_\\_\\_\\_\\_\\_\\_\\_ 2026 р. № \\_\\_\\_\\\\
  (в редакції наказу <%= @org_name %>\\\\
  від \\_\\_ \\_\\_\\_\\_\\_\\_\\_\\_\\_ 2026 р. № \\_\\_)
  \\end{flushright}

  \\vspace{2cm}

  \\begin{center}
  \\textbf{\\Large <%= @system_desc %>}\\\\
  \\textbf{\\Large «<%= @system_name %>»}\\\\
  \\vspace{1cm}
  \\textbf{\\Large ЦІЛЬОВИЙ ПРОФІЛЬ БЕЗПЕКИ}\\\\
  \\vspace{0.5cm}
  \\large <%= @doc_id %>
  \\end{center}

  \\newpage

  \\footnotesize
  \\begin{longtable}{|>{\\centering\\arraybackslash}p{0.5cm}|>{\\raggedright\\arraybackslash}p{4cm}|>{\\raggedright\\arraybackslash}p{5cm}|>{\\raggedright\\arraybackslash}p{2cm}|>{\\raggedright\\arraybackslash}p{3cm}|}
  \\hline
  \\textbf{№} & \\textbf{Вимога з безпеки інформації} & \\textbf{Вимога ГПБ} & \\multicolumn{2}{c|}{\\textbf{ЦПБ}} \\\\
  \\cline{4-5}
  & & & \\textbf{Захід захисту} & \\textbf{Налаштований зміст заходу захисту}\\\\
  \\hline
  \\endfirsthead

  \\hline
  \\textbf{№} & \\textbf{Вимога з безпеки інформації} & \\textbf{Вимога ГПБ} & \\multicolumn{2}{c|}{\\textbf{ЦПБ}} \\\\
  \\cline{4-5}
  & & & \\textbf{Захід захисту} & \\textbf{Налаштований зміст заходу захисту}\\\\
  \\hline
  \\endhead

  \\hline
  \\endfoot

  \\hline
  \\endlastfoot

  <%= @table_body %>

  \\end{longtable}

  \\end{document}
  """

  EEx.function_from_string(:def, :render_legal_l2, @legal_template_l2, [:assigns])
  EEx.function_from_string(:def, :render_legal_l3, @legal_template_l3, [:assigns])

  def legal_l1_profile_1(controls \\ CA.L1.Base84.groups(), opts \\ []) do
    {body, _count} = generate_legal_l2_table_body(controls)

    opts =
      Keyword.merge(
        [
          org_name: "Держспецзв’язок України",
          title:
            "Базовий профіль безпеки системи, де обробляється відкрита або конфіденційна інформація, затверджений наказом Адміністрації Держспецзв’язку від 30.06.2025 № 409",
          table_body: body
        ],
        opts
      )

    content = render_legal_l2(Enum.into(opts, %{}))
    File.write!("priv/legal_l1_profile_409.tex", content)
    "priv/legal_l1_profile_409.tex"
  end

  def legal_l1_profile_2(controls \\ CA.L1.Base97.groups(), opts \\ []) do
    {body, _count} = generate_legal_l2_table_body(controls)

    opts =
      Keyword.merge(
        [
          org_name: "Держспецзв’язок України",
          title:
            "Базовий профіль безпеки системи, де обробляється службова інформація, затверджений наказом Адміністрації Держспецзв’язку від 02.07.2025 № 419",
          table_body: body
        ],
        opts
      )

    content = render_legal_l2(Enum.into(opts, %{}))
    File.write!("priv/legal_l1_profile_419.tex", content)
    "priv/legal_l1_profile_419.tex"
  end

  def legal_l2_profile(opts \\ []) do
    controls = CA.L2.Court.controls() -- CA.L1.controls()
    {body, _count} = generate_legal_l2_table_body(controls)

    opts =
      Keyword.merge(
        [
          org_name: "Державна Судова Адміністрація України",
          title:
            "Галузевий профіль безпеки судової системи, що використовуються для надання хмарних послуг та/або послуг центру обробки даних публічним користувачам та/або критично важливим об’єктам інфраструктури",
          table_body: body
        ],
        opts
      )

    content = render_legal_l2(Enum.into(opts, %{}))
    File.write!("priv/legal_l2_court_profile.tex", content)
    "priv/legal_l2_court_profile.tex"
  end

  def generate_doc_id(opts \\ []) do
    base = Keyword.get(opts, :base, "47850061")
    dept = Keyword.get(opts, :dept, "СЗІ")
    sub = Keyword.get(opts, :sub, "ДП")
    seq = Keyword.get_lazy(opts, :seq, fn -> Enum.random(1..99) end)

    "UA.#{base}.#{dept}.#{sub}-#{String.pad_leading(to_string(seq), 2, "0")}"
  end

  def legal_l3_profile(module, opts \\ []) do
    name = module |> Module.split() |> List.last()
    controls = module.controls()
    doc_id = generate_doc_id()
    {body, _count} = generate_legal_l3_table_body(controls)

    opts =
      Keyword.merge(
        [
          org_name: module.org_name(),
          system_desc: module.system_desc(),
          system_name: module.system_name(),
          doc_id: doc_id,
          table_body: body
        ],
        opts
      )

    content = render_legal_l3(Enum.into(opts, %{}))
    filename = "priv/legal_l3_profile_#{String.downcase(name)}.tex"
    File.write!(filename, content)
    filename
  end

  defp generate_legal_l2_table_body(controls_or_groups) do
    all_specs = CA.Profile.Data.specs()

    is_grouped =
      Enum.any?(controls_or_groups, fn
        {group_name, list} when is_binary(group_name) and is_list(list) -> true
        _ -> false
      end)

    chunked_specs =
      if is_grouped do
        # It's already grouped (a list of {name, controls} or {:category, name})
        Enum.map(controls_or_groups, fn
          {:category, name} ->
            {:category, name}

          {name, group} ->
            {name, unfold(group)}
        end)
        |> Enum.reject(fn
          {:category, _} -> false
          {_, specs} -> specs == []
        end)
      else
        # It's a flat list, use default grouping
        specs = unfold(controls_or_groups)

        {policy_specs, other_specs} =
          Enum.split_with(specs, fn spec ->
            base_id =
              spec.id |> to_string() |> String.split("-") |> Enum.take(4) |> Enum.join("-")

            Regex.match?(~r/^id-spe-[a-z]+-1$/, base_id)
          end)

        chunked_others =
          other_specs
          |> Enum.chunk_by(fn spec ->
            spec.id |> to_string() |> String.split("-") |> Enum.take(4) |> Enum.join("-")
          end)
          |> Enum.map(fn sp -> {hd(sp).title, sp} end)

        policy_chunk =
          if policy_specs != [], do: [{"Політики та процедури з безпеки", policy_specs}], else: []

        policy_chunk ++ chunked_others
      end

    {rows, {final_idx, _last_fam}} =
      Enum.map_reduce(chunked_specs, {1, nil}, fn
        {:category, name}, {idx, _last_fam} ->
          # Explicit category provided, don't increment idx
          prefix =
            "\\multicolumn{5}{|>{\\raggedright\\arraybackslash}p{16cm}|}{\\textbf{#{escape_latex(name)}}} \\\\* \\noalign{\\hrule height 0.4pt}\n"

          {prefix, {idx, name}}

        {group_name, specs}, {idx, last_fam} ->
          is_policy_chunk =
            Enum.all?(specs, fn s ->
              base_id = s.id |> to_string() |> String.split("-") |> Enum.take(4) |> Enum.join("-")
              Regex.match?(~r/^id-spe-[a-z]+-1$/, base_id)
            end)

          family =
            if is_policy_chunk do
              "ПОЛІТИКИ ТА ПРОЦЕДУРИ"
            else
              base_spec = hd(specs)
              parts = base_spec.id |> to_string() |> String.split("-")
              Enum.at(parts, 2) |> String.upcase()
            end

          title = escape_latex(group_name)

          row_str =
            specs
            |> Enum.with_index()
            |> Enum.map(fn {spec, spec_idx} ->
              p = spec.id |> to_string() |> String.split("-")
              fam = Enum.at(p, 2) |> String.upcase()
              cid = fam <> "-" <> (Enum.at(p, 3) || "")
              cid = if length(p) > 4, do: cid <> "(" <> Enum.at(p, 4) <> ")", else: cid

              {desc_list, params_list} =
                Map.get(spec, :parameters, [])
                |> Enum.reject(fn {_name, _pdesc, opts} ->
                  Keyword.get(opts, :default) in [nil, "", "nil"]
                end)
                |> Enum.map(fn {name_atom, pdesc, opts} ->
                  default_val = Keyword.get(opts, :default, "")
                  type = Keyword.get(opts, :type, "unknown")

                  default_str =
                    if is_list(default_val),
                      do: Enum.join(default_val, ", "),
                      else: to_string(default_val)

                  default = escape_latex(default_str)
                  desc_str = escape_latex(pdesc)

                  formatted_param =
                    "Параметр: #{escape_latex(to_string(name_atom))}\\newline Тип: #{escape_latex(to_string(type))}\\newline Значення: \\textbf{#{default}}"

                  {desc_str, formatted_param}
                end)
                |> Enum.uniq()
                |> Enum.reduce([], fn {desc1, def1} = item, acc ->
                  if Enum.any?(acc, fn {desc2, def2} ->
                       def1 == def2 and
                         (String.contains?(desc1, desc2) or String.contains?(desc2, desc1))
                     end) do
                    Enum.map(acc, fn {desc2, def2} = existing ->
                      if def1 == def2 and
                           (String.contains?(desc1, desc2) or String.contains?(desc2, desc1)) do
                        if String.length(desc1) < String.length(desc2), do: item, else: existing
                      else
                        existing
                      end
                    end)
                    |> Enum.uniq()
                  else
                    [item | acc]
                  end
                end)
                |> Enum.reverse()
                |> Enum.unzip()

              col1 = if spec_idx == 0, do: "#{idx}", else: ""
              col2 = if spec_idx == 0, do: "#{title}", else: ""

              is_last = spec_idx == length(specs) - 1
              line_cmd = if is_last, do: "\\hline", else: "\\cline{3-5}"

              params = Enum.zip(desc_list, params_list)

              if params == [] do
                "#{col1} & #{col2} & & #{escape_latex(cid)} & \\\\ #{line_cmd}\n"
              else
                params
                |> Enum.with_index()
                |> Enum.map(fn {{d, p}, p_idx} ->
                  c1 = if p_idx == 0, do: col1, else: ""
                  c2 = if p_idx == 0, do: col2, else: ""
                  c4 = if p_idx == 0, do: escape_latex(cid), else: ""
                  lcmd = if p_idx == length(params) - 1, do: line_cmd, else: "\\cline{3-5}"

                  chunks = String.split(d, "; ")

                  chunks
                  |> Enum.with_index()
                  |> Enum.map(fn {chunk, chunk_idx} ->
                    cx1 = if chunk_idx == 0, do: c1, else: ""
                    cx2 = if chunk_idx == 0, do: c2, else: ""
                    cx4 = if chunk_idx == 0, do: c4, else: ""
                    cx5 = if chunk_idx == 0, do: p, else: ""

                    chunk_text = if chunk_idx == length(chunks) - 1, do: chunk, else: chunk <> ";"
                    lcmd_inner = if chunk_idx == length(chunks) - 1, do: lcmd, else: ""

                    "#{cx1} & #{cx2} & #{chunk_text} & #{cx4} & #{cx5} \\\\ #{lcmd_inner}\n"
                  end)
                  |> Enum.join("")
                end)
                |> Enum.join("")
              end
            end)
            |> Enum.join("")

          if !is_grouped and family != last_fam do
            family_atom = String.to_atom("id-spe-#{String.downcase(family)}")
            family_spec = Enum.find(all_specs, &(&1.id == family_atom))

            family_title =
              if family_spec, do: escape_latex(family_spec.title), else: escape_latex(family)

            prefix =
              "\\multicolumn{5}{|>{\\raggedright\\arraybackslash}p{16cm}|}{\\textbf{#{family_title}}} \\\\* \\noalign{\\hrule height 0.4pt}\n"

            {prefix <> row_str, {idx + 1, family}}
          else
            {row_str, {idx + 1, family}}
          end
      end)

    {Enum.join(rows, ""), final_idx - 1}
  end

  defp generate_legal_l3_table_body(controls) do
    profile_specs =
      case controls do
        [%{subcontrols: _} | _] ->
          Enum.flat_map(controls, fn fam ->
            Enum.map(fam.subcontrols, fn sc ->
              %{
                id: String.to_atom("id-spe-" <> String.downcase(sc.id)),
                title: sc.name,
                description: sc.text,
                parameters: Map.get(sc, :parameters, [])
              }
            end)
          end)

        _ ->
          cmdb_lookup =
            CA.L3.ERP.controls()
            |> Enum.flat_map(& &1.subcontrols)
            |> Enum.map(&{String.to_atom("id-spe-" <> String.downcase(&1.id)), &1})
            |> Enum.into(%{})

          unfold(controls)
          |> Enum.map(fn base_spec ->
            case Map.get(cmdb_lookup, base_spec.id) do
              nil ->
                base_spec

              cmdb_sc ->
                %{
                  base_spec
                  | description: cmdb_sc.text,
                    parameters: Map.get(cmdb_sc, :parameters, [])
                }
            end
          end)
      end

    all_specs = CA.Profile.Data.specs()

    {rows, _state} =
      profile_specs
      |> Enum.with_index(1)
      |> Enum.map_reduce({nil, 0, 0}, fn {spec, row_idx}, {last_fam, fam_idx, ctrl_idx} ->
        parts = spec.id |> to_string() |> String.split("-")
        family = Enum.at(parts, 2) |> String.upcase()
        control_id = family <> "-" <> (Enum.at(parts, 3) || "")

        control_id =
          if length(parts) > 4,
            do: control_id <> "(" <> Enum.at(parts, 4) <> ")",
            else: control_id

        title = escape_latex(spec.title)
        # escape_latex(spec.description)
        desc_list =
          Map.get(spec, :parameters, [])
          |> Enum.reject(fn
            %{default: default_val} -> default_val in [nil, "", "nil"]
            {_name, _desc, opts} -> Keyword.get(opts, :default) in [nil, "", "nil"]
            _ -> false
          end)
          |> Enum.map(fn
            %{name: name_atom, type: type, default: default_val} ->
              default_str =
                if is_list(default_val),
                  do: Enum.join(default_val, ", "),
                  else: to_string(default_val)

              default = escape_latex(default_str)

              "Параметр: #{escape_latex(name_atom)}\\newline Тип: #{escape_latex(type)}\\newline Значення: \\textbf{#{default}}"

            {_name_atom, pdesc, opts} ->
              default_val = Keyword.get(opts, :default, "")
              type = Keyword.get(opts, :type, "unknown")

              default_str =
                if is_list(default_val),
                  do: Enum.join(default_val, ", "),
                  else: to_string(default_val)

              default = escape_latex(default_str)

              "Параметр: #{escape_latex(pdesc)}\\newline Тип: #{escape_latex(type)}\\newline Значення: \\textbf{#{default}}"
          end)
          |> Enum.uniq()

        original_spec = Enum.find(all_specs, &(&1.id == spec.id))
        gpb_text = if original_spec, do: escape_latex(original_spec.description), else: ""
        t_text = String.replace(gpb_text, "\\\\ \n", "\\newline ")

        custom_text_raw = escape_latex(spec.description) |> String.replace("\\\\ \n", "\\newline ")
        custom_text = if custom_text_raw == t_text, do: "", else: custom_text_raw

        t_chunks = if t_text == "", do: [""], else: [t_text]

        grouped_params = 
          Enum.chunk_every(desc_list, 4) 
          |> Enum.map(fn chunk ->
            Enum.join(chunk, "\\vspace{1mm}\\newline\\noindent\\rule{\\linewidth}{0.4pt}\\vspace{1mm}\n")
          end)

        p_chunks =
          if custom_text == "" do
            if grouped_params == [], do: [""], else: grouped_params
          else
            case grouped_params do
              [] -> [custom_text]
              [first | rest] ->
                [custom_text <> "\\vspace{1mm}\\newline\\noindent\\rule{\\linewidth}{0.4pt}\\vspace{1mm}\n" <> first | rest]
            end
          end

        max_chunks = max(length(t_chunks), length(p_chunks))
        t_chunks = t_chunks ++ List.duplicate("", max_chunks - length(t_chunks))
        p_chunks = p_chunks ++ List.duplicate("", max_chunks - length(p_chunks))

        {fam_idx_new, ctrl_idx_new, prefix} =
          if family != last_fam do
            family_atom = String.to_atom("id-spe-#{String.downcase(family)}")
            family_spec = Enum.find(all_specs, &(&1.id == family_atom))

            family_title =
              if family_spec, do: escape_latex(family_spec.title), else: escape_latex(family)

            new_fam_idx = fam_idx + 1

            pref =
              "\\multicolumn{5}{|>{\\raggedright\\arraybackslash}p{16cm}|}{\\textbf{#{new_fam_idx}. #{family_title}}} \\\\* \\noalign{\\hrule height 0.4pt}\n"

            {new_fam_idx, 1, pref}
          else
            {fam_idx, ctrl_idx + 1, ""}
          end

        row_str =
          Enum.zip(t_chunks, p_chunks)
          |> Enum.with_index()
          |> Enum.map(fn {{t, p}, chunk_idx} ->
            c1 = if chunk_idx == 0, do: "#{row_idx}", else: ""
            c2 = if chunk_idx == 0, do: "#{title}", else: ""
            c4 = if chunk_idx == 0, do: "#{escape_latex(control_id)}", else: ""
            line_cmd = if chunk_idx == max_chunks - 1, do: "\\hline\n", else: "\n"
            "#{c1} & #{c2} & #{t} & #{c4} & #{p} \\\\ #{line_cmd}"
          end)
          |> Enum.join("")

        {prefix <> row_str, {family, fam_idx_new, ctrl_idx_new}}
      end)

    {Enum.join(rows, ""), length(profile_specs)}
  end
end
