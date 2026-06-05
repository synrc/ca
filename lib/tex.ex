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
    \\color{white}\\thispagestyle{empty}\\vspace*{4cm}\\centering
    {\\Huge  \\textbf{<%= @subtitle %>} \\par} \\vspace{2cm}
    {\\HUGE  \\textbf{<%= @title %>} \\par} \\vspace{2.5cm}
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

  def base_profile(opts \\ []) do
    {body, count} = generate_body(CA.L1.controls())

    opts =
      Keyword.merge(
        [
          title: "Профіль базових заходів із захисту інформації (#{count})",
          subtitle: "Комплексна система захисту інформації",
          abstract: "Базовий профіль — затверджується Адміністрацією Держспецзв’язку (наказом).",
          body: body
        ],
        opts
      )

    content = generate(opts)
    File.write!("priv/base_profile.tex", content)
    "priv/base_profile.tex"
  end

  def court_profile(opts \\ []) do
    controls = CA.L2.Court.controls() -- CA.L1.controls()
    {body, count} = generate_body(controls)

    opts =
      Keyword.merge(
        [
          title: "Галузевий профіль заходів із захисту інформації (#{count})",
          subtitle: "Комплексна система захисту інформації",
          abstract:
            "Галузевий профіль — розробляється галузевим органом, погоджується з Держспецзв’язку та затверджується наказом/рішенням відповідного органу. Включає лише додаткові вимоги (відмінності) відносно Базового профілю.",
          body: body
        ],
        opts
      )

    content = generate(opts)
    File.write!("priv/court_profile.tex", content)
    "priv/court_profile.tex"
  end

  def chat_profile(opts \\ []) do
    controls = CA.L2.Messenger.controls() -- CA.L1.controls()
    {body, count} = generate_body(controls)

    opts =
      Keyword.merge(
        [
          title: "Завдання безпеки для месенджера (#{count})",
          subtitle: "Комплексна система захисту інформації",
          abstract:
            "Завдання з безпеки для забезпечення конфіденційності, цілісності повідомлень та управління сесіями в месенджері.",
          body: body
        ],
        opts
      )

    content = generate(opts)
    File.write!("priv/chat_profile.tex", content)
    "priv/chat_profile.tex"
  end

  def mail_profile(opts \\ []) do
    controls = CA.L2.Mail.controls() -- CA.L1.controls()
    {body, count} = generate_body(controls)

    opts =
      Keyword.merge(
        [
          title: "Завдання безпеки для військової пошти (#{count})",
          subtitle: "Комплексна система захисту інформації",
          abstract:
            "Завдання з безпеки для забезпечення конфіденційності, цілісності та гарантованої доставки повідомлень (MHS X.420) з підтримкою грифування.",
          body: body
        ],
        opts
      )

    content = generate(opts)
    File.write!("priv/mail_profile.tex", content)
    "priv/mail_profile.tex"
  end

  def vpn_profile(opts \\ []) do
    controls = CA.L2.VPN.controls() -- CA.L1.controls()
    {body, count} = generate_body(controls)

    opts =
      Keyword.merge(
        [
          title: "Завдання безпеки для VPN та PKI (#{count})",
          subtitle: "Комплексна система захисту інформації",
          abstract:
            "Завдання з безпеки для забезпечення безпеки VPN-продуктів та інфраструктури PKI (CA, OCSP, TSP, LDAP).",
          body: body
        ],
        opts
      )

    content = generate(opts)
    File.write!("priv/vpn_profile.tex", content)
    "priv/vpn_profile.tex"
  end

  def target_profile(module, opts \\ []) do
    name = module |> Module.split() |> List.last()
    controls = module.controls() -- CA.L2.Court.controls()

    title =
      case name do
        "Orgs" -> "Цільовий профіль безпеки органів та установ в системі правосуддя"
        "Supreme" -> "Цільовий профіль безпеки вищих судів"
        "Specialized" -> "Цільовий профіль безпеки вищих спеціалізованих судів"
        "Local" -> "Цільовий профіль судів"
        _ -> "Цільовий профіль безпеки (#{name})"
      end

    {body, count} = generate_body(controls)

    opts =
      Keyword.merge(
        [
          title: "#{title} (#{count})",
          subtitle: "Комплексна система захисту інформації",
          abstract:
            "Цільовий профіль безпеки (ЦПБ) — індивідуальний для конкретної системи підприємства. Саме на його основі створюється/модернізується КЗЗІ. Включає лише додаткові вимоги (відмінності) відносно Галузевого профілю.",
          body: body
        ],
        opts
      )

    content = generate(opts)
    filename = "priv/target_profile_#{String.downcase(name)}.tex"
    File.write!(filename, content)
    filename
  end

  def generate_l3_profiles do
    [
      CA.L3.Local,
      CA.L3.Orgs,
      CA.L3.Specialized,
      CA.L3.Supreme
    ]
    |> Enum.map(&target_profile/1)
  end

  def gen do
    :lists.flatten([
      gen_bible(),
      base_profile(),
      court_profile(),
      chat_profile(),
      mail_profile(),
      vpn_profile(),
      generate_l3_profiles()
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
    profile_specs = CA.Profile.Data.unfold(controls)

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
      |> Enum.map(fn {{name, desc, opts}, idx} ->
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
  \\begin{longtable}{|c|>{\\raggedright\\arraybackslash}p{2.5cm}|>{\\raggedright\\arraybackslash}p{4cm}|>{\\raggedright\\arraybackslash}p{3.5cm}|>{\\raggedright\\arraybackslash}p{5.5cm}|}
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
  \\textbf{\\Large ІНФОРМАЦІЙНО-КОМУНІКАЦІЙНА СИСТЕМА}\\\\
  \\textbf{\\Large «<%= @system_name %>»}\\\\
  \\vspace{1cm}
  \\textbf{\\Large ЦІЛЬОВИЙ ПРОФІЛЬ БЕЗПЕКИ}\\\\
  \\vspace{0.5cm}
  \\large <%= @doc_id %>
  \\end{center}

  \\newpage

  \\footnotesize
  \\begin{longtable}{|c|>{\\raggedright\\arraybackslash}p{4cm}|>{\\raggedright\\arraybackslash}p{2.5cm}|>{\\raggedright\\arraybackslash}p{3.5cm}|>{\\raggedright\\arraybackslash}p{5.5cm}|}
  \\hline
  \\multirow{2}{*}{\\textbf{№}} & \\multirow{2}{*}{\\textbf{Вимога з безпеки інформації}} & \\multirow{2}{*}{\\textbf{Вимога ГПБ}} & \\multicolumn{2}{c|}{\\textbf{ЦПБ}} \\\\
  \\cline{4-5}
  & & & \\textbf{Захід захисту} & \\textbf{Налаштований зміст заходу захисту}\\\\
  \\hline
  \\endfirsthead

  \\hline
  \\multirow{2}{*}{\\textbf{№}} & \\multirow{2}{*}{\\textbf{Вимога з безпеки інформації}} & \\multirow{2}{*}{\\textbf{Вимога ГПБ}} & \\multicolumn{2}{c|}{\\textbf{ЦПБ}} \\\\
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

  def legal_l1_profile(opts \\ []) do
    controls = CA.L1.controls()
    {body, _count} = generate_legal_l2_table_body(controls)

    opts =
      Keyword.merge(
        [
          org_name: "Міністерства цифрової трансформації України",
          title: "Базовий профіль безпеки (L1)",
          table_body: body
        ],
        opts
      )

    content = render_legal_l2(Enum.into(opts, %{}))
    File.write!("priv/legal_baseline_profile.tex", content)
    "priv/legal_baseline_profile.tex"
  end

  def legal_l2_profile(opts \\ []) do
    controls = CA.L2.Court.controls() -- CA.L1.controls()
    {body, _count} = generate_legal_l2_table_body(controls)

    opts =
      Keyword.merge(
        [
          org_name: "Міністерства цифрової трансформації України",
          title:
            "Галузевий профіль безпеки систем, що використовуються для надання хмарних послуг та/або послуг центру обробки даних публічним користувачам та/або критично важливим об’єктам інфраструктури",
          table_body: body
        ],
        opts
      )

    content = render_legal_l2(Enum.into(opts, %{}))
    File.write!("priv/legal_digital_profile.tex", content)
    "priv/legal_digital_profile.tex"
  end

  def legal_l3_profile(module, opts \\ []) do
    name = module |> Module.split() |> List.last()
    controls = module.controls()

    system_name =
      case name do
        "Orgs" -> "РЕЄСТР БАЗОВОЇ МЕРЕЖІ ЗАКЛАДІВ КУЛЬТУРИ"
        "Local" -> "СУДОВІ СИСТЕМИ"
        _ -> String.upcase(name)
      end

    org_name =
      case name do
        "Orgs" -> "Міністерства культури України"
        _ -> "Відповідного Органу"
      end

    doc_id = "UA.43220275.СЗІ.ЦПБ-01"

    {body, _count} = generate_legal_l3_table_body(controls)

    opts =
      Keyword.merge(
        [
          org_name: org_name,
          system_name: system_name,
          doc_id: doc_id,
          table_body: body
        ],
        opts
      )

    content = render_legal_l3(Enum.into(opts, %{}))
    filename = "priv/legal_target_profile_#{String.downcase(name)}.tex"
    File.write!(filename, content)
    filename
  end

  defp generate_legal_l2_table_body(controls) do
    all_specs = CA.Profile.Data.specs()

    chunked_specs =
      CA.Profile.Data.unfold(controls)
      |> Enum.chunk_by(fn spec ->
        spec.id |> to_string() |> String.split("-") |> Enum.take(4) |> Enum.join("-")
      end)

    {rows, _last_fam} =
      chunked_specs
      |> Enum.with_index(1)
      |> Enum.map_reduce(nil, fn {specs, idx}, last_fam ->
        base_spec = hd(specs)
        parts = base_spec.id |> to_string() |> String.split("-")
        family = Enum.at(parts, 2) |> String.upcase()

        control_ids =
          specs
          |> Enum.map(fn spec ->
            p = spec.id |> to_string() |> String.split("-")
            fam = Enum.at(p, 2) |> String.upcase()
            cid = fam <> "-" <> (Enum.at(p, 3) || "")
            if length(p) > 4, do: cid <> "(" <> Enum.at(p, 4) <> ")", else: cid
          end)
          |> Enum.join(", ")

        title = escape_latex(base_spec.title)
        desc = ""

        params_text =
          specs
          |> Enum.flat_map(fn spec ->
            Map.get(spec, :parameters, [])
            |> Enum.reject(fn {_name, _pdesc, opts} ->
              Keyword.get(opts, :default) in [nil, "", "nil"]
            end)
            |> Enum.map(fn {_name, pdesc, opts} ->
              default = Keyword.get(opts, :default, "") |> to_string() |> escape_latex()
              desc_str = escape_latex(pdesc)

              if desc_str != "",
                do: "#{desc_str}: \\textbf{#{default}}",
                else: "\\textbf{#{default}}"
            end)
          end)
          |> Enum.join("\\newline ")

        row_str =
          "#{idx} & #{title} & #{desc} & #{escape_latex(control_ids)} & #{params_text} \\\\ \\hline\n"

        if family != last_fam do
          family_atom = String.to_atom("id-spe-#{String.downcase(family)}")
          family_spec = Enum.find(all_specs, &(&1.id == family_atom))

          family_title =
            if family_spec, do: escape_latex(family_spec.title), else: escape_latex(family)

          prefix =
            "\\multicolumn{5}{|>{\\raggedright\\arraybackslash}p{14.5cm}|}{\\textbf{#{family_title}}} \\\\ \\hline\n"

          {prefix <> row_str, family}
        else
          {row_str, family}
        end
      end)

    {Enum.join(rows, ""), length(chunked_specs)}
  end

  defp generate_legal_l3_table_body(controls) do
    profile_specs = CA.Profile.Data.unfold(controls)
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
        desc = ""

        params_text =
          Map.get(spec, :parameters, [])
          |> Enum.reject(fn {_name, _pdesc, opts} ->
            Keyword.get(opts, :default) in [nil, "", "nil"]
          end)
          |> Enum.map(fn {_name, pdesc, opts} ->
            default = Keyword.get(opts, :default, "") |> to_string() |> escape_latex()
            desc_str = escape_latex(pdesc)

            if desc_str != "",
              do: "#{desc_str} = \\textbf{#{default}}",
              else: "\\textbf{#{default}}"
          end)
          |> Enum.join("\\newline ")

        {fam_idx_new, ctrl_idx_new, prefix} =
          if family != last_fam do
            family_atom = String.to_atom("id-spe-#{String.downcase(family)}")
            family_spec = Enum.find(all_specs, &(&1.id == family_atom))

            family_title =
              if family_spec, do: escape_latex(family_spec.title), else: escape_latex(family)

            new_fam_idx = fam_idx + 1

            pref =
              "\\multicolumn{5}{|>{\\raggedright\\arraybackslash}p{14.5cm}|}{\\textbf{#{new_fam_idx}. #{family_title} (#{family})}} \\\\ \\hline\n"

            {new_fam_idx, 1, pref}
          else
            {fam_idx, ctrl_idx + 1, ""}
          end

        row_str =
          "#{row_idx} & #{title} & #{desc} & #{escape_latex(control_id)} & #{params_text} \\\\ \\hline\n"

        {prefix <> row_str, {family, fam_idx_new, ctrl_idx_new}}
      end)

    {Enum.join(rows, ""), length(profile_specs)}
  end
end
