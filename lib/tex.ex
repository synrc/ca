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
    {\\color{nato}\\Huge\\bfseries}{\\thesection.}{1em}{}
  \\titlespacing*{\\section}{0pt}{30pt}{12pt}

  \\titleformat{\\subsection}
    {\\color{nato}\\LARGE\\bfseries}{\\thesubsection.}{1em}{}
  \\titlespacing*{\\subsection}{0pt}{20pt}{8pt}

  \\titleformat{\\subsubsection}
    {\\color{nato}\\Large\\bfseries}{\\thesubsubsection.}{1em}{}
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
    * `:subtitle` - subtitle on title page and footer (default: "ЄСІКС КЗЗІ")
    * `:title` - title on title page and footer (default: "Профілі безпеки")
    * `:year` - copyright year (default: "2026")
    * `:copyright` - copyright owner (default: "Інформаційні Судові Системи")
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
          copyright: "Інформаційні Судові Системи",
          toc_title: "Зміст",
          abstract: "",
          body: ""
        ],
        opts
      )

    render(Enum.into(opts, %{}))
  end

  def base_profile(opts \\ []) do
    opts =
      Keyword.merge(
        [
          title: "Профіль базових заходів із захисту інформації",
          subtitle: "Комплексна система захисту інформації",
          abstract: "Базовий профіль — затверджується Адміністрацією Держспецзв’язку (наказом).",
          body: generate_body(CA.L1.controls())
        ],
        opts
      )

    content = generate(opts)
    File.write!("priv/base_profile.tex", content)
    "priv/base_profile.tex"
  end

  def industry_profile(opts \\ []) do
    controls = CA.L2.controls() -- CA.L1.controls()

    opts =
      Keyword.merge(
        [
          title: "Галузевий профіль заходів із захисту інформації",
          subtitle: "Комплексна система захисту інформації",
          abstract:
            "Галузевий профіль — розробляється галузевим органом, погоджується з Держспецзв’язку та затверджується наказом/рішенням відповідного органу. Включає лише додаткові вимоги (відмінності) відносно Базового профілю.",
          body: generate_body(controls)
        ],
        opts
      )

    content = generate(opts)
    File.write!("priv/industry_profile.tex", content)
    "priv/industry_profile.tex"
  end

  def target_profile(module, opts \\ []) do
    name = module |> Module.split() |> List.last()
    controls = module.controls() -- CA.L2.controls()

    title =
      case name do
        "Orgs" -> "Цільовий профіль безпеки органів та установ в системі правосуддя"
        "Supreme" -> "Цільовий профіль безпеки вищих судів"
        "Specialized" -> "Цільовий профіль безпеки вищих спеціалізованих судів"
        "Local" -> "Цільовий профіль судів"
        _ -> "Цільовий профіль безпеки (#{name})"
      end

    opts =
      Keyword.merge(
        [
          title: title,
          subtitle: "Комплексна система захисту інформації",
          abstract:
            "Цільовий профіль безпеки (ЦПБ) — індивідуальний для конкретної системи підприємства. Саме на його основі створюється/модернізується КЗЗІ. Включає лише додаткові вимоги (відмінності) відносно Галузевого профілю.",
          body: generate_body(controls)
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

  defp generate_body(controls) do
    all_specs = CA.Profile.Data.specs()
    oid_to_spec = Map.new(all_specs, fn spec -> {CA.SPE.oid(spec.id), spec} end)

    expanded_controls = expand_controls(controls, all_specs)

    {sections, _} =
      Enum.map_reduce(expanded_controls, nil, fn oid, last_fam ->
        spec = Map.get(oid_to_spec, oid)

        if spec do
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
            {"\\section{#{family}}\n\n" <> formatted, family}
          else
            {formatted, last_fam}
          end
        else
          {"\\subsection{Unknown Control}\\nUnknown OID: #{inspect(oid)}", last_fam}
        end
      end)

    Enum.join(sections, "\n\n")
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
    |> String.replace("_", "\\_")
    |> String.replace("~", "\\textasciitilde{}")
    |> String.replace("^", "\\textasciicircum{}")
    |> String.replace("\"", "\\textquotedbl{}")
  end

  defp expand_controls(controls, all_specs) do
    all_oids = Enum.map(all_specs, &CA.SPE.oid(&1.id))

    Enum.flat_map(controls, fn parent_oid ->
      parent_list = Tuple.to_list(parent_oid)

      all_oids
      |> Enum.filter(fn child_oid ->
        child_list = Tuple.to_list(child_oid)
        List.starts_with?(child_list, parent_list)
      end)
    end)
    |> Enum.uniq()
    |> Enum.sort_by(&Tuple.to_list/1)
  end
end
