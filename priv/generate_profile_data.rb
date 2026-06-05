require 'fileutils'
require 'json'

files = [
  "requirements/НД ТЗІ 2.3-025-24_Т1.txt",
  "requirements/НД ТЗІ 2.3-025-24_Т2.txt",
  "requirements/НД ТЗІ 2.3-025-24_Т3.txt"
]

# 1. Parse Control Descriptions from 3.6-006-24
desc_text = File.read("requirements/НД ТЗІ 3.6-006-24.txt")
descriptions = {}
title_map = {}
odps = {}
explicit_defaults = {}

in_desc = false
parent_control = nil
current_control = nil
current_desc = ""

def format_control_description(desc)
  desc = desc.gsub(/\s+/, ' ').strip
  desc = desc.gsub(/- ([а-яіїєґa-z])/i, '\1')
  desc = desc.gsub(/ ([a-z]\.) /, "\n\\1 ")
  desc = desc.gsub(/ (\d+\.) /, "\n\\1 ")
  desc = desc.gsub(/ (\([a-z]\)) /, "\n\\1 ")
  desc
end

desc_text.each_line do |line|
  stripped = line.strip
  next if stripped.match?(/^?\d+$/)
  next if stripped.match?(/КЗЗ[IІ]\.\s*Базовий\s*проф[iі]ль\.\s*\d+/i)
  next if stripped.match?(/^\d{1,2}\s+(січня|лютого|березня|квітня|травня|червня|липня|серпня|вересня|жовтня|листопада|грудня)\s+\d{4}$/i)

  if stripped == "Додаток А"
    if current_control && in_desc && !current_desc.strip.empty?
      atom_name = current_control.downcase.gsub('-', '_').gsub('(', '-').gsub(')', '')
      descriptions["id-spe-#{atom_name.gsub('_', '-')}"] = format_control_description(current_desc)
    end
    break
  end

  if match = stripped.match(/^([A-Z]{2}-\d+)\s+([А-ЯІЇЄҐ \-]+)/)
    if current_control && in_desc && !current_desc.strip.empty?
      descriptions["id-spe-#{current_control.downcase.gsub('-', '_')}"] = format_control_description(current_desc)
    end
    current_control = match[1]
    parent_control = current_control
    current_desc = ""
    in_desc = false
  elsif match = stripped.match(/^\((\d+)\)\s+([А-ЯІЇЄҐ])/)
    if current_control && in_desc && !current_desc.strip.empty?
      descriptions["id-spe-#{current_control.downcase.gsub('-', '_').gsub('(', '-').gsub(')', '')}"] = format_control_description(current_desc)
    end
    if parent_control
      current_control = "#{parent_control}(#{match[1]})"
      current_desc = ""
      in_desc = true 
    end
  elsif match = stripped.match(/(?:Клас заходів захисту|КЛАС ЗАХОДІВ ЗАХИСТУ) ([А-ЯІЇЄҐA-Z]{2})\s*[—\–\-]\s*(.*)/i)
    fam = match[1].upcase
    fam = fam.gsub('А', 'A').gsub('С', 'C').gsub('Т', 'T').gsub('І', 'I').gsub('Р', 'P').gsub('М', 'M').gsub('Е', 'E').gsub('О', 'O')
    family_id = "id-spe-#{fam.downcase}"
    descriptions[family_id] = "Клас заходів захисту #{fam} — #{match[2].strip}"
  elsif match = stripped.match(/^Заходи захисту:\s*(.*)/i)
    in_desc = true
    current_desc = match[1] || ""
  elsif stripped.match?(/^(Рекомендації з реалізації:|Пов’язані заходи:|Посилення заходів:)/i)
    if current_control && in_desc
      # Try to remove leftover uppercase title parts if they leaked into desc
      cd = format_control_description(current_desc)
      cd = cd.sub(/^[А-ЯІЇЄҐ \-]+\s+/, '') if cd.match?(/^[А-ЯІЇЄҐ \-]{10,}/)
      
      # Fix mangled description for AC-4(5)
   #   cd = cd.sub("Впровадити [Призначення: визначені організацією вбудовування типів даних в інші типи даних. обмеження] для", 
    #              "Впровадити [Призначення: визначені організацією обмеження] для вбудовування типів даних в інші типи даних.")

      atom_name = current_control.downcase.gsub('-', '_').gsub('(', '_').gsub(')', '')
      atom_name = atom_name.sub(/_0(\d)/, '_\1')
      
      descriptions["id-spe-#{atom_name.gsub('_', '-')}"] = cd
      in_desc = false
    end
  elsif in_desc
    if current_desc.empty? && stripped.match?(/^[А-ЯІЇЄҐ0-9 \-'(),.‑–—]+$/)
      # Skip wrapped uppercase title lines
    else
      current_desc += " " + stripped unless stripped.empty?
    end
  end
end


# 2. Parse ODPs from T1, T2, T3
odps = Hash.new { |h, k| h[k] = {} }

junk_phrases = [
  "ВИБІРКОВЕ ЗНАЧЕННЯ ПАРАМЕТРА",
  "ВИБІРКОВЕ",
  "ЗНАЧЕННЯ ПАРАМЕТРА",
  "організація визначає",
  "організацією визначається",
  "ВИБРАНЕ"
]

explicit_defaults = {
  "id-spe-ac-2" => { match: /період|час/i, default: '24', type: ':integer' },
  "id-spe-ac-11" => { match: /час/i, default: '30', type: ':integer' },
  "id-spe-at-2" => { match: /частота/i, default: '"раз на рік"', type: ':string' },
  "id-spe-at-3" => { match: /частота/i, default: '"раз на рік"', type: ':string' },
  "id-spe-au-6" => { match: /частота/i, default: '"щотижня"', type: ':string' }
}

def clean_description(desc)
  return nil if desc.match?(/^[A-Z]{2}-?\d+(\(\d+\))?_ODP/i)
  return nil if desc.match?(/^ВИБІРКОВЕ/i)
  
  desc = desc.gsub(/<[A-Z0-9\-()]+_ODP(?:\[\d+\])?\s+([^>]+)>/i, '\1')
  desc = desc.gsub(/<[A-Z0-9\-()]+_ODP(?:\[\d+\])?>/i, '')
  
  desc = desc.gsub(/^[A-Z]{2}-\d+[a-z]?\.?\[\d+\]\s*/i, '')
  desc = desc.gsub(/^[A-Z]{2}-\d+(?:\(\d+\))?(?:\([a-z]\))?(?:\[\d+\])?\s*/i, '')
  
  desc = desc.sub(/^[^[:alpha:]]+/, '')
  desc = desc.gsub(/\s+/, ' ').strip
  desc = desc.sub(/\s+для$/i, '')
  desc = desc.sub(/\s+та$/i, '')
  desc = desc.gsub(/[>;.]$/, '')
  
  return nil if desc.empty? || desc.length < 3
  return nil if desc.match?(/^[\p{Lu} \-.,0-9()\[\]]+$/)
  
  desc[0].capitalize + desc[1..-1]
end

def infer_type_and_default(control_atom, desc, explicit_defaults)
  type = ':string'
  default = 'nil'
  
  d = desc.downcase
  
  # Advanced heuristics
  if d.match?(/персонал|ролі|посадов|особ/i)
    type = ':list'
    default = '["admin", "security_officer"]'
  elsif d.match?(/атрибути|правила|політик/i)
    type = ':list'
    default = '["default_deny_rule", "abac_rule_1"]'
  elsif d.match?(/алгоритм|крипто|шифрув|хеш/i)
    type = ':string'
    default = '"AES-256-GCM"'
  elsif d.match?(/протокол/i)
    type = ':string'
    default = '"TLS 1.3"'
  elsif d.match?(/події|дії/i)
    type = ':list'
    default = '["login", "logout", "failed_attempt"]'
  elsif d.match?(/умови|критерії|список|перелік/i)
    type = ':list'
    default = '[]'
  elsif d.match?(/частота|періодичність/i)
    type = ':string'
    default = '"щорічно"'
  elsif d.match?(/період|час|хвилин|годин/i)
    type = ':integer'
    default = '30' # e.g. 30 minutes
  elsif d.match?(/кількість|спроб/i)
    type = ':integer'
    default = '3'
  elsif d.match?(/механізми|засоби|техніки/i)
    type = ':string'
    default = '"автоматизований засіб моніторингу"'
  end

  # Fallback to explicit
  if explicit_defaults[control_atom] && desc.match?(explicit_defaults[control_atom][:match])
    type = explicit_defaults[control_atom][:type]
    default = explicit_defaults[control_atom][:default]
  end

  { type: type, default: default }
end

def add_param(odps, control, odp_flag, letter, idx, desc, junk_phrases)
  return if desc.nil?
  desc = desc.strip
  return if junk_phrases.any? { |j| desc.include?(j) }
  
  clean_desc = clean_description(desc)
  return if clean_desc.nil?

  letters = clean_desc.scan(/[А-ЯІЇЄҐа-яіїєґa-zA-Z]/)
  return if letters.any? && letters.all? { |c| c.match?(/[А-ЯІЇЄҐA-Z]/) }

  norm = control.downcase.gsub(/0(\d)/, '\1')
  norm = norm.gsub(/\((\d+)\)/, '-\1')
  atom = "id-spe-#{norm}"
  
  parts = [norm.gsub('-', '_')]
  parts << "odp" if odp_flag
  parts << letter if letter && !letter.empty?
  parts << idx if idx && !idx.empty?
  
  parts << "01" if parts.length == 1
  
  param_key = parts.join('_')
  
  existing = odps[atom][param_key]
  if existing.nil? || clean_desc.length > existing.length
    odps[atom][param_key] = clean_desc
  end
end

files.each do |f|
  next unless File.exist?(f)
  text = File.read(f)
  
  current_id = nil
  current_desc = ""
  current_odp_flag = false
  current_letter = nil
  current_idx = nil
  
  text.each_line do |line|
    next if line.strip.match?(/^?\d+$/)
    next if line.strip.match?(/КЗЗ[IІ]\.\s*Базовий\s*проф[iі]ль\.\s*\d+/i)
    next if line.strip.match?(/^\d{1,2}\s+(січня|лютого|березня|квітня|травня|червня|липня|серпня|вересня|жовтня|листопада|грудня)\s+\d{4}$/i)
    
    if line.match?(/^[A-Z]{2}-0?\d+(?:\(\d+\))?(?:_ODP)?(?:\([a-z]\))?(?:\[\d+\])?(?:\s|$)/i)
      if current_id
        add_param(odps, current_id, current_odp_flag, current_letter, current_idx, current_desc, junk_phrases)
      end
      
      match = line.match(/^([A-Z]{2}-0?\d+(?:\(\d+\))?)(_ODP)?(?:\(([a-z])\))?(?:\[(\d+)\])?\s*(.*)$/i)
      current_id = match[1]
      current_odp_flag = !match[2].nil?
      current_letter = match[3]
      current_idx = match[4]
      current_desc = match[5]
    elsif current_id
      if line.match?(/^(МЕТА ОЦ[ІI]НКИ|ПОТЕНЦ[ІI]ЙН[ІI]\s*МЕТОДИ|Співбесіда:|Перевірка:|Досл[іi]дження:|Таблиця\s+\d|Рисунок\s+\d|Додаток\s+[А-ЯІЇЄҐA-Z]|\d+\.\d+(\.\d+)?\s+[А-ЯІЇЄҐA-Z])/i) || line.strip.match?(/^[A-Z]{2}-\d+$/)
        add_param(odps, current_id, current_odp_flag, current_letter, current_idx, current_desc, junk_phrases)
        current_id = nil
      else
        stripped = line.strip
        current_desc += " " + stripped unless stripped.empty?
      end
    end
  end
  
  if current_id
    add_param(odps, current_id, current_odp_flag, current_letter, current_idx, current_desc, junk_phrases)
  end
end

spe_content = File.read("/Users/tonpa/depot/synrc/ca/lib/oid/spe.ex")
title_map = {}
spe_content.scan(/def oid\(:"([^"]+)"\), do: (\{[\d, ]+\})/) do |atom, tuple|
  title_map[atom] = tuple.delete(' ')
end

lookup_map = {}
spe_content.scan(/def lookup\((\{[\d, ]+\})\),\s*do:\s*"(.*?)"/) do |tuple, title|
  lookup_map[tuple.delete(' ')] = title
end

out = <<~ELIXIR
defmodule CA.Profile.Data do
  @moduledoc "Central registry for all Security Controls and their ODPs"

  def controls do
    [
#{title_map.keys.map { |atom| "      CA.SPE.oid(:\"#{atom}\")" }.join(",\n")}
    ]
  end

  def specs do
    [
#{title_map.keys.map { |atom| "      spec(:\"#{atom}\")" }.join(",\n")}
    ]
  end

ELIXIR

title_map.each do |atom, tuple|
  title = lookup_map[tuple] || atom
  title = title.gsub('"', '\"')
  
  top_desc = descriptions[atom] || ""
  top_desc = top_desc.gsub('"', '\"').gsub("\n", "\\n")
  
  out += "  def spec(:\"#{atom}\") do\n"
  out += "    %{\n"
  out += "      id: :\"#{atom}\",\n"
  out += "      description: \"#{top_desc}\",\n"
  out += "      title: \"#{title}\",\n"
  out += "      parameters: [\n"
  
  params = odps[atom] || {}
  
  param_strs = params.keys.sort.map do |param_key|
    desc = params[param_key]
    info = infer_type_and_default(atom, desc, explicit_defaults)
    "        {:#{param_key},\n         \"#{desc.gsub('"', '\"')}\",\n         [type: #{info[:type]}, default: #{info[:default]}]}"
  end
  
  out += param_strs.join(",\n")
  out += "\n      ]\n"
  out += "    }\n"
  out += "  end\n\n"
end

out += "  def spec(_), do: nil\n"
out += "end\n"

File.write("/Users/tonpa/depot/synrc/ca/lib/oid/profile_data.ex", out)
puts "Wrote profile_data.ex with top-level descriptions and improved defaults!"
