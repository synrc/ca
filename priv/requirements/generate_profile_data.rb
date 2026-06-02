require 'fileutils'

files = [
  "/Users/tonpa/depot/synrc/ca/priv/requirements/НД ТЗІ 2.3-025-24_Т1.txt",
  "/Users/tonpa/depot/synrc/ca/priv/requirements/НД ТЗІ 2.3-025-24_Т2.txt",
  "/Users/tonpa/depot/synrc/ca/priv/requirements/НД ТЗІ 2.3-025-24_Т3.txt"
]

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
  
  # Replace <AC-22_ODP частотою> with "частотою"
  desc = desc.gsub(/<[A-Z0-9\-()]+_ODP(?:\[\d+\])?\s+([^>]+)>/i, '\1')
  desc = desc.gsub(/<[A-Z0-9\-()]+_ODP(?:\[\d+\])?>/i, '')
  
  desc = desc.gsub(/^[A-Z]{2}-\d+[a-z]?\.?\[\d+\]\s*/i, '')
  desc = desc.gsub(/^[A-Z]{2}-\d+(?:\(\d+\))?(?:\([a-z]\))?(?:\[\d+\])?\s*/i, '')
  
  desc = desc.sub(/^[^[:alpha:]]+/, '')
  desc = desc.gsub(/\s+/, ' ').strip
  desc = desc.gsub(/[>;.]$/, '')
  
  return nil if desc.empty? || desc.length < 3
  
  return nil if desc.match?(/^[А-ЯІЇЄҐ \-]+$/) && desc.length < 50
  
  desc[0].capitalize + desc[1..-1]
end

def infer_type_and_default(control_atom, desc, explicit_defaults)
  type = ':string'
  default = 'nil'
  
  if desc.match?(/частота|період|час|хвилин|годин/i)
    type = ':string'
  end
  
  if desc.match?(/персонал|ролі|умови|критерії|атрибути|список|перелік|визначені особи/i)
    type = ':list'
    default = '[]'
  end
  
  if desc.match?(/кількість/i)
    type = ':integer'
    default = '0'
  end

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
      if line.match?(/^(МЕТА ОЦІНКИ|ПОТЕНЦІЙНІ МЕТОДИ|Співбесіда:|Перевірка:|Дослідження:)/i) || line.strip.match?(/^[A-Z]{2}-\d+$/)
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
spe_content.scan(/def lookup\((\{[\d, ]+\})\), do: "(.*?)"/) do |tuple, title|
  lookup_map[tuple.delete(' ')] = title
end

out = <<~ELIXIR
defmodule CA.Profile.Data do
  use CA.Profile.DSL
  @moduledoc "Central registry for all Security Controls and their ODPs"

ELIXIR

title_map.each do |atom, tuple|
  title = lookup_map[tuple] || atom
  title = title.gsub('"', '\"')
  
  out += "  control :\"#{atom}\" do\n"
  out += "    title \"#{title}\"\n"
  out += "    desc \"\"\n"
  
  params = odps[atom] || {}
  
  params.keys.sort.each do |param_key|
    desc = params[param_key]
    info = infer_type_and_default(atom, desc, explicit_defaults)
    out += "    param :#{param_key}, \"#{desc.gsub('"', '\"')}\", type: #{info[:type]}, default: #{info[:default]}\n"
  end
  
  out += "  end\n\n"
end

out += "end\n"

File.write("/Users/tonpa/depot/synrc/ca/lib/oid/profile_data.ex", out)
puts "Wrote profile_data.ex with full multiline evaluation objectives"
