# CA: Certificate Authority

[![Actions Status](https://github.com/synrc/ca/workflows/mix/badge.svg)](https://github.com/synrc/ca/actions)
[![Build Status](https://travis-ci.com/synrc/ca.svg?branch=master)](https://travis-ci.com/synrc/ca)
[![Hex pm](http://img.shields.io/hexpm/v/ca.svg?style=flat)](https://hex.pm/packages/ca)

## KEP usage

```elixir
> KEP.Cert.parseSignData bin
{{:certAttrs, "1786046", "СОХАЦЬКИЙ МАКСИМ ЕРОТЕЙОВИЧ",
  "МАКСИМ ЕРОТЕЙОВИЧ", "СОХАЦЬКИЙ",
  "СОХАЦЬКИЙ МАКСИМ ЕРОТЕЙОВИЧ",
  "Електронна печатка", "", 'UA', "КИЇВ"},
 {:certAttrs, "UA-14360570-2018", "АЦСК АТ КБ «ПРИВАТБАНК»",
  "", "",
  "АКЦІОНЕРНЕ ТОВАРИСТВО КОМЕРЦІЙНИЙ БАНК «ПРИВАТБАНК»",
  "", "АЦСК", 'UA', "Київ"}}
```

## Credits

Максим Сохацький
